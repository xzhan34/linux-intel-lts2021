/*
 * Copyright © 2017 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 */

#include <linux/highmem.h>
#include <linux/sched/mm.h>
#include <linux/iosys-map.h>

#include <drm/drm_cache.h>

#include "display/intel_frontbuffer.h"
#include "gt/intel_gt.h"
#include "gt/intel_gt_requests.h"
#include "pxp/intel_pxp.h"

#include "i915_drv.h"
#include "i915_gem_clflush.h"
#include "i915_gem_context.h"
#include "i915_gem_dmabuf.h"
#include "i915_gem_lmem.h"
#include "i915_gem_mman.h"
#include "i915_gem_object.h"
#include "i915_gem_object_blt.h"
#include "i915_gem_region.h"
#include "i915_gem_tiling.h"
#include "i915_memcpy.h"
#include "i915_trace.h"

static struct kmem_cache *slab_objects;

static const struct drm_gem_object_funcs i915_gem_object_funcs;

void i915_gem_object_migrate_prepare(struct drm_i915_gem_object *obj,
				     struct i915_request *rq)
{
	GEM_WARN_ON(i915_active_fence_set(&obj->mm.migrate, rq));
}

long i915_gem_object_migrate_wait(struct drm_i915_gem_object *obj,
				  unsigned int flags,
				  long timeout)
{
	struct dma_fence *fence;

	fence = i915_active_fence_get_or_error(&obj->mm.migrate);
	if (likely(!fence))
		return timeout;

	if (IS_ERR(fence))
		return PTR_ERR(fence);

	timeout = i915_request_wait(to_request(fence), flags, timeout);
	if (fence->error)
		timeout = fence->error;

	dma_fence_put(fence);
	return timeout;
}

int i915_gem_object_migrate_sync(struct drm_i915_gem_object *obj)
{
	long timeout =
		i915_gem_object_migrate_wait(obj,
					     I915_WAIT_INTERRUPTIBLE |
					     I915_WAIT_PRIORITY,
					     MAX_SCHEDULE_TIMEOUT);

	return timeout < 0 ? timeout : 0;
}

void i915_gem_object_migrate_finish(struct drm_i915_gem_object *obj)
{
	i915_gem_object_migrate_wait(obj, 0, MAX_SCHEDULE_TIMEOUT);
	obj->mm.migrate.fence = NULL;
}

struct drm_i915_gem_object *i915_gem_object_alloc(void)
{
	struct drm_i915_gem_object *obj;

	obj = kmem_cache_zalloc(slab_objects, GFP_KERNEL);
	if (!obj)
		return NULL;
	obj->base.funcs = &i915_gem_object_funcs;

	INIT_ACTIVE_FENCE(&obj->mm.migrate);
	return obj;
}

void i915_gem_object_free(struct drm_i915_gem_object *obj)
{
	return kmem_cache_free(slab_objects, obj);
}

void i915_gem_object_init(struct drm_i915_gem_object *obj,
			  const struct drm_i915_gem_object_ops *ops,
			  struct lock_class_key *key, unsigned flags)
{
	/*
	 * A gem object is embedded both in a struct ttm_buffer_object :/ and
	 * in a drm_i915_gem_object. Make sure they are aliased.
	 */
	BUILD_BUG_ON(offsetof(typeof(*obj), base) !=
		     offsetof(typeof(*obj), __do_not_access.base));

	spin_lock_init(&obj->vma.lock);
	INIT_LIST_HEAD(&obj->vma.list);

	INIT_LIST_HEAD(&obj->mm.link);
	INIT_LIST_HEAD(&obj->mm.region.link);

	INIT_LIST_HEAD(&obj->lut_list);
	spin_lock_init(&obj->lut_lock);

	spin_lock_init(&obj->mmo.lock);
	obj->mmo.offsets = RB_ROOT;

	init_rcu_head(&obj->rcu);

	obj->ops = ops;
	obj->flags = flags;

	obj->mm.madv = I915_MADV_WILLNEED;
	INIT_RADIX_TREE(&obj->mm.get_page.radix, GFP_KERNEL | __GFP_NOWARN);
	mutex_init(&obj->mm.get_page.lock);
	INIT_RADIX_TREE(&obj->mm.get_dma_page.radix, GFP_KERNEL | __GFP_NOWARN);
	mutex_init(&obj->mm.get_dma_page.lock);
}

/**
 * Mark up the object's coherency levels for a given cache_level
 * @obj: #drm_i915_gem_object
 * @cache_level: cache level
 */
void i915_gem_object_set_cache_coherency(struct drm_i915_gem_object *obj,
					 unsigned int cache_level)
{
	obj->cache_level = cache_level;

	if (cache_level != I915_CACHE_NONE)
		obj->cache_coherent = (I915_BO_CACHE_COHERENT_FOR_READ |
				       I915_BO_CACHE_COHERENT_FOR_WRITE);
	else if (HAS_LLC(to_i915(obj->base.dev)))
		obj->cache_coherent = I915_BO_CACHE_COHERENT_FOR_READ;
	else
		obj->cache_coherent = 0;

	obj->cache_dirty =
		!(obj->cache_coherent & I915_BO_CACHE_COHERENT_FOR_WRITE);
}

bool i915_gem_object_can_bypass_llc(struct drm_i915_gem_object *obj)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);

	/*
	 * This is purely from a security perspective, so we simply don't care
	 * about non-userspace objects being able to bypass the LLC.
	 */
	if (!(obj->flags & I915_BO_ALLOC_USER))
		return false;

	/*
	 * EHL and JSL add the 'Bypass LLC' MOCS entry, which should make it
	 * possible for userspace to bypass the GTT caching bits set by the
	 * kernel, as per the given object cache_level. This is troublesome
	 * since the heavy flush we apply when first gathering the pages is
	 * skipped if the kernel thinks the object is coherent with the GPU. As
	 * a result it might be possible to bypass the cache and read the
	 * contents of the page directly, which could be stale data. If it's
	 * just a case of userspace shooting themselves in the foot then so be
	 * it, but since i915 takes the stance of always zeroing memory before
	 * handing it to userspace, we need to prevent this.
	 */
	return IS_JSL_EHL(i915);
}

static void i915_gem_close_object(struct drm_gem_object *gem, struct drm_file *file)
{
	struct drm_i915_gem_object *obj = to_intel_bo(gem);
	struct drm_i915_file_private *fpriv = file->driver_priv;
	struct i915_lut_handle bookmark = {};
	struct i915_mmap_offset *mmo, *mn;
	struct i915_lut_handle *lut, *ln;
	LIST_HEAD(close);

	spin_lock(&obj->lut_lock);
	list_for_each_entry_safe(lut, ln, &obj->lut_list, obj_link) {
		struct i915_gem_context *ctx = lut->ctx;

		if (ctx && ctx->file_priv == fpriv) {
			i915_gem_context_get(ctx);
			list_move(&lut->obj_link, &close);
		}

		/* Break long locks, and carefully continue on from this spot */
		if (&ln->obj_link != &obj->lut_list) {
			list_add_tail(&bookmark.obj_link, &ln->obj_link);
			if (cond_resched_lock(&obj->lut_lock))
				list_safe_reset_next(&bookmark, ln, obj_link);
			__list_del_entry(&bookmark.obj_link);
		}
	}
	spin_unlock(&obj->lut_lock);

	spin_lock(&obj->mmo.lock);
	rbtree_postorder_for_each_entry_safe(mmo, mn, &obj->mmo.offsets, offset)
		drm_vma_node_revoke(&mmo->vma_node, file);
	spin_unlock(&obj->mmo.lock);

	list_for_each_entry_safe(lut, ln, &close, obj_link) {
		struct i915_gem_context *ctx = lut->ctx;
		struct i915_vma *vma;

		/*
		 * We allow the process to have multiple handles to the same
		 * vma, in the same fd namespace, by virtue of flink/open.
		 */

		mutex_lock(&ctx->lut_mutex);
		vma = radix_tree_delete(&ctx->handles_vma, lut->handle);
		if (vma) {
			GEM_BUG_ON(vma->obj != obj);
			GEM_BUG_ON(!atomic_read(&vma->open_count));
			i915_vma_close(vma);
		}
		mutex_unlock(&ctx->lut_mutex);

		i915_gem_context_put(lut->ctx);
		i915_lut_handle_free(lut);
		i915_gem_object_put(obj);
	}
}

void __i915_gem_free_object_rcu(struct rcu_head *head)
{
	struct drm_i915_gem_object *obj =
		container_of(head, typeof(*obj), rcu);
	struct drm_i915_private *i915 = to_i915(obj->base.dev);

	i915_active_fence_fini(&obj->mm.migrate);

	/* Reset shared reservation object */
	obj->base.resv = &obj->base._resv;
	dma_resv_fini(&obj->base._resv);

	i915_gem_object_free(obj);

	GEM_BUG_ON(!atomic_read(&i915->mm.free_count));
	atomic_dec(&i915->mm.free_count);
}

static void vma_offset_revoke_all(struct drm_vma_offset_node *node)
{
	struct drm_vma_offset_file *it, *n;

	write_lock(&node->vm_lock);

	rbtree_postorder_for_each_entry_safe(it, n, &node->vm_files, vm_rb)
		kfree(it);
	node->vm_files = RB_ROOT;

	write_unlock(&node->vm_lock);
}

void __i915_gem_object_free_mmaps(struct drm_i915_gem_object *obj)
{
	/* Skip serialisation and waking the device if known to be not used. */

	if (obj->userfault_count)
		i915_gem_object_release_mmap_gtt(obj);

	if (!RB_EMPTY_ROOT(&obj->mmo.offsets)) {
		struct i915_mmap_offset *mmo, *mn;

		i915_gem_object_release_mmap_offset(obj);

		rbtree_postorder_for_each_entry_safe(mmo, mn,
						     &obj->mmo.offsets,
						     offset) {
			vma_offset_revoke_all(&mmo->vma_node);
			drm_vma_offset_remove(obj->base.dev->vma_offset_manager,
					      &mmo->vma_node);
			kfree(mmo);
		}
		obj->mmo.offsets = RB_ROOT;
	}

	if (unlikely(drm_mm_node_allocated(&obj->base.vma_node.vm_node)))
		drm_gem_free_mmap_offset(&obj->base);
}

static void __i915_gem_object_free_vma(struct drm_i915_gem_object *obj)
{
	struct i915_vma *vma;

	if (list_empty(&obj->vma.list))
		return;

	/*
	 * Note that the vma keeps an object reference while
	 * it is active, so it *should* not sleep while we
	 * destroy it. Our debug code errs insits it *might*.
	 * For the moment, play along.
	 */
	spin_lock(&obj->vma.lock);
	while ((vma = list_first_entry_or_null(&obj->vma.list,
					       struct i915_vma,
					       obj_link))) {
		__i915_vma_get(vma);
		spin_unlock(&obj->vma.lock);

		mutex_lock(&vma->vm->mutex);
		i915_vma_unpublish(vma);
		mutex_unlock(&vma->vm->mutex);

		__i915_vma_put(vma);
		spin_lock(&obj->vma.lock);
	}
	spin_unlock(&obj->vma.lock);
}

void __i915_gem_free_object(struct drm_i915_gem_object *obj)
{
	trace_i915_gem_object_destroy(obj);

	__i915_gem_object_free_mmaps(obj);
	__i915_gem_object_free_vma(obj);

	GEM_BUG_ON(!list_empty(&obj->lut_list));

	atomic_set(&obj->mm.pages_pin_count, 0);
	__i915_gem_object_put_pages(obj);
	GEM_BUG_ON(i915_gem_object_has_pages(obj));
	GEM_BUG_ON(!list_empty(&obj->mm.region.link));
	GEM_BUG_ON(!list_empty(&obj->mm.link));
	bitmap_free(obj->bit_17);

	if (obj->base.import_attach)
		drm_prime_gem_destroy(&obj->base, NULL);

	if (obj->ops->release)
		obj->ops->release(obj);

	if (obj->mm.n_placements > 1)
		kfree(obj->mm.placements);

	if (obj->shares_resv_from)
		i915_vm_resv_put(obj->shares_resv_from);
}

static void __i915_gem_free_objects(struct drm_i915_private *i915,
				    struct llist_node *freed)
{
	struct drm_i915_gem_object *obj, *on;

	llist_for_each_entry_safe(obj, on, freed, freed) {
		might_sleep();
		if (obj->ops->delayed_free) {
			obj->ops->delayed_free(obj);
			continue;
		}
		__i915_gem_free_object(obj);

		/* But keep the pointer alive for RCU-protected lookups */
		call_rcu(&obj->rcu, __i915_gem_free_object_rcu);
		cond_resched();
	}
}

void i915_gem_flush_free_objects(struct drm_i915_private *i915)
{
	struct llist_node *freed = llist_del_all(&i915->mm.free_list);

	if (unlikely(freed))
		__i915_gem_free_objects(i915, freed);
}

static void __i915_gem_free_work(struct work_struct *work)
{
	struct drm_i915_private *i915 =
		container_of(work, struct drm_i915_private, mm.free_work);

	i915_gem_flush_free_objects(i915);
}

static void i915_gem_free_object(struct drm_gem_object *gem_obj)
{
	struct drm_i915_gem_object *obj = to_intel_bo(gem_obj);
	struct drm_i915_private *i915 = to_i915(obj->base.dev);

	GEM_BUG_ON(i915_gem_object_is_framebuffer(obj));

	/*
	 * If object had been swapped out, free the hidden object.
	 */
	if (obj->swapto) {
		i915_gem_object_put(obj->swapto);
		obj->swapto = NULL;
	}

	/*
	 * Before we free the object, make sure any pure RCU-only
	 * read-side critical sections are complete, e.g.
	 * i915_gem_busy_ioctl(). For the corresponding synchronized
	 * lookup see i915_gem_object_lookup_rcu().
	 */
	atomic_inc(&i915->mm.free_count);

	/*
	 * Since we require blocking on struct_mutex to unbind the freed
	 * object from the GPU before releasing resources back to the
	 * system, we can not do that directly from the RCU callback (which may
	 * be a softirq context), but must instead then defer that work onto a
	 * kthread. We use the RCU callback rather than move the freed object
	 * directly onto the work queue so that we can mix between using the
	 * worker and performing frees directly from subsequent allocations for
	 * crude but effective memory throttling.
	 */

	if (llist_add(&obj->freed, &i915->mm.free_list))
		queue_work(i915->wq, &i915->mm.free_work);
}

int i915_gem_object_prepare_move(struct drm_i915_gem_object *obj)
{
	int err;

	assert_object_held(obj);

	if (obj->mm.madv != I915_MADV_WILLNEED)
		return -EINVAL;

	if (i915_gem_object_needs_bit17_swizzle(obj))
		return -EINVAL;

	if (i915_gem_object_is_framebuffer(obj))
		return -EBUSY;

	GEM_BUG_ON(obj->mm.mapping);
	GEM_BUG_ON(obj->base.filp && mapping_mapped(obj->base.filp->f_mapping));

	err = i915_gem_object_wait(obj,
				   I915_WAIT_INTERRUPTIBLE |
				   I915_WAIT_ALL,
				   MAX_SCHEDULE_TIMEOUT);
	if (err)
		return err;

	return i915_gem_object_unbind(obj,
				      I915_GEM_OBJECT_UNBIND_ACTIVE);
}

/**
 * i915_gem_object_can_migrate - Whether an object likely can be migrated
 *
 * @obj: The object to migrate
 * @id: The region intended to migrate to
 *
 * Check whether the object backend supports migration to the
 * given region. Note that pinning may affect the ability to migrate as
 * returned by this function.
 *
 * This function is primarily intended as a helper for checking the
 * possibility to migrate objects and might be slightly less permissive
 * than i915_gem_object_migrate() when it comes to objects with the
 * I915_BO_ALLOC_USER flag set.
 *
 * Return: true if migration is possible, false otherwise.
 */
bool i915_gem_object_can_migrate(struct drm_i915_gem_object *obj,
				 enum intel_region_id id)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	unsigned int num_allowed = obj->mm.n_placements;
	struct intel_memory_region *mr;
	unsigned int i;

	GEM_BUG_ON(id >= INTEL_REGION_UNKNOWN);
	GEM_BUG_ON(obj->mm.madv != I915_MADV_WILLNEED);

	mr = i915->mm.regions[id];
	if (!mr)
		return false;

	if (obj->mm.region.mem == mr)
		return true;

	if (num_allowed <= 1)
		return false;

	if (!i915_gem_object_evictable(obj))
		return false;

	for (i = 0; i < num_allowed; ++i) {
		if (mr == obj->mm.placements[i])
			return true;
	}

	return false;
}

static void lists_swap(struct list_head *a, struct list_head *b)
{
	struct list_head tmp;

	list_replace(a, &tmp);
	list_replace(b, a);
	list_replace(&tmp, b);
}

static void
swap_blocks(struct drm_i915_gem_object *obj, struct drm_i915_gem_object *donor)
{
	struct intel_memory_region *a = obj->mm.region.mem;
	struct intel_memory_region *b = donor->mm.region.mem;

	GEM_BUG_ON(a == b);
	if (a->id > b->id)
		swap(a, b);

	mutex_lock(&a->mm_lock);
	mutex_lock_nested(&b->mm_lock, SINGLE_DEPTH_NESTING);

	lists_swap(&obj->mm.blocks, &donor->mm.blocks);

	mutex_unlock(&b->mm_lock);
	mutex_unlock(&a->mm_lock);
}

static void
swap_region(struct drm_i915_gem_object *obj, struct drm_i915_gem_object *donor)
{
	struct intel_memory_region *a = obj->mm.region.mem;
	struct intel_memory_region *b = donor->mm.region.mem;

	GEM_BUG_ON(a == b);
	if (a->id > b->id)
		swap(a, b);

	spin_lock(&a->objects.lock);
	spin_lock_nested(&b->objects.lock, SINGLE_DEPTH_NESTING);

	lists_swap(&obj->mm.region.link, &donor->mm.region.link);
	swap(obj->mm.region.mem, donor->mm.region.mem);

	spin_unlock(&b->objects.lock);
	spin_unlock(&a->objects.lock);
}

static void
swap_shrinker(struct drm_i915_gem_object *obj, struct drm_i915_gem_object *donor)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	unsigned long flags;

	spin_lock_irqsave(&i915->mm.obj_lock, flags);
	lists_swap(&obj->mm.link, &donor->mm.link);
	swap(obj->mm.shrink_pin, donor->mm.shrink_pin);
	spin_unlock_irqrestore(&i915->mm.obj_lock, flags);
}

static void
swap_pages(struct drm_i915_gem_object *obj, struct drm_i915_gem_object *donor)
{
	swap(obj->mm.pages, donor->mm.pages);
	swap(obj->mm.mapping, donor->mm.mapping);
	swap(obj->mm.page_sizes, donor->mm.page_sizes);

	__i915_gem_object_reset_page_iter(obj, obj->mm.pages);
	__i915_gem_object_reset_page_iter(donor, donor->mm.pages);
}

int i915_gem_object_migrate(struct drm_i915_gem_object *obj,
			    struct i915_gem_ww_ctx *ww,
			    struct intel_context *ce,
			    enum intel_region_id id)
{
	struct drm_i915_gem_object *donor;
	int err = 0;

	assert_object_held(obj);

	GEM_BUG_ON(id >= INTEL_REGION_UNKNOWN);
	if (obj->mm.region.mem->id == id)
		return 0;

	if (GEM_WARN_ON(obj->mm.madv != I915_MADV_WILLNEED))
		return -EFAULT;

	if (id == INTEL_REGION_SMEM) {
		err = __i915_gem_object_put_pages(obj);
		if (err)
			return err;
	}

	if (obj->swapto && id == INTEL_REGION_SMEM) {
		donor = fetch_and_zero(&obj->swapto);
	} else {
		donor = i915_gem_object_create_region(to_i915(obj->base.dev)->mm.regions[id],
						      obj->base.size,
						      obj->flags & I915_BO_ALLOC_FLAGS);
		if (IS_ERR(donor))
			return PTR_ERR(donor);

		donor->base.resv = obj->base.resv;
	}
	assert_object_held(donor);
	GEM_BUG_ON(donor->mm.region.mem->id != id);

	/* Prevent concurrent access to the backing store by the user */
	i915_gem_object_release_mmap(obj);

	/* Copy backing store if we have to */
	if (i915_gem_object_has_pages(obj) || obj->base.filp) {
		err = i915_gem_object_ww_copy_blt(obj, donor, ww, ce);
		if (err)
			goto out;

		/*
		 * Occasionally i915_gem_object_wait() called inside
		 * i915_gem_object_set_to_cpu_domain() get interrupted
		 * and return -ERESTARTSYS, this will make migration
		 * operation fail. So adding a non-interruptible wait
		 * before changing the object domain.
		 */
		err = i915_gem_object_wait(donor, 0, MAX_SCHEDULE_TIMEOUT);
		if (err)
			goto out;

		err = i915_gem_object_unbind(donor, 0);
		if (err)
			goto out;

		err = i915_gem_object_unbind(obj, I915_GEM_OBJECT_UNBIND_ACTIVE);
		if (err)
			goto out;
	}

	swap(obj->base.size, donor->base.size);
	swap(obj->base.filp, donor->base.filp);
	swap(obj->flags, donor->flags);
	swap(obj->ops, donor->ops);

	swap_blocks(obj, donor);
	swap_region(obj, donor);
	swap_shrinker(obj, donor);
	swap_pages(obj, donor);

	GEM_BUG_ON(obj->mm.region.mem->id != id);
	GEM_BUG_ON(obj->swapto && id == INTEL_REGION_SMEM);

out:
	/* Need to set I915_MADV_DONTNEED so that shrinker can free it */
	donor->mm.madv = I915_MADV_DONTNEED; /* XXX set_madv() */
	i915_gem_object_put(donor);
	return err;
}

struct object_memcpy_info {
	struct drm_i915_gem_object *obj;
	intel_wakeref_t wakeref;
	bool write;
	int clflush;
	struct page *page;
	struct iosys_map map;
	struct iosys_map *(*get_map)(struct object_memcpy_info *info,
			   unsigned long idx);
	void (*put_map)(struct object_memcpy_info *info);
};

static struct iosys_map *
lmem_get_map(struct object_memcpy_info *info, unsigned long idx)
{
	void __iomem *vaddr;

	vaddr = i915_gem_object_lmem_io_map_page(info->obj, idx);
	iosys_map_set_vaddr_iomem(&info->map, vaddr);

	return &info->map;
}

static void lmem_put_map(struct object_memcpy_info *info)
{
	io_mapping_unmap(info->map.vaddr_iomem);
}

static struct iosys_map *
smem_get_map(struct object_memcpy_info *info, unsigned long idx)
{
	void *vaddr;

	info->page = i915_gem_object_get_page(info->obj, idx);
	vaddr = kmap(info->page);
	iosys_map_set_vaddr(&info->map, vaddr);
	if (info->clflush & CLFLUSH_BEFORE)
		drm_clflush_virt_range(info->map.vaddr, PAGE_SIZE);
	return &info->map;
}

static void smem_put_map(struct object_memcpy_info *info)
{
	if (info->clflush & CLFLUSH_AFTER)
		drm_clflush_virt_range(info->map.vaddr, PAGE_SIZE);
	kunmap(info->page);
}

static int
i915_gem_object_prepare_memcpy(struct drm_i915_gem_object *obj,
			       struct object_memcpy_info *info,
			       bool write)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	int ret;

	assert_object_held(obj);
	ret = i915_gem_object_wait(obj,
				   I915_WAIT_INTERRUPTIBLE,
				   MAX_SCHEDULE_TIMEOUT);
	if (ret)
		return ret;

	ret = i915_gem_object_pin_pages(obj);
	if (ret)
		return ret;

	if (i915_gem_object_is_lmem(obj)) {
		ret = i915_gem_object_set_to_wc_domain(obj, write);
		if (!ret) {
			info->wakeref =
				intel_runtime_pm_get(&i915->runtime_pm);
			info->get_map = lmem_get_map;
			info->put_map = lmem_put_map;
		}
	} else {
		if (write)
			ret = i915_gem_object_prepare_write(obj,
							    &info->clflush);
		else
			ret = i915_gem_object_prepare_read(obj,
							   &info->clflush);

		if (!ret) {
			i915_gem_object_finish_access(obj);
			info->get_map = smem_get_map;
			info->put_map = smem_put_map;
		}
	}

	if (!ret) {
		info->obj = obj;
		info->write = write;
	} else {
		i915_gem_object_unpin_pages(obj);
	}

	return ret;
}

static void
i915_gem_object_finish_memcpy(struct object_memcpy_info *info)
{
	struct drm_i915_private *i915 = to_i915(info->obj->base.dev);

	if (i915_gem_object_is_lmem(info->obj)) {
		intel_runtime_pm_put(&i915->runtime_pm, info->wakeref);
	} else {
		if (info->write) {
			i915_gem_object_flush_frontbuffer(info->obj,
							  ORIGIN_CPU);
			info->obj->mm.dirty = true;
		}
	}
	i915_gem_object_unpin_pages(info->obj);
}

int i915_gem_object_memcpy(struct drm_i915_gem_object *dst,
			   struct drm_i915_gem_object *src)
{
	struct object_memcpy_info sinfo, dinfo;
	struct iosys_map *smap, *dmap;
	unsigned long npages;
	int i, ret;

	ret = i915_gem_object_prepare_memcpy(src, &sinfo, false);
	if (ret)
		return ret;

	ret = i915_gem_object_prepare_memcpy(dst, &dinfo, true);
	if (ret)
		goto finish_src;

	npages = src->base.size / PAGE_SIZE;
	for (i = 0; i < npages; i++) {
		smap = sinfo.get_map(&sinfo, i);
		dmap = dinfo.get_map(&dinfo, i);

		i915_memcpy_iosys_map(dmap, smap, PAGE_SIZE);

		dinfo.put_map(&dinfo);
		sinfo.put_map(&sinfo);

		cond_resched();
	}

	i915_gem_object_finish_memcpy(&dinfo);
finish_src:
	i915_gem_object_finish_memcpy(&sinfo);

	return ret;
}

void __i915_gem_object_flush_frontbuffer(struct drm_i915_gem_object *obj,
					 enum fb_op_origin origin)
{
	struct intel_frontbuffer *front;

	front = __intel_frontbuffer_get(obj);
	if (front) {
		intel_frontbuffer_flush(front, origin);
		intel_frontbuffer_put(front);
	}
}

void __i915_gem_object_invalidate_frontbuffer(struct drm_i915_gem_object *obj,
					      enum fb_op_origin origin)
{
	struct intel_frontbuffer *front;

	front = __intel_frontbuffer_get(obj);
	if (front) {
		intel_frontbuffer_invalidate(front, origin);
		intel_frontbuffer_put(front);
	}
}

static void
i915_gem_object_read_from_page_kmap(struct drm_i915_gem_object *obj, u64 offset, void *dst, int size)
{
	pgoff_t idx = offset >> PAGE_SHIFT;
	void *src_map;
	void *src_ptr;

	src_map = kmap_atomic(i915_gem_object_get_page(obj, idx));

	src_ptr = src_map + offset_in_page(offset);
	if (!(obj->cache_coherent & I915_BO_CACHE_COHERENT_FOR_READ))
		drm_clflush_virt_range(src_ptr, size);
	memcpy(dst, src_ptr, size);

	kunmap_atomic(src_map);
}

static void
i915_gem_object_read_from_page_iomap(struct drm_i915_gem_object *obj, u64 offset, void *dst, int size)
{
	pgoff_t idx = offset >> PAGE_SHIFT;
	dma_addr_t dma = i915_gem_object_get_dma_address(obj, idx);
	void __iomem *src_map;
	void __iomem *src_ptr;

	src_map = io_mapping_map_wc(&obj->mm.region.mem->iomap,
				    dma - obj->mm.region.mem->region.start,
				    PAGE_SIZE);

	src_ptr = src_map + offset_in_page(offset);
	if (!i915_memcpy_from_wc(dst, (void __force *)src_ptr, size))
		memcpy_fromio(dst, src_ptr, size);

	io_mapping_unmap(src_map);
}

/**
 * i915_gem_object_read_from_page - read data from the page of a GEM object
 * @obj: GEM object to read from
 * @offset: offset within the object
 * @dst: buffer to store the read data
 * @size: size to read
 *
 * Reads data from @obj at the specified offset. The requested region to read
 * from can't cross a page boundary. The caller must ensure that @obj pages
 * are pinned and that @obj is synced wrt. any related writes.
 *
 * Returns 0 on success or -ENODEV if the type of @obj's backing store is
 * unsupported.
 */
int i915_gem_object_read_from_page(struct drm_i915_gem_object *obj, u64 offset, void *dst, int size)
{
	GEM_BUG_ON(overflows_type(offset >> PAGE_SHIFT, pgoff_t));
	GEM_BUG_ON(offset >= obj->base.size);
	GEM_BUG_ON(offset_in_page(offset) > PAGE_SIZE - size);
	GEM_BUG_ON(!i915_gem_object_has_pinned_pages(obj));

	if (i915_gem_object_has_struct_page(obj))
		i915_gem_object_read_from_page_kmap(obj, offset, dst, size);
	else if (i915_gem_object_has_iomem(obj))
		i915_gem_object_read_from_page_iomap(obj, offset, dst, size);
	else
		return -ENODEV;

	return 0;
}

/**
 * i915_gem_object_evictable - Whether object is likely evictable after unbind.
 * @obj: The object to check
 *
 * This function checks whether the object is likely unvictable after unbind.
 * If the object is not locked when checking, the result is only advisory.
 * If the object is locked when checking, and the function returns true,
 * then an eviction should indeed be possible. But since unlocked vma
 * unpinning and unbinding is currently possible, the object can actually
 * become evictable even if this function returns false.
 *
 * Return: true if the object may be evictable. False otherwise.
 */
bool i915_gem_object_evictable(struct drm_i915_gem_object *obj)
{
	struct i915_vma *vma;
	int pin_count = atomic_read(&obj->mm.pages_pin_count);

	if (!pin_count)
		return true;

	spin_lock(&obj->vma.lock);
	list_for_each_entry(vma, &obj->vma.list, obj_link) {
		if (i915_vma_is_pinned(vma)) {
			spin_unlock(&obj->vma.lock);
			return false;
		}
		if (atomic_read(&vma->pages_count))
			pin_count--;
	}
	spin_unlock(&obj->vma.lock);
	GEM_WARN_ON(pin_count < 0);

	return pin_count == 0;
}

/**
 * i915_gem_object_migratable - Whether the object is migratable out of the
 * current region.
 * @obj: Pointer to the object.
 *
 * Return: Whether the object is allowed to be resident in other
 * regions than the current while pages are present.
 */
bool i915_gem_object_migratable(struct drm_i915_gem_object *obj)
{
	struct intel_memory_region *mr = READ_ONCE(obj->mm.region.mem);

	if (!mr)
		return false;

	return obj->mm.n_placements > 1;
}

void i915_gem_init__objects(struct drm_i915_private *i915)
{
	INIT_WORK(&i915->mm.free_work, __i915_gem_free_work);
}

void i915_objects_module_exit(void)
{
	kmem_cache_destroy(slab_objects);
}

int __init i915_objects_module_init(void)
{
	slab_objects = KMEM_CACHE(drm_i915_gem_object, SLAB_HWCACHE_ALIGN);
	if (!slab_objects)
		return -ENOMEM;

	return 0;
}

static const struct drm_gem_object_funcs i915_gem_object_funcs = {
	.free = i915_gem_free_object,
	.close = i915_gem_close_object,
	.export = i915_gem_prime_export,
};

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftests/huge_gem_object.c"
#include "selftests/huge_pages.c"
#include "selftests/i915_gem_object.c"
#include "selftests/i915_gem_coherency.c"
#endif
