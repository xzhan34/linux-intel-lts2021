// SPDX-License-Identifier: MIT
/*
 * Copyright © 2019 Intel Corporation
 */

#include <linux/interval_tree_generic.h>

#include "gt/gen8_engine_cs.h"

#include "i915_drv.h"
#include "i915_gem_gtt.h"
#include "i915_gem_userptr.h"
#include "i915_gem_vm_bind.h"

#define START(node) ((node)->start)
#define LAST(node) ((node)->last)

INTERVAL_TREE_DEFINE(struct i915_vma, rb, u64, __subtree_last,
		     START, LAST, static inline, i915_vm_bind_it)

#undef START
#undef LAST

struct i915_vma *
i915_gem_vm_bind_lookup_vma(struct i915_address_space *vm, u64 va)
{
	struct i915_vma *vma, *temp;

	assert_vm_bind_held(vm);

	vma = i915_vm_bind_it_iter_first(&vm->va, va, va);
	/* Working around compiler error, remove later */
	if (vma)
		temp = i915_vm_bind_it_iter_next(vma, va + vma->size, -1);
	return vma;
}

static void i915_gem_vm_bind_unpublish(struct i915_vma *vma)
{
	struct i915_address_space *vm = vma->vm;

	mutex_lock_nested(&vm->mutex, SINGLE_DEPTH_NESTING);
	i915_vma_unpublish(vma);
	mutex_unlock(&vm->mutex);
}

static void i915_gem_vm_bind_release(struct i915_vma *vma)
{
	struct drm_i915_gem_object *obj = vma->obj;

	__i915_vma_put(vma);
	i915_gem_object_put(obj);
}

static void i915_gem_vm_bind_remove(struct i915_vma *vma)
{
	assert_vm_bind_held(vma->vm);
	GEM_BUG_ON(list_empty(&vma->vm_bind_link));

	spin_lock(&vma->vm->vm_capture_lock);
	if (!list_empty(&vma->vm_capture_link))
		list_del_init(&vma->vm_capture_link);
	spin_unlock(&vma->vm->vm_capture_lock);

	spin_lock(&vma->vm->vm_rebind_lock);
	list_del(&vma->vm_rebind_link);
	spin_unlock(&vma->vm->vm_rebind_lock);

	list_del_init(&vma->vm_bind_link);
	list_del_init(&vma->non_priv_vm_bind_link);
	i915_vm_bind_it_remove(vma, &vma->vm->va);
}

void i915_gem_vm_unbind_all(struct i915_address_space *vm)
{
	struct i915_vma *vma, *vn;

	i915_gem_vm_bind_lock(vm);
	list_for_each_entry_safe(vma, vn, &vm->vm_bind_list, vm_bind_link) {
		i915_gem_vm_bind_remove(vma);
		i915_gem_vm_bind_release(vma);
	}
	list_for_each_entry_safe(vma, vn, &vm->vm_bound_list, vm_bind_link) {
		i915_gem_vm_bind_remove(vma);
		i915_gem_vm_bind_release(vma);
	}
	i915_gem_vm_bind_unlock(vm);
}

int i915_gem_vm_unbind_obj(struct i915_address_space *vm,
			   struct prelim_drm_i915_gem_vm_bind *va)
{
	struct i915_vma *vma;
	int ret;

	/* Handle is not used and must be 0 */
	if (va->handle)
		return -EINVAL;

	va->start = gen8_noncanonical_addr(va->start);
	/* XXX: Support async and delayed unbind */
	ret = i915_gem_vm_bind_lock_interruptible(vm);
	if (ret)
		return ret;

	vma = i915_gem_vm_bind_lookup_vma(vm, va->start);
	if (!vma) {
		ret = -ENOENT;
		goto out_unlock;
	}

	if (vma->size != va->length) {
		ret = -EINVAL;
		goto out_unlock;
	}

	if (i915_vma_is_pinned(vma) || atomic_read(&vma->open_count)) {
		ret = -EAGAIN;
		goto out_unlock;
	}

	i915_gem_vm_bind_remove(vma);
	i915_gem_vm_bind_release(vma);

out_unlock:
	i915_gem_vm_bind_unlock(vm);

	return ret;
}

static struct i915_vma *vm_bind_get_vma(struct i915_address_space *vm,
					struct drm_i915_gem_object *obj,
					struct prelim_drm_i915_gem_vm_bind *va)
{
	struct i915_ggtt_view view;
	struct i915_vma *vma;

	va->start = gen8_noncanonical_addr(va->start);
	vma = i915_gem_vm_bind_lookup_vma(vm, va->start);
	if (vma)
		return ERR_PTR(-EEXIST);

	view.type = I915_GGTT_VIEW_PARTIAL;
	view.partial.offset = va->offset >> PAGE_SHIFT;
	view.partial.size = va->length >> PAGE_SHIFT;
	vma = i915_vma_instance(obj, vm, &view);
	if (IS_ERR(vma))
		return vma;

	vma->start = va->start;
	vma->last = va->start + va->length - 1;
	__set_bit(I915_VMA_PERSISTENT_BIT, __i915_vma_flags(vma));

	return __i915_vma_get(vma);
}

int i915_gem_vm_bind_obj(struct i915_address_space *vm,
			 struct prelim_drm_i915_gem_vm_bind *va,
			 struct drm_file *file)
{
	struct drm_i915_gem_object *obj;
	struct i915_gem_ww_ctx ww;
	struct i915_vma *vma;
	int ret;

	obj = i915_gem_object_lookup(file, va->handle);
	if (!obj)
		return -ENOENT;

	if (!va->length ||
	    !IS_ALIGNED(va->offset | va->length,
			i915_gem_object_max_page_size(obj)) ||
	    range_overflows_t(u64, va->offset, va->length, obj->base.size)) {
		ret = -EINVAL;
		goto put_obj;
	}

	if (obj->vm && obj->vm != vm) {
		ret = -EPERM;
		goto put_obj;
	}

	if (i915_gem_object_is_userptr(obj)) {
		ret = i915_gem_object_userptr_submit_init(obj);
		if (ret)
			goto put_obj;
	}

	ret = i915_gem_vm_bind_lock_interruptible(vm);
	if (ret)
		goto put_obj;

	vma = vm_bind_get_vma(vm, obj, va);
	if (IS_ERR(vma)) {
		ret = PTR_ERR(vma);
		goto unlock_vm;
	}
	/* Hold object reference until vm_unbind */
	i915_gem_object_get(vma->obj);

	i915_gem_ww_ctx_init(&ww, true);
	set_bit(I915_VM_HAS_PERSISTENT_BINDS, &vm->flags);
retry:
	if (va->flags & PRELIM_I915_GEM_VM_BIND_IMMEDIATE) {
		u64 pin_flags = va->start | PIN_OFFSET_FIXED | PIN_USER;

		/* Always take vm_priv lock here (just like execbuff path) even
		 * for shared BOs, this will prevent the eviction/shrinker logic
		 * from evicint private BOs of the VM.
		 */
		ret = i915_gem_vm_priv_lock(vm, &ww);
		if (ret)
			goto out_ww;

		ret = i915_gem_object_lock(vma->obj, &ww);
		if (ret)
			goto out_ww;

		if (i915_gem_object_is_userptr(obj)) {
			i915_gem_userptr_lock_mmu_notifier(vm->i915);
			ret = i915_gem_object_userptr_submit_done(obj);
			i915_gem_userptr_unlock_mmu_notifier(vm->i915);
			if (ret)
				goto out_ww;
		}

		ret = i915_vma_pin_ww(vma, &ww, 0, 0, pin_flags);
		if (ret)
			goto out_ww;

		__i915_vma_unpin(vma);
	}

	if (va->flags & PRELIM_I915_GEM_VM_BIND_CAPTURE) {
		spin_lock(&vm->vm_capture_lock);
		list_add_tail(&vma->vm_capture_link, &vm->vm_capture_list);
		spin_unlock(&vm->vm_capture_lock);
	}

	list_add_tail(&vma->vm_bind_link, &vm->vm_bind_list);
	i915_vm_bind_it_insert(vma, &vm->va);
	if (!obj->vm)
		list_add_tail(&vma->non_priv_vm_bind_link,
			      &vm->non_priv_vm_bind_list);

out_ww:
	if (ret == -EDEADLK) {
		ret = i915_gem_ww_ctx_backoff(&ww);
		if (!ret)
			goto retry;
	}
	i915_gem_ww_ctx_fini(&ww);

	if (ret) {
		i915_gem_vm_bind_unpublish(vma);
		i915_gem_vm_bind_release(vma);
	}
unlock_vm:
	i915_gem_vm_bind_unlock(vm);
put_obj:
	i915_gem_object_put(obj);
	return ret;
}
