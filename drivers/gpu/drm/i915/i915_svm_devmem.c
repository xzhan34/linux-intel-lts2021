// SPDX-License-Identifier: MIT
/*
 * Copyright © 2019 Intel Corporation
 */

#include <linux/mm_types.h>
#include <linux/sched/mm.h>

#include "i915_svm.h"
#include "intel_memory_region.h"

struct i915_devmem_migrate {
	struct drm_i915_private *i915;
	struct migrate_vma *args;

	enum intel_region_id src_id;
	enum intel_region_id dst_id;
	u64 npages;
};

struct i915_devmem {
	struct intel_memory_region *mem;
	struct dev_pagemap pagemap;
	unsigned long pfn_first;
	unsigned long pfn_last;
};

static int
i915_devmem_page_alloc_locked(struct intel_memory_region *mem,
			      unsigned long npages,
			      struct list_head *blocks,
			      struct i915_gem_ww_ctx *ww)
{
	unsigned long size = ALIGN((npages * PAGE_SIZE), mem->mm.chunk_size);
	struct i915_buddy_block *block;
	int ret;

	INIT_LIST_HEAD(blocks);
	ret = __intel_memory_region_get_pages_buddy(mem, ww, size, 0, blocks);
	if (unlikely(ret))
		goto alloc_failed;

	list_for_each_entry(block, blocks, link) {
		block->pfn_first = mem->devmem->pfn_first;
		block->pfn_first += i915_buddy_block_offset(block) /
				    PAGE_SIZE;
		bitmap_zero(block->bitmap, I915_BUDDY_MAX_PAGES);
		DRM_DEBUG_DRIVER("%s pfn_first 0x%lx off 0x%llx size 0x%llx\n",
				 "Allocated block", block->pfn_first,
				 i915_buddy_block_offset(block),
				 i915_buddy_block_size(&mem->mm, block));
	}

alloc_failed:
	return ret;
}

static struct page *
i915_devmem_page_get_locked(struct intel_memory_region *mem,
			    struct list_head *blocks)
{
	struct i915_buddy_block *block, *on;

	list_for_each_entry_safe(block, on, blocks, link) {
		unsigned long weight, max;
		unsigned long i, pfn;
		struct page *page;

		max = i915_buddy_block_size(&mem->mm, block) / PAGE_SIZE;
		i = find_first_zero_bit(block->bitmap, max);
		if (unlikely(i == max)) {
			WARN(1, "Getting a page should have never failed\n");
			break;
		}

		set_bit(i, block->bitmap);
		pfn = block->pfn_first + i;
		page = pfn_to_page(pfn);
		get_page(page);
		lock_page(page);
		page->zone_device_data = block;
		weight = bitmap_weight(block->bitmap, max);
		if (weight == max)
			list_del_init(&block->link);
		DRM_DEBUG_DRIVER("%s pfn 0x%lx block weight 0x%lx\n",
				 "Allocated page", pfn, weight);
		return page;
	}
	return NULL;
}

static void
i915_devmem_page_free_locked(struct drm_i915_private *dev_priv,
			     struct page *page)
{
	unlock_page(page);
	put_page(page);
}

static int
i915_devmem_migrate_alloc_and_copy(struct i915_devmem_migrate *migrate,
				   struct i915_gem_ww_ctx *ww)
{
	struct drm_i915_private *i915 = migrate->i915;
	struct migrate_vma *args = migrate->args;
	struct intel_memory_region *mem;
	struct list_head blocks = {0};
	unsigned long i, npages, cnt;
	struct page *page;
	int ret;

	npages = (args->end - args->start) >> PAGE_SHIFT;
	DRM_DEBUG_DRIVER("start 0x%lx npages %ld\n", args->start, npages);

	/* Check source pages */
	for (i = 0, cnt = 0; i < npages; i++) {
		args->dst[i] = 0;
		page = migrate_pfn_to_page(args->src[i]);
		if (unlikely(!page || !(args->src[i] & MIGRATE_PFN_MIGRATE)))
			continue;

		args->dst[i] = MIGRATE_PFN_VALID;
		cnt++;
	}

	if (!cnt) {
		ret = -ENOMEM;
		goto migrate_out;
	}

	mem = i915->mm.regions[migrate->dst_id];
	ret = i915_devmem_page_alloc_locked(mem, cnt, &blocks, ww);
	if (unlikely(ret))
		goto migrate_out;

	/* Allocate device memory */
	for (i = 0, cnt = 0; i < npages; i++) {
		if (!args->dst[i])
			continue;

		page = i915_devmem_page_get_locked(mem, &blocks);
		if (unlikely(!page)) {
			WARN(1, "Failed to get dst page\n");
			args->dst[i] = 0;
			continue;
		}

		cnt++;
		args->dst[i] = migrate_pfn(page_to_pfn(page)) |
			       MIGRATE_PFN_LOCKED;
	}

	if (!cnt) {
		ret = -ENOMEM;
		goto migrate_out;
	}

	/* Copy the pages */
	migrate->npages = npages;
migrate_out:
	if (unlikely(ret)) {
		for (i = 0; i < npages; i++) {
			if (args->dst[i] & MIGRATE_PFN_LOCKED) {
				page = migrate_pfn_to_page(args->dst[i]);
				i915_devmem_page_free_locked(i915, page);
			}
			args->dst[i] = 0;
		}
	}

	return ret;
}

static void
i915_devmem_migrate_finalize_and_map(struct i915_devmem_migrate *migrate)
{
	DRM_DEBUG_DRIVER("npages %lld\n", migrate->npages);
}

static int i915_devmem_migrate_chunk(struct i915_devmem_migrate *migrate,
				     struct i915_gem_ww_ctx *ww)
{
	int ret;

	ret = i915_devmem_migrate_alloc_and_copy(migrate, ww);
	if (!ret) {
		migrate_vma_pages(migrate->args);
		i915_devmem_migrate_finalize_and_map(migrate);
	}
	migrate_vma_finalize(migrate->args);

	return ret;
}

static int i915_devmem_migrate_vma(struct intel_memory_region *mem,
				   struct i915_gem_ww_ctx *ww,
				   struct vm_area_struct *vma,
				   unsigned long start,
				   unsigned long end)
{
	unsigned long npages = (end - start) >> PAGE_SHIFT;
	unsigned long max = min_t(unsigned long, I915_BUDDY_MAX_PAGES, npages);
	struct i915_devmem_migrate migrate = {0};
	struct migrate_vma args = {
		.vma		= vma,
		.start		= start,
		.pgmap_owner    = mem->i915->drm.dev,
		.flags          = MIGRATE_VMA_SELECT_SYSTEM,
	};
	unsigned long c, i;
	int ret = 0;

	/* XXX: Opportunistically migrate additional pages? */
	DRM_DEBUG_DRIVER("start 0x%lx end 0x%lx\n", start, end);
	args.src = kcalloc(max, sizeof(args.src), GFP_KERNEL);
	if (unlikely(!args.src))
		return -ENOMEM;

	args.dst = kcalloc(max, sizeof(args.dst), GFP_KERNEL);
	if (unlikely(!args.dst)) {
		kfree(args.src);
		return -ENOMEM;
	}

	/* XXX: Support migrating from LMEM to SMEM */
	migrate.args = &args;
	migrate.i915 = mem->i915;
	migrate.src_id = INTEL_REGION_SMEM;
	migrate.dst_id = mem->id;
	for (i = 0; i < npages; i += c) {
		c = min_t(unsigned long, I915_BUDDY_MAX_PAGES, npages);
		args.end = start + (c << PAGE_SHIFT);
		ret = migrate_vma_setup(&args);
		if (unlikely(ret))
			goto migrate_done;
		if (args.cpages) {
			if (i915_devmem_migrate_chunk(&migrate, ww) == -EDEADLK) {
				ret = -EDEADLK;
				goto migrate_done;
			}
		}
		args.start = args.end;
	}
migrate_done:
	kfree(args.dst);
	kfree(args.src);
	return ret;
}

static vm_fault_t i915_devmem_migrate_to_ram(struct vm_fault *vmf)
{
	return VM_FAULT_SIGBUS;
}

static void i915_devmem_page_free(struct page *page)
{
	struct i915_buddy_block *block = page->zone_device_data;
	struct intel_memory_region *mem = block->private;
	unsigned long i, max, weight;

	max = i915_buddy_block_size(&mem->mm, block) / PAGE_SIZE;
	i = page_to_pfn(page) - block->pfn_first;
	clear_bit(i, block->bitmap);
	weight = bitmap_weight(block->bitmap, max);
	DRM_DEBUG_DRIVER("%s pfn 0x%lx block weight 0x%lx\n",
			 "Freeing page", page_to_pfn(page), weight);
	if (!weight) {
		DRM_DEBUG_DRIVER("%s pfn_first 0x%lx off 0x%llx size 0x%llx\n",
				 "Freeing block", block->pfn_first,
				 i915_buddy_block_offset(block),
				 i915_buddy_block_size(&mem->mm, block));
		__intel_memory_region_put_block_buddy(block);
	}
}

static const struct dev_pagemap_ops i915_devmem_pagemap_ops = {
	.page_free = i915_devmem_page_free,
	.migrate_to_ram = i915_devmem_migrate_to_ram,
};

int i915_svm_devmem_add(struct intel_memory_region *mem)
{
	struct device *dev = &to_pci_dev(mem->i915->drm.dev)->dev;
	struct i915_devmem *devmem;
	struct resource *res;
	void *addr;
	int ret;

	devmem = kzalloc(sizeof(*devmem), GFP_KERNEL);
	if (!devmem)
		return -ENOMEM;

	devmem->mem = mem;
	res = devm_request_free_mem_region(dev, &iomem_resource,
					   resource_size(&mem->region));
	if (IS_ERR(res)) {
		ret = PTR_ERR(res);
		goto devm_err;
	}

	devmem->pagemap.type = MEMORY_DEVICE_PRIVATE;
	devmem->pagemap.range.start = res->start;
	devmem->pagemap.range.end = res->end;
	devmem->pagemap.nr_range = 1;
	devmem->pagemap.ops = &i915_devmem_pagemap_ops;
	devmem->pagemap.owner = mem->i915->drm.dev;
	addr = devm_memremap_pages(dev, &devmem->pagemap);
	if (IS_ERR(addr)) {
		ret = PTR_ERR(addr);
		goto devm_err;
	}

	devmem->pfn_first = res->start >> PAGE_SHIFT;
	devmem->pfn_last = res->end >> PAGE_SHIFT;
	mem->devmem = devmem;
	return 0;
devm_err:
	kfree(devmem);
	return ret;
}

void i915_svm_devmem_remove(struct intel_memory_region *mem)
{
	if (mem->devmem) {
		devm_memunmap_pages(&to_pci_dev(mem->i915->drm.dev)->dev,
				    &mem->devmem->pagemap);
		kfree(mem->devmem);
		mem->devmem = NULL;
	}
}

int i915_gem_vm_prefetch_ioctl(struct drm_device *dev, void *data,
			       struct drm_file *file_priv)
{
	struct drm_i915_private *i915 = to_i915(dev);
	struct prelim_drm_i915_gem_vm_prefetch *args = data;
	unsigned long addr, end, size = args->length;
	struct intel_memory_region *mem;
	struct i915_gem_ww_ctx ww;
	struct mm_struct *mm;
	u16 class, instance;
	int err = 0;

	DRM_DEBUG_DRIVER("start 0x%llx length 0x%llx region 0x%x\n",
			 args->start, args->length, args->region);
	/*
	 * XXX: should this be updated to use class:instance instead of opaque
	 * id?
	 */
	class = args->region >> 16;
	instance = args->region & 0xffff;
	if (class != INTEL_MEMORY_LOCAL)
		return -EINVAL;

	mem = intel_memory_region_lookup(i915, class, instance);
	if (!mem)
		return -EINVAL;
	else if (!mem->devmem)
		return -ERANGE;

	mm = get_task_mm(current);
	mmap_read_lock(mm);

	i915_gem_ww_ctx_init(&ww, true);

retry:
	for (addr = args->start, end = args->start + size; addr < end;) {
		struct vm_area_struct *vma;
		unsigned long next;

		vma = find_vma_intersection(mm, addr, end);
		if (!vma)
			break;

		addr &= PAGE_MASK;
		next = min(vma->vm_end, end);
		next = round_up(next, PAGE_SIZE);

		/*
		 * XXX: This is a best effort so we ignore errors(expect in the
		 * case of ww backoff). It's not clear what the desired
		 * behaviour here is with ww + migrate_vma...
		 */
		err = i915_devmem_migrate_vma(mem, &ww, vma, addr, next);
		if (err == -EDEADLK)
			goto out_ww;

		addr = next;
	}

out_ww:
	if (err == -EDEADLK) {
		err = i915_gem_ww_ctx_backoff(&ww);
		if (!err)
			goto retry;
	}

	i915_gem_ww_ctx_fini(&ww);

	mmap_read_unlock(mm);
	mmput(mm);
	return 0;
}
