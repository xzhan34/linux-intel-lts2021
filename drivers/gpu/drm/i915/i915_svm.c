// SPDX-License-Identifier: MIT
/*
 * Copyright © 2019 Intel Corporation
 */

#include <linux/mm_types.h>
#include <linux/sched/mm.h>

#include "i915_svm.h"
#include "intel_memory_region.h"
#include "gem/i915_gem_context.h"

struct svm_notifier {
	struct mmu_interval_notifier notifier;
	struct i915_svm *svm;
};

static bool i915_svm_range_invalidate(struct mmu_interval_notifier *mni,
				      const struct mmu_notifier_range *range,
				      unsigned long cur_seq)
{
	struct svm_notifier *sn =
		container_of(mni, struct svm_notifier, notifier);
	struct i915_svm *svm = sn->svm;
	unsigned long length = range->end - range->start;

	if (mmu_notifier_range_blockable(range))
		mutex_lock(&svm->mutex);
	else if (!mutex_trylock(&svm->mutex))
		return false;
	mmu_interval_set_seq(mni, cur_seq);
	svm_unbind_addr(svm->vm, range->start, length);
	mutex_unlock(&svm->mutex);
	return true;
}

static const struct mmu_interval_notifier_ops i915_svm_mni_ops = {
	.invalidate = i915_svm_range_invalidate,
};

/** register a mmu interval notifier to monitor vma change
 * @vma: vma to monitor
 * @svm: which i915_svm is monitoring the vma
 * if this vma is already been registered with a notifier, return it directly;
 * otherwise create and insert a new notifier.
 */
static struct svm_notifier *register_svm_notifier(struct vm_area_struct *vma,
						struct i915_svm *svm)
{
	struct svm_notifier *sn;
	u64 start, length;
	int ret = 0;

	sn = (struct svm_notifier *)vma->vm_private_data;
	if (sn)
		return sn;

	sn = kmalloc(sizeof(*sn), GFP_KERNEL);
	if (!sn)
		return ERR_PTR(-ENOMEM);

	start =  vma->vm_start;
	length = vma->vm_end - vma->vm_start;
	ret = mmu_interval_notifier_insert(&sn->notifier, vma->vm_mm,
					   start, length,
					   &i915_svm_mni_ops);
	if (ret) {
		kfree(sn);
		return ERR_PTR(ret);
	}

	sn->svm = svm;
	vma->vm_private_data = sn;
	return sn;
}

static void unregister_svm_notifier(struct vm_area_struct *vma,
		struct i915_svm *svm)
{
	struct svm_notifier *sn;

	sn = (struct svm_notifier *)vma->vm_private_data;
	if (!sn)
	    return;

	if (sn->svm != svm)
		return;

	mmu_interval_notifier_remove(&sn->notifier);
	kfree(sn);
	vma->vm_private_data = NULL;
}

static struct i915_svm *vm_get_svm(struct i915_address_space *vm)
{
	struct i915_svm *svm = vm->svm;

	mutex_lock(&vm->svm_mutex);
	if (svm && !kref_get_unless_zero(&svm->ref))
		svm = NULL;

	mutex_unlock(&vm->svm_mutex);
	return svm;
}

static void release_svm(struct kref *ref)
{
	struct i915_svm *svm = container_of(ref, typeof(*svm), ref);
	struct i915_address_space *vm = svm->vm;
	struct mm_struct *mm = svm->mm;
	struct vm_area_struct *vma = 0;

	for (vma = mm->mmap; vma; vma = vma->vm_next) {
		unregister_svm_notifier(vma, svm);
	}

	mutex_destroy(&svm->mutex);
	vm->svm = NULL;
	mmdrop(svm->mm);
	kfree(svm);
}

static void vm_put_svm(struct i915_address_space *vm)
{
	mutex_lock(&vm->svm_mutex);
	if (vm->svm)
		kref_put(&vm->svm->ref, release_svm);
	mutex_unlock(&vm->svm_mutex);
}

static u32 i915_svm_build_sg(struct i915_address_space *vm,
			     struct hmm_range *range,
			     struct sg_table *st)
{
	struct scatterlist *sg;
	u32 sg_page_sizes = 0;
	u64 i, npages;

	sg = NULL;
	st->nents = 0;
	npages = (range->end - range->start) / PAGE_SIZE;

	/*
	 * No need to dma map the host pages and later unmap it, as
	 * GPU is not allowed to access it with SVM.
	 * XXX: Need to dma map host pages for integrated graphics while
	 * extending SVM support there.
	 */
	for (i = 0; i < npages; i++) {
		unsigned long addr = range->hmm_pfns[i];

		if (sg && (addr == (sg_dma_address(sg) + sg->length))) {
			sg->length += PAGE_SIZE;
			sg_dma_len(sg) += PAGE_SIZE;
			continue;
		}

		if (sg)
			sg_page_sizes |= sg->length;

		sg =  sg ? __sg_next(sg) : st->sgl;
		sg_dma_address(sg) = addr;
		sg_dma_len(sg) = PAGE_SIZE;
		sg->length = PAGE_SIZE;
		st->nents++;
	}

	sg_page_sizes |= sg->length;
	sg_mark_end(sg);
	return sg_page_sizes;
}

int i915_gem_vm_unbind_svm_buffer(struct i915_address_space *vm,
				  struct prelim_drm_i915_gem_vm_bind *va)
{
	struct i915_svm *svm;
	struct mm_struct *mm;
	int ret = 0;

	if (unlikely(!i915_vm_is_svm_enabled(vm)))
		return -ENOTSUPP;

	svm = vm_get_svm(vm);
	if (!svm)
		return -EINVAL;

	mm = svm->mm;
	if (mm != current->mm) {
		ret = -EPERM;
		goto unbind_done;
	}

	va->length += (va->start & ~PAGE_MASK);
	va->start &= PAGE_MASK;
	mutex_lock(&svm->mutex);
	svm_unbind_addr(vm, va->start, va->length);
	mutex_unlock(&svm->mutex);

unbind_done:
	vm_put_svm(vm);
	return ret;
}

static int i915_hmm_convert_pfn(struct drm_i915_private *dev_priv,
				struct hmm_range *range)
{
	unsigned long i, npages;
	int regions = 0;

	npages = (range->end - range->start) >> PAGE_SHIFT;
	for (i = 0; i < npages; ++i) {
		struct page *page;
		unsigned long addr;

		if (!(range->hmm_pfns[i] & HMM_PFN_VALID)) {
			range->hmm_pfns[i] = 0;
			continue;
		}

		page = hmm_pfn_to_page(range->hmm_pfns[i]);
		if (!page)
			continue;

		if (is_device_private_page(page)) {
			struct i915_buddy_block *block = page->zone_device_data;
			struct intel_memory_region *mem = block->private;

			regions |= REGION_LMEM;
			addr = mem->region.start + i915_buddy_block_offset(block);
			addr += (page_to_pfn(page) - block->pfn_first) << PAGE_SHIFT;
		} else {
			regions |= REGION_SMEM;
			addr = page_to_phys(page);
		}

		range->hmm_pfns[i] = addr;
	}

	return regions;
}

static int i915_range_fault(struct svm_notifier *sn,
			    __u64 start, __u64 length, __u64 flags,
			    struct sg_table *st, unsigned long *pfns)
{
	unsigned long timeout =
		jiffies + msecs_to_jiffies(HMM_RANGE_DEFAULT_TIMEOUT);
	struct i915_svm *svm = sn->svm;
	struct i915_address_space *vm = svm->vm;
	/* Have HMM fault pages within the fault window to the GPU. */
	struct hmm_range range = {
		.notifier = &sn->notifier,
		.start = sn->notifier.interval_tree.start,
		.end = sn->notifier.interval_tree.last + 1,
		.pfn_flags_mask = HMM_PFN_REQ_FAULT | HMM_PFN_REQ_WRITE,
		.hmm_pfns = pfns,
		.dev_private_owner = vm->i915->drm.dev,
	};
	struct mm_struct *mm = sn->notifier.mm;
	struct i915_vm_pt_stash stash = {};
	struct i915_gem_ww_ctx ww;
	u32 sg_page_sizes;
	int regions;
	long ret;

	while (true) {
		if (time_after(jiffies, timeout))
			return -EBUSY;

		range.notifier_seq = mmu_interval_read_begin(range.notifier);
		mmap_read_lock(mm);
		ret = hmm_range_fault(&range);
		mmap_read_unlock(mm);
		if (ret) {
			if (ret == -EBUSY)
				continue;
			return ret;
		}

		/* Ensure the range is in one memory region */
		regions = i915_hmm_convert_pfn(vm->i915, &range);
		if (!regions ||
		    ((regions & REGION_SMEM) && (regions & REGION_LMEM)))
			return -EINVAL;

		sg_page_sizes = i915_svm_build_sg(vm, &range, st);

		/* XXX: Not an elegant solution, revisit */
		i915_gem_ww_ctx_init(&ww, true);
		ret = svm_bind_addr_prepare(vm, &stash, &ww, start, length);
		if (ret)
			goto fault_done;

		mutex_lock(&svm->mutex);
		if (mmu_interval_read_retry(range.notifier,
					    range.notifier_seq)) {
			svm_unbind_addr(vm, start, length);
			mutex_unlock(&svm->mutex);
			i915_vm_free_pt_stash(vm, &stash);
			i915_gem_ww_ctx_fini(&ww);
			continue;
		}
		break;
	}

	flags = (flags & PRELIM_I915_GEM_VM_BIND_READONLY) ?
		 I915_GTT_SVM_READONLY : 0;
	flags |= (regions & REGION_LMEM) ? I915_GTT_SVM_LMEM : 0;
	ret = svm_bind_addr_commit(vm, &stash, start, length, flags,
				   st, sg_page_sizes);
	mutex_unlock(&svm->mutex);
	i915_vm_free_pt_stash(vm, &stash);
fault_done:
	i915_gem_ww_ctx_fini(&ww);
	return ret;
}

/* Determine whether read or/and write to vma is allowed
 * write: true means a read and write access; false: read only access
 */
static bool svm_access_allowed(struct vm_area_struct *vma, bool write)
{
	unsigned long access = VM_READ;

	if (write)
		access |= VM_WRITE;

	return (vma->vm_flags & access) == access;
}

static bool svm_should_migrate(u64 va, enum intel_region_id dst_region, bool is_atomic_fault)
{
	return true;
}

/**
 * svm_migrate_to_vram() - migrate backing store of a va range to vram
 * @mm: the process mm_struct of the va range
 * @start: start of the va range
 * @length: length of the va range
 * @mem: destination migration memory region
 *
 * Returns: negative errno on faiure, 0 on success
 */
static int svm_migrate_to_vram(struct mm_struct *mm,
			__u64 start, __u64 length,
			struct intel_memory_region *mem)
{
	unsigned long addr, end;
	struct i915_gem_ww_ctx ww;
	int err = 0;

	if (!mem->devmem)
		return -EINVAL;

	mmap_read_lock(mm);
	i915_gem_ww_ctx_init(&ww, true);
retry:
	for (addr = start, end = start + length; addr < end;) {
		struct vm_area_struct *vma;
		unsigned long next;

		vma = find_vma_intersection(mm, addr, end);
		if (!vma)
			break;

		addr &= PAGE_MASK;
		next = min(vma->vm_end, end);
		next = round_up(next, PAGE_SIZE);

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
	return 0;
}

int i915_svm_handle_gpu_fault(struct i915_address_space *vm,
				struct intel_gt *gt,
				struct recoverable_page_fault_info *info)
{
	unsigned long *pfns, flags = HMM_PFN_REQ_FAULT;
	struct vm_area_struct *vma;
	u64 npages, start, length;
	struct svm_notifier *sn;
	struct i915_svm *svm;
	struct mm_struct *mm;
	struct sg_table st;
	int ret = 0;

	svm = vm_get_svm(vm);
	if (!svm)
		return -EINVAL;

	mm = svm->mm;
	vma = find_vma_intersection(mm, info->page_addr, info->page_addr + 4);
	if (!vma) {
		ret = -ENOENT;
		goto put_svm;
	}

	if (!svm_access_allowed (vma, info->access_type != ACCESS_TYPE_READ)) {
		ret = -EPERM;
		goto put_svm;
	}

	sn = register_svm_notifier(vma, svm);
	if (IS_ERR(sn)) {
		ret = PTR_ERR(sn);
		goto put_svm;
	}

	/** migrate the whole vma */
	start =  vma->vm_start;
	length = vma->vm_end - vma->vm_start;
	npages = vma->vm_end / PAGE_SIZE - vma->vm_start / PAGE_SIZE + 1;

	if (svm_should_migrate(start, gt->lmem->id, info->access_type == ACCESS_TYPE_ATOMIC))
		/*
		 * Migration is best effort. If we failed to migrate to vram,
		 * we just map that range to gpu in system memory. For cases
		 * such as gpu atomic operation which requires memory to be
		 * resident in vram, we will fault again and retry migration.
		 */
		svm_migrate_to_vram(mm, start, length, gt->lmem);

	if (unlikely(sg_alloc_table(&st, npages, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto unregister_notifier;
	}

	pfns = kvmalloc_array(npages, sizeof(*pfns), GFP_KERNEL);
	if (unlikely(!pfns)) {
		ret = -ENOMEM;
		goto free_sg;
	}

	if (vma->vm_flags & VM_WRITE)
		flags |= HMM_PFN_REQ_WRITE;

	memset64((u64 *)pfns, (u64)flags, npages);

	ret = i915_range_fault(sn, start, length,
		!(vma->vm_flags & VM_WRITE) ? PRELIM_I915_GEM_VM_BIND_READONLY : 0,
		&st, pfns);

	kvfree(pfns);
free_sg:
	sg_free_table(&st);
unregister_notifier:
	unregister_svm_notifier(vma, svm);
put_svm:
	vm_put_svm(vm);
	return ret;
}

int i915_gem_vm_bind_svm_buffer(struct i915_address_space *vm,
				struct prelim_drm_i915_gem_vm_bind *va)
{
	unsigned long *pfns, flags = HMM_PFN_REQ_FAULT;
	struct svm_notifier sn;
	struct i915_svm *svm;
	struct mm_struct *mm;
	struct sg_table st;
	int ret = 0;
	u64 npages;

	if (unlikely(!i915_vm_is_svm_enabled(vm)))
		return -ENOTSUPP;

	svm = vm_get_svm(vm);
	if (!svm)
		return -EINVAL;

	mm = svm->mm;
	if (mm != current->mm) {
		ret = -EPERM;
		goto bind_done;
	}

	va->length += (va->start & ~PAGE_MASK);
	va->start &= PAGE_MASK;
	npages = va->length / PAGE_SIZE;
	if (unlikely(sg_alloc_table(&st, npages, GFP_KERNEL))) {
		ret = -ENOMEM;
		goto bind_done;
	}

	pfns = kvmalloc_array(npages, sizeof(*pfns), GFP_KERNEL);
	if (unlikely(!pfns)) {
		ret = -ENOMEM;
		goto range_done;
	}

	if (!(va->flags & PRELIM_I915_GEM_VM_BIND_READONLY))
		flags |= HMM_PFN_REQ_WRITE;

	memset64((u64 *)pfns, (u64)flags, npages);

	sn.svm = svm;
	ret = mmu_interval_notifier_insert(&sn.notifier, mm,
					   va->start, va->length,
					   &i915_svm_mni_ops);
	if (!ret) {
		ret = i915_range_fault(&sn, va->start, va->length, va->flags, &st, pfns);
		mmu_interval_notifier_remove(&sn.notifier);
	}

	kvfree(pfns);
range_done:
	sg_free_table(&st);
bind_done:
	vm_put_svm(vm);
	return ret;
}

void i915_svm_unbind_mm(struct i915_address_space *vm)
{
	vm_put_svm(vm);
}

int i915_svm_bind_mm(struct i915_address_space *vm)
{
	struct mm_struct *mm = current->mm;
	struct i915_svm *svm;
	int ret = 0;

	mmap_write_lock(mm);
	mutex_lock(&vm->svm_mutex);
	if (vm->svm)
		goto bind_out;

	svm = kzalloc(sizeof(*svm), GFP_KERNEL);
	if (!svm) {
		ret = -ENOMEM;
		goto bind_out;
	}
	mutex_init(&svm->mutex);
	kref_init(&svm->ref);
	svm->vm = vm;
	mmgrab(mm);
	svm->mm = mm;

	vm->svm = svm;
bind_out:
	mutex_unlock(&vm->svm_mutex);
	mmap_write_unlock(mm);
	return ret;
}
