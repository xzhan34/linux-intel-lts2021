// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_memirq.h"
#include "intel_iov_reg.h"
#include "intel_iov_utils.h"
#include "gem/i915_gem_lmem.h"

/**
 * Memory based irq page layout
 * We use a single page to contain the different objects used for memory
 * based irq (which are also called "page" in the specs, even if they
 * aren't page-sized). The address of those objects are them programmed
 * in the HW via LRI and LRM in the context image.
 *
 * - Interrupt Status Report page: this page contains the interrupt
 *   status vectors for each unit. Each bit in the interrupt vectors is
 *   converted to a byte, with the byte being set to 0xFF when an
 *   interrupt is triggered; interrupt vectors are 16b big so each unit
 *   gets 16B. One space is reseved for each bit in one of the
 *   GEN11_GT_INTR_DWx registers, so this object needs a total of 1024B.
 *   This object needs to be 4k aligned.
 *
 * - Interrupt Source Report page: this is the equivalent of the
 *   GEN11_GT_INTR_DWx registers, with each bit in those registers being
 *   mapped to a byte here. The offsets are the same, just bytes instead
 *   of bits. This object needs to be cacheline aligned.
 *
 * - Interrupt Mask: the HW needs a location to fetch the interrupt
 *   mask vector to be used by the LRM in the context, so we just use
 *   the next available space in the interrupt page
 */

static int vf_create_memirq_data(struct intel_iov *iov)
{
	struct drm_i915_private *i915 = iov_to_i915(iov);
	struct drm_i915_gem_object *obj;
	void *vaddr;
	int err;
	u32 *enable_vector;

	GEM_BUG_ON(!intel_iov_is_vf(iov));
	GEM_BUG_ON(!HAS_MEMORY_IRQ_STATUS(i915));
	GEM_BUG_ON(iov->vf.irq.obj);

	obj = i915_gem_object_create_shmem(i915, SZ_4K);
	if (IS_ERR(obj)) {
		err = PTR_ERR(obj);
		goto out;
	}

	vaddr = i915_gem_object_pin_map_unlocked(obj, i915_coherent_map_type(i915, obj, true));
	if (IS_ERR(vaddr)) {
		err = PTR_ERR(vaddr);
		goto out_obj;
	}

	iov->vf.irq.obj = obj;
	iov->vf.irq.vaddr = vaddr;

	enable_vector = (u32*)(vaddr + I915_VF_IRQ_ENABLE);
	/*XXX: we should start with all irqs disabled: 0xffff0000 */
	*enable_vector = 0xffff;

	return 0;

out_obj:
	i915_gem_object_put(obj);
out:
	IOV_DEBUG(iov, "failed %d\n", err);
	return err;
}

static int vf_map_memirq_data(struct intel_iov *iov)
{
	struct intel_gt *gt = iov_to_gt(iov);
	struct i915_vma *vma;
	int err;

	GEM_BUG_ON(!intel_iov_is_vf(iov));
	GEM_BUG_ON(!iov->vf.irq.obj);

	vma = i915_vma_instance(iov->vf.irq.obj, &gt->ggtt->vm, NULL);
	if (IS_ERR(vma)) {
		err = PTR_ERR(vma);
		goto out;
	}

	err = i915_vma_pin(vma, 0, 0, PIN_GLOBAL);
	if (err)
		goto out_vma;

	iov->vf.irq.vma = vma;

	return 0;

out_vma:
	__i915_vma_put(vma);
out:
	IOV_DEBUG(iov, "failed %d\n", err);
	return err;
}

static void vf_release_memirq_data(struct intel_iov *iov)
{
	i915_vma_unpin_and_release(&iov->vf.irq.vma, I915_VMA_RELEASE_MAP);
	iov->vf.irq.obj = NULL;
	iov->vf.irq.vaddr = NULL;
}

/**
 * intel_iov_memirq_init - Initialize data used by memory based interrupts.
 * @iov: the IOV struct
 *
 * Allocate Interrupt Source Report page and Interrupt Status Report page
 * used by memory based interrupts.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_memirq_init(struct intel_iov *iov)
{
	int err;

	if (!HAS_MEMORY_IRQ_STATUS(iov_to_i915(iov)))
		return 0;

	err = vf_create_memirq_data(iov);
	if (unlikely(err))
		return err;

	err = vf_map_memirq_data(iov);
	if (unlikely(err))
		return err;

	return 0;
}

/**
 * intel_iov_irq_fini - Release data used by memory based interrupts.
 * @iov: the IOV struct
 *
 * Release data used by memory based interrupts.
 */
void intel_iov_memirq_fini(struct intel_iov *iov)
{
	if (!HAS_MEMORY_IRQ_STATUS(iov_to_i915(iov)))
		return;

	vf_release_memirq_data(iov);
}
