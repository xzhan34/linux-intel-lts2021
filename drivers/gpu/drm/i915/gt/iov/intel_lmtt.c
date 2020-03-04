// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include "intel_lmtt.h"

#include "i915_drv.h"
#include "gt/intel_gt_mcr.h"
#include "gt/intel_gt_regs.h"
#include "gem/i915_gem_lmem.h"
#include "gem/i915_gem_region.h"

static struct intel_gt *lmtt_to_gt(struct intel_lmtt *lmtt)
{
	return container_of(lmtt, struct intel_gt, iov.pf.lmtt);
}

static struct intel_lmtt_pt *
lmtt_pt_alloc(struct intel_lmtt *lmtt, unsigned int level)
{
	resource_size_t pt_size = lmtt->ops->lmtt_pte_size(level) *
				  lmtt->ops->lmtt_pte_num(level);
	struct drm_i915_gem_object *obj;
	struct intel_lmtt_pt *pt;
	int err;

	pt = kzalloc(sizeof(*pt), GFP_KERNEL);
	if (!pt) {
		err = -ENOMEM;
		goto out;
	}

	if (level > 0) {
		pt->entry = kcalloc(lmtt->ops->lmtt_pte_num(level), sizeof(pt),
				    GFP_KERNEL);
		if (!pt->entry) {
			err = -ENOMEM;
			goto out_pt;
		}
	}

	obj = i915_gem_object_create_lmem(lmtt_to_gt(lmtt)->i915, pt_size,
					  I915_BO_ALLOC_CHUNK_64K |
					  I915_BO_ALLOC_CONTIGUOUS |
					  I915_BO_ALLOC_VOLATILE |
					  I915_BO_CPU_CLEAR);
	if (IS_ERR(obj)) {
		err = PTR_ERR(obj);
		goto out_entry;
	}

	err = i915_gem_object_pin_pages_unlocked(obj);
	if (unlikely(err))
		goto out_obj;

	pt->obj = obj;

	return pt;

out_obj:
	i915_gem_object_put(obj);
out_entry:
	kfree(pt->entry);
out_pt:
	kfree(pt);
out:
	return ERR_PTR(err);
}

static void
lmtt_pt_free(struct intel_lmtt_pt *pt)
{
	struct drm_i915_gem_object *obj;

	obj = fetch_and_zero(&pt->obj);
	i915_gem_object_unpin_pages(obj);
	i915_gem_object_put(obj);

	kfree(pt->entry);
	kfree(pt);
}

static void gt_set_lmtt_dir_ptr(struct intel_gt *gt, unsigned long offset)
{
	u32 lmem_cfg;

	/* in multiples of 64KB */
	GEM_BUG_ON(!IS_ALIGNED(offset, SZ_64K));
	lmem_cfg = REG_FIELD_PREP(LMTT_DIR_PTR, offset / SZ_64K) | LMEM_ENABLE;

	intel_gt_mcr_multicast_write(gt, XEHP_LMEM_CFG_ADDR, lmem_cfg);
}

static int lmtt_pd_init(struct intel_lmtt *lmtt)
{
	struct intel_lmtt_pt *pd;

	GEM_BUG_ON(lmtt->ops->lmtt_root_pd_level() == 0);
	GEM_BUG_ON(lmtt->pd);

	pd = lmtt_pt_alloc(lmtt, lmtt->ops->lmtt_root_pd_level());
	if (IS_ERR(pd))
		return PTR_ERR(pd);
	lmtt->pd = pd;

	return 0;
}

static void lmtt_pd_fini(struct intel_lmtt *lmtt)
{
	struct intel_lmtt_pt *pd;

	/* We may have never initialized if we got wedged on init */
	pd = fetch_and_zero(&lmtt->pd);
	if (pd)
		lmtt_pt_free(pd);
}

void intel_lmtt_init_hw(struct intel_lmtt *lmtt)
{
	struct intel_gt *gt = lmtt_to_gt(lmtt);

	if (!HAS_LMEM(gt->i915))
		return;

	if (!lmtt->pd)
		return;

	gt_set_lmtt_dir_ptr(gt, i915_gem_object_lmem_offset(lmtt->pd->obj));
}

/**
 * intel_lmtt_init - Initalize LMTT allocations.
 * @lmtt: the LMTT struct
 *
 * This function allocates empty LMTT Page Directory and
 * registers it for use by GT hardware.
 * This function shall be called only on PF.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_lmtt_init(struct intel_lmtt *lmtt)
{
	struct intel_gt *gt = lmtt_to_gt(lmtt);
	int err;

	if (!HAS_LMEM(gt->i915))
		return 0;

	lmtt->ops = &xehpsdv_lmtt_ops;

	err = lmtt_pd_init(lmtt);
	if (unlikely(err))
		return err;

	return 0;
}

/**
 * intel_lmtt_fini - Cleanup LMTT allocations.
 * @lmtt: the LMTT struct
 *
 * This function shall be called only on PF.
 */
void intel_lmtt_fini(struct intel_lmtt *lmtt)
{
	struct intel_gt *gt = lmtt_to_gt(lmtt);

	if (!HAS_LMEM(gt->i915))
		return;

	lmtt_pd_fini(lmtt);
}
