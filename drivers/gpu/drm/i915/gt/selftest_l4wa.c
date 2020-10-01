// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */

#include "i915_selftest.h"

int intel_gtt_l4wa_live_selftests(struct drm_i915_private *i915)
{
	static const struct i915_subtest tests[] = {
	};
	struct intel_gt *gt;
	unsigned int i;

	if (!i915_is_mem_wa_enabled(i915, I915_WA_USE_FLAT_PPGTT_UPDATE))
		return 0;

	if (!i915->bind_ctxt_ready) {
		drm_err(&i915->drm,
			"L4WA not enabled, bind_ctxt_ready? %s!\n",
			str_yes_no(i915->bind_ctxt_ready));
		return -EINVAL;
	}

	for_each_gt(gt, i915, i) {
		int err;

		if (!gt->lmem)
			continue;

		if (!gt->engine[BCS0]->bind_context) {
			drm_err(&i915->drm,
				"L4WA not setup on gt%d, no bind contexts!\n",
				gt->info.id);
			return -EINVAL;
		}

		if (intel_gt_is_wedged(gt))
			continue;

		err = intel_gt_live_subtests(tests, gt);
		if (err)
			return err;
	}

	return 0;
}
