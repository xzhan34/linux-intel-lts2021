// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */

#include "gt/intel_gt.h"

#include "i915_selftest.h"

int i915_debugger_live_selftests(struct drm_i915_private *i915)
{
	static const struct i915_subtest tests[] = {
	};

	if (!i915_modparams.debug_eu)
		return 0;

	if (intel_gt_is_wedged(to_gt(i915)))
		return 0;

	return i915_subtests(tests, i915);
}
