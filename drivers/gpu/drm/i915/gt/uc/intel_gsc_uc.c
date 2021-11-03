// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */

#include <linux/types.h>

#include "gt/intel_gt.h"
#include "intel_gsc_uc.h"
#include "i915_drv.h"

static bool gsc_engine_supported(struct intel_gt *gt)
{
	return gt->info.engine_mask ?
		HAS_ENGINE(gt, GSC0) :
		INTEL_INFO(gt->i915)->platform_engine_mask & BIT(GSC0);
}

void intel_gsc_uc_init_early(struct intel_gsc_uc *gsc)
{
	intel_uc_fw_init_early(&gsc->fw, INTEL_UC_FW_TYPE_GSC);

	/* we can arrive here from i915_driver_early_probe for primary
	 * GT with it being not fully setup hence check device info's
	 * engine mask
	 */
	if (!gsc_engine_supported(gsc_uc_to_gt(gsc))){
		intel_uc_fw_change_status(&gsc->fw, INTEL_UC_FIRMWARE_NOT_SUPPORTED);
		return;
	}
}

int intel_gsc_uc_init(struct intel_gsc_uc *gsc)
{
	struct drm_i915_private *i915 = gsc_uc_to_gt(gsc)->i915;
	int err;

	err = intel_uc_fw_init(&gsc->fw);
	if (err)
		goto out;

	intel_uc_fw_change_status(&gsc->fw, INTEL_UC_FIRMWARE_LOADABLE);

	return 0;

out:
	i915_probe_error(i915, "failed with %d\n", err);
	return err;
}

void intel_gsc_uc_fini(struct intel_gsc_uc *gsc)
{
	if (!intel_uc_fw_is_loadable(&gsc->fw))
		return;

	intel_uc_fw_fini(&gsc->fw);
}
