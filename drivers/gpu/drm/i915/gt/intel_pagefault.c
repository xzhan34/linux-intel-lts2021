// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */
#include "i915_drv.h"
#include "i915_trace.h"

#include "intel_gt.h"
#include "intel_gt_regs.h"
#include "intel_pagefault.h"

int intel_gt_pagefault_process_cat_error_msg(struct intel_gt *gt, const u32 *msg, u32 len)
{
	struct drm_device *drm = &gt->i915->drm;
	char buf[11];
	u32 guc_ctx_id;

	if (len != GUC2HOST_NOTIFY_MEMORY_CAT_ERROR_MSG_LEN)
		return -EPROTO;

	if (FIELD_GET(GUC2HOST_NOTIFY_MEMORY_CAT_ERROR_MSG_0_MBZ, msg[0]) != 0)
		return -EPROTO;

	guc_ctx_id = FIELD_GET(GUC2HOST_NOTIFY_MEMORY_CAT_ERROR_MSG_1_CONTEXT_ID, msg[1]);

	if (guc_ctx_id != CAT_ERROR_INV_SW_CTX)
		snprintf(buf, sizeof(buf), "%#04x", guc_ctx_id);
	else
		snprintf(buf, sizeof(buf), "n/a");

	trace_intel_gt_cat_error(gt, buf);

	drm_err(drm, "GPU catastrophic memory error. GuC context: %s\n", buf);

	return 0;
}
