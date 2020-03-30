// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef _GT_INTEL_PAGEFAULT_H
#define _GT_INTEL_PAGEFAULT_H

#include <linux/types.h>

struct drm_i915_gem_object;
struct intel_gt;
struct intel_guc;

void intel_gt_pagefault_process_cat_error_msg(struct intel_gt *gt, u32 guc_ctx_id);
int intel_gt_pagefault_process_page_fault_msg(struct intel_gt *gt, const u32 *msg, u32 len);
int intel_pagefault_req_process_msg(struct intel_guc *guc, const u32 *payload,
				    u32 len);
#endif /* _GT_INTEL_PAGEFAULT_H */

