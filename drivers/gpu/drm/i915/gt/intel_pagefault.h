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

struct recoverable_page_fault_info {
	u64 page_addr;
	u32 asid;
	u16 pdata;
	u8 vfid;
	u8 access_type;
	u8 fault_type;
	u8 fault_level;
	u8 engine_class;
	u8 engine_instance;
	u8 fault_unsuccessful;
};

const char *intel_pagefault_type2str(unsigned int type);

const char *intel_access_type2str(unsigned int type);

void intel_gt_pagefault_process_cat_error_msg(struct intel_gt *gt, u32 guc_ctx_id);
int intel_gt_pagefault_process_page_fault_msg(struct intel_gt *gt, const u32 *msg, u32 len);
int intel_pagefault_req_process_msg(struct intel_guc *guc, const u32 *payload,
				    u32 len);
#endif /* _GT_INTEL_PAGEFAULT_H */

