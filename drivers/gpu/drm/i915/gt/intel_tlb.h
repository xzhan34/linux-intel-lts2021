/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef INTEL_TLB_H
#define INTEL_TLB_H

struct intel_gt;

void intel_gt_invalidate_tlb_full(struct intel_gt *gt);

void intel_gt_init_tlb(struct intel_gt *gt);
void intel_gt_fini_tlb(struct intel_gt *gt);

#endif /* INTEL_TLB_H */
