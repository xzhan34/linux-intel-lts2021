/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2020 Intel Corporation
 */

#ifndef INTEL_FLAT_PPGTT_POOL_TYPES_H
#define INTEL_FLAT_PPGTT_POOL_TYPES_H

#include <linux/list.h>
#include <linux/types.h>
#include <linux/wait.h>

#define INTEL_FLAT_PPGTT_MAX_PINNED_OBJS	1024
#define INTEL_FLAT_PPGTT_BB_OBJ_SIZE		SZ_8K
#define INTEL_FLAT_PPGTT_MAX_PTE_ENTRIES	((INTEL_FLAT_PPGTT_BB_OBJ_SIZE >> 5) - 2)

struct i915_address_space;
struct i915_vma;

struct intel_pte_bo {
	struct i915_vma *vma;
	struct list_head link;
	u32 *cmd;
};

struct intel_flat_ppgtt_pool {
	struct list_head free_list;
	wait_queue_head_t bind_wq;
};

#endif /* INTEL_FLAT_PPGTT_POOL_TYPES_H */
