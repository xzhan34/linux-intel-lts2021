// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include <linux/sizes.h>
#include <linux/types.h>

#include "intel_lmtt.h"
#include "i915_gem.h"

typedef u32 xehpsdv_lmtt_pde_t;
typedef u32 xehpsdv_lmtt_pte_t;

#define XEHPSDV_LMTT_PDE_MAX	64 /* PDE index 0 is unused */

#define XEHPSDV_LMTT_PTE_MAX	SZ_64K

static unsigned int xehpsdv_lmtt_root_pd_level(void)
{
	return 1;
}

static unsigned int xehpsdv_lmtt_pte_num(unsigned int level)
{
	switch (level) {
	case 1:
		return XEHPSDV_LMTT_PDE_MAX;
	case 0:
		return XEHPSDV_LMTT_PTE_MAX;
	default:
		MISSING_CASE(level);
		return 0;
	}
}

static resource_size_t xehpsdv_lmtt_pte_size(unsigned int level)
{
	switch (level) {
	case 1:
		return sizeof(xehpsdv_lmtt_pde_t);
	case 0:
		return sizeof(xehpsdv_lmtt_pte_t);
	default:
		MISSING_CASE(level);
		return 0;
	}
}

const struct intel_lmtt_ops xehpsdv_lmtt_ops = {
	.lmtt_root_pd_level = xehpsdv_lmtt_root_pd_level,
	.lmtt_pte_num = xehpsdv_lmtt_pte_num,
	.lmtt_pte_size = xehpsdv_lmtt_pte_size,
};
