// SPDX-License-Identifier: MIT
/*
 * Copyright © 2019 Intel Corporation
 */

#include "i915_drv.h"
#include "i915_pci.h"
#include "i915_reg.h"
#include "intel_memory_region.h"
#include "intel_pci_config.h"
#include "intel_region_lmem.h"
#include "gem/i915_gem_lmem.h"
#include "gem/i915_gem_region.h"
#include "gt/intel_gt.h"
#include "gt/intel_gt_mcr.h"
#include "gt/intel_gt_regs.h"

static void
region_lmem_release(struct intel_memory_region *mem)
{
	io_mapping_fini(&mem->iomap);
	intel_memory_region_release_buddy(mem);
}

static int
region_lmem_init(struct intel_memory_region *mem)
{
	int ret;

	if (!io_mapping_init_wc(&mem->iomap,
				mem->io_start,
				mem->io_size))
		return -EIO;

	ret = intel_memory_region_init_buddy(mem);
	if (ret)
		io_mapping_fini(&mem->iomap);

	return ret;
}

static const struct intel_memory_region_ops intel_region_lmem_ops = {
	.init = region_lmem_init,
	.release = region_lmem_release,
	.init_object = __i915_gem_lmem_object_init,
};

static bool get_legacy_lowmem_region(struct intel_uncore *uncore,
				     u64 *start, u32 *size)
{
	if (!IS_DG1(uncore->i915))
		return false;

	*start = 0;
	*size = SZ_1M;

	drm_dbg(&uncore->i915->drm, "LMEM: reserved legacy low-memory [0x%llx-0x%llx]\n",
		*start, *start + *size);

	return true;
}

static int reserve_lowmem_region(struct intel_uncore *uncore,
				 struct intel_memory_region *mem)
{
	u64 reserve_start;
	u32 reserve_size;
	int ret;

	if (!get_legacy_lowmem_region(uncore, &reserve_start, &reserve_size))
		return 0;

	ret = intel_memory_region_reserve(mem, reserve_start, reserve_size);
	if (ret)
		drm_err(&uncore->i915->drm, "LMEM: reserving low memory region failed\n");

	return ret;
}

static struct intel_memory_region *setup_lmem(struct intel_gt *gt)
{
	struct drm_i915_private *i915 = gt->i915;
	struct intel_uncore *uncore = gt->uncore;
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);
	struct intel_memory_region *mem;
	resource_size_t min_page_size;
	resource_size_t io_start;
	resource_size_t root_lmembar_size;
	u64 lmem_range, lmem_size, lmem_base = 0;
	static const i915_mcr_reg_t tile_addr_reg[] = {
		XEHP_TILE0_ADDR_RANGE,
		XEHP_TILE1_ADDR_RANGE,
		XEHP_TILE2_ADDR_RANGE,
		XEHP_TILE3_ADDR_RANGE,
	};
	u32 instance = gt->info.id;
	int err;

	if (!IS_DGFX(i915))
		return ERR_PTR(-ENODEV);

	if (!i915_pci_resource_valid(pdev, GEN12_LMEM_BAR))
		return ERR_PTR(-ENXIO);

	root_lmembar_size = pci_resource_len(pdev, GEN12_LMEM_BAR);

	if (i915->remote_tiles > 0) {
		/* We should take the size and range of the tiles from
		 * the tile range register intead of assigning the offsets
		 * manually. The tile ranges are divided into 1GB granularity
		 */
		lmem_range = intel_gt_mcr_read_any(gt, tile_addr_reg[instance]) & 0xFFFF;
		lmem_size = lmem_range >> XEHP_TILE_LMEM_RANGE_SHIFT;
		lmem_base = (lmem_range & 0xFF) >> XEHP_TILE_LMEM_BASE_SHIFT;

		lmem_size *= SZ_1G;
		lmem_base *= SZ_1G;
	} else {
		lmem_size = root_lmembar_size;
		/* base for tile0 always set below */
	}

	if (!lmem_size || lmem_base > root_lmembar_size)
		return ERR_PTR(-EIO);

	/* Leave space for per-tile WOPCM/GSM stolen memory at the LMEM roof.
	 * Applicable only to XEHPSDV/DG2 etc.
	 */

	if (HAS_FLAT_CCS(i915)) {
		resource_size_t lmem_range;
		u64 tile_stolen, flat_ccs_base_addr_reg, flat_ccs_base;

		lmem_range = intel_gt_mcr_read_any(&i915->gt0, XEHP_TILE0_ADDR_RANGE) & 0xFFFF;
		lmem_size = lmem_range >> XEHP_TILE_LMEM_RANGE_SHIFT;
		lmem_size *= SZ_1G;

		flat_ccs_base_addr_reg = intel_gt_mcr_read_any(gt, XEHP_FLAT_CCS_BASE_ADDR);
		flat_ccs_base = (flat_ccs_base_addr_reg >> XEHP_CCS_BASE_SHIFT) * SZ_64K;
		tile_stolen = lmem_size - flat_ccs_base;

		/* If the FLAT_CCS_BASE_ADDR register is not populated, flag an error */
		if (tile_stolen == lmem_size)
			drm_err(&i915->drm,
				"CCS_BASE_ADDR register did not have expected value\n");

		lmem_size -= tile_stolen;
	} else {
		/* Stolen starts from GSMBASE without CCS */
		lmem_size = intel_uncore_read64(&i915->uncore, GEN12_GSMBASE);
		if (GEM_WARN_ON(lmem_size > pci_resource_len(pdev, GEN12_LMEM_BAR)))
			return ERR_PTR(-ENODEV);

	}

	if (i915->params.lmem_size > 0) {
		lmem_size = min_t(resource_size_t, lmem_size,
				  mul_u32_u32(i915->params.lmem_size, SZ_1M));
	}

	io_start = pci_resource_start(pdev, GEN12_LMEM_BAR) + lmem_base;

	min_page_size = HAS_64K_PAGES(i915) ? I915_GTT_PAGE_SIZE_64K :
						I915_GTT_PAGE_SIZE_4K;
	mem = intel_memory_region_create(gt,
					 lmem_base,
					 lmem_size,
					 min_page_size,
					 io_start,
					 lmem_size,
					 INTEL_MEMORY_LOCAL,
					 0,
					 &intel_region_lmem_ops);
	if (IS_ERR(mem))
		return mem;

	err = reserve_lowmem_region(uncore, mem);
	if (err)
		goto err_region_put;

	drm_dbg(&i915->drm, "Local memory: %pR\n", &mem->region);
	drm_dbg(&i915->drm, "Local memory IO start: %pa\n",
		&mem->io_start);
	drm_info(&i915->drm, "Local memory IO size: %pa\n",
		 &mem->io_size);
	drm_info(&i915->drm, "Local memory available: %pa\n",
		 &lmem_size);

	return mem;

err_region_put:
	intel_memory_region_put(mem);
	return ERR_PTR(err);
}

struct intel_memory_region *intel_gt_setup_lmem(struct intel_gt *gt)
{
	return setup_lmem(gt);
}
