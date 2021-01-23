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

/*
 * Don't allow LMEM allocation for first few megabytes reserved for
 * per tile debug trace data. Make sure to maintain alignment by using
 * buddy_alloc_range.
 */
static bool get_tracedebug_region(struct intel_uncore *uncore,
				  u64 *start, u32 *size)
{
	/* TODO: bspec says this is for XEHPSDV debug only */
	if (!IS_XEHPSDV(uncore->i915))
		return false;

	*size = intel_uncore_read(uncore, XEHP_DBGTRACEMEM_SZ);
	if (!*size)
		return false;

	if (WARN_ON(*size > 255))
		*size = 255;

	*size *= SZ_1M;
	*start = intel_uncore_read64_2x32(uncore,
					  XEHP_DBGTRACEMEMBASE_LDW,
					  XEHP_DBGTRACEMEMBASE_UDW);

	DRM_DEBUG_DRIVER("LMEM: debug trace data region: [0x%llx-0x%llx]\n",
			 *start, *start + *size);

	return true;
}

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
	u64 reserve_size = 0;
	u64 region_start;
	u32 region_size;
	int ret;

	if (get_legacy_lowmem_region(uncore, &region_start, &region_size)) {
		reserve_start = region_start;
		reserve_size = region_size;
	}

	if (get_tracedebug_region(uncore, &region_start, &region_size)) {
		reserve_start = 0;
		reserve_size = region_size;
	}

	if (!reserve_size)
		return 0;

	ret = intel_memory_region_reserve(mem, reserve_start, reserve_size);
	if (ret)
		drm_err(&uncore->i915->drm, "LMEM: reserving low memory region failed\n");

	return ret;
}

static inline bool lmembar_is_igpu_stolen(struct drm_i915_private *i915)
{
	u32 regions = INTEL_INFO(i915)->memory_regions;

	if (regions & REGION_LMEM)
		return false;

	drm_WARN_ON(&i915->drm, (regions & REGION_STOLEN_LMEM) == 0);

	return true;
}

int intel_get_tile_range(struct intel_gt *gt,
			 resource_size_t *lmem_base,
			 resource_size_t *lmem_size)
{
	struct drm_i915_private *i915 = gt->i915;
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);
	resource_size_t root_lmembar_size;
	resource_size_t lmem_range;
	static const i915_mcr_reg_t tile_addr_reg[] = {
		XEHP_TILE0_ADDR_RANGE,
		XEHP_TILE1_ADDR_RANGE,
		XEHP_TILE2_ADDR_RANGE,
		XEHP_TILE3_ADDR_RANGE,
	};
	u32 instance = gt->info.id;

	if (!i915_pci_resource_valid(pdev, GEN12_LMEM_BAR))
		return -ENXIO;

	root_lmembar_size = pci_resource_len(pdev, GEN12_LMEM_BAR);

	/*
	 * XEHPSDV A step single tile doesn't support the tile range
	 * registers.
	 * https://gfxspecs.intel.com/Predator/Home/Index/43880
	 */
	if (!lmembar_is_igpu_stolen(i915) && !IS_DG1(i915) &&
	    !(IS_XEHPSDV_GRAPHICS_STEP(i915, STEP_A0, STEP_B0) &&
	      !i915->remote_tiles)) {
		/* We should take the size and range of the tiles from
		 * the tile range register intead of assigning the offsets
		 * manually. The tile ranges are divided into 1GB granularity
		 */
		lmem_range = intel_gt_mcr_read_any(gt, tile_addr_reg[instance]) & 0xFFFF;
		*lmem_size = lmem_range >> XEHP_TILE_LMEM_RANGE_SHIFT;
		*lmem_base = (lmem_range & 0xFF) >> XEHP_TILE_LMEM_BASE_SHIFT;

		*lmem_size *= SZ_1G;
		*lmem_base *= SZ_1G;
	} else {
		*lmem_size = root_lmembar_size;
		*lmem_base = 0;
	}

	if (!*lmem_size || *lmem_base > root_lmembar_size)
		return -EIO;

	return 0;
}

static struct intel_memory_region *setup_lmem(struct intel_gt *gt)
{
	struct drm_i915_private *i915 = gt->i915;
	struct intel_uncore *uncore = gt->uncore;
	struct intel_mem_sparing_event *sparing;
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);
	struct intel_memory_region *mem;
	resource_size_t min_page_size;
	resource_size_t io_start;
	resource_size_t lmem_size, lmem_base;
	resource_size_t root_lmembar_size;
	bool is_degraded = false;
	int err;

	if (!IS_DGFX(i915))
		return ERR_PTR(-ENODEV);

	if (!i915_pci_resource_valid(pdev, GEN12_LMEM_BAR))
		return ERR_PTR(-ENXIO);

	root_lmembar_size = pci_resource_len(pdev, GEN12_LMEM_BAR);

	sparing = &to_gt(i915)->mem_sparing;

	/* Get per tile memory range */
	err = intel_get_tile_range(gt, &lmem_base, &lmem_size);
	if (err)
		return ERR_PTR(err);

	/* Leave space for per-tile WOPCM/GSM stolen memory at the LMEM roof.
	 * Applicable only to XEHPSDV/DG2 etc.
	 */

	if (HAS_FLAT_CCS(i915)) {
		u64 tile_stolen, flat_ccs_base_addr_reg, flat_ccs_base;
		u64 actual_flat_ccs_size, expected_flat_ccs_size, bgsm;

		bgsm = intel_uncore_read64(uncore, GEN12_GSMBASE);
		flat_ccs_base_addr_reg = intel_gt_mcr_read_any_fw(gt, XEHP_FLAT_CCS_BASE_ADDR);
		flat_ccs_base = (flat_ccs_base_addr_reg >> XEHP_CCS_BASE_SHIFT) * SZ_64K;

		/* CCS to LMEM size ratio is 1:256 */
		expected_flat_ccs_size = lmem_size / 256;
		actual_flat_ccs_size = bgsm - flat_ccs_base;
		tile_stolen = lmem_size - (flat_ccs_base - lmem_base);

		/* If the FLAT_CCS_BASE_ADDR register is not populated, flag an error */
		if (tile_stolen == lmem_size)
			drm_err(&i915->drm,
				"CCS_BASE_ADDR register did not have expected value\n");
		/*
		 * If the actual flat ccs size is greater than the expected
		 * value, then there is memory degradation
		 */
		if (actual_flat_ccs_size > expected_flat_ccs_size &&
		    to_gt(i915)->info.id == 0) {
			drm_err(&i915->drm, "CCS_BASE_ADDR register did not have expected value - and memory degradation might have occurred\n");
			is_degraded = true;
		}

		lmem_size -= tile_stolen;
	} else {
		/* Stolen starts from GSMBASE without CCS */
		lmem_size = intel_uncore_read64(uncore, GEN12_GSMBASE) - lmem_base;

	}

	/*
	 * We do want to continue with the driver load if the BAR size is smaller than
	 * memory fitted on the device. Fail on multi tile devices as BAR size might
	 * not be sufficient to map all the tiles.
	 */
	if (GEM_WARN_ON(lmem_size > root_lmembar_size || lmem_base > root_lmembar_size)) {
		if (i915->remote_tiles) {
			return ERR_PTR(-EIO);
		} else {
			drm_warn(&i915->drm, "Cannot use the full memory %pa on the device as LMEM BAR size was found to be smaller\n", &lmem_size);
			lmem_size = min(lmem_size, root_lmembar_size);
			drm_warn(&i915->drm, "Continuing with reduced LMEM size: %pa\n", &lmem_size);
		}
 	}
 
	if (i915->params.lmem_size > 0) {
		lmem_size = min_t(resource_size_t, lmem_size,
				  mul_u32_u32(i915->params.lmem_size, SZ_1M));
	}

	if (GEM_WARN_ON(lmem_size > pci_resource_len(pdev, GEN12_LMEM_BAR)))
		return ERR_PTR(-ENODEV);

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

	/* Report memory health status on the root tile */
	if (to_gt(i915)->info.id == 0) {
		if (is_degraded)
			sparing->health_status = MEM_HEALTH_DEGRADED;
		else
			sparing->health_status = MEM_HEALTH_OKAY;
	}

	return mem;

err_region_put:
	intel_memory_region_put(mem);
	return ERR_PTR(err);
}

struct intel_memory_region *intel_gt_setup_lmem(struct intel_gt *gt)
{
	return setup_lmem(gt);
}
