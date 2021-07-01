// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "i915_sriov.h"
#include "i915_drv.h"
#include "i915_pci.h"
#include "intel_pci_config.h"

/* safe for use before register access via uncore is completed */
static u32 pci_peek_mmio_read32(struct pci_dev *pdev, i915_reg_t reg)
{
	unsigned long offset = i915_mmio_reg_offset(reg);
	void __iomem *addr;
	u32 value;

	addr = pci_iomap_range(pdev, 0, offset, sizeof(u32));
	if (WARN(!addr, "Failed to map MMIO at %#lx\n", offset))
		return 0;

	value = readl(addr);
	pci_iounmap(pdev, addr);

	return value;
}

static bool gen12_pci_capability_is_vf(struct pci_dev *pdev)
{
	u32 value = pci_peek_mmio_read32(pdev, GEN12_VF_CAP_REG);

	/*
	 * Bugs in PCI programming (or failing hardware) can occasionally cause
	 * lost access to the MMIO BAR.  When this happens, register reads will
	 * come back with 0xFFFFFFFF for every register, including VF_CAP, and
	 * then we may wrongly claim that we are running on the VF device.
	 * Since VF_CAP has only one bit valid, make sure no other bits are set.
	 */
	if (WARN(value & ~GEN12_VF, "MMIO BAR malfunction, %#x returned %#x\n",
		 i915_mmio_reg_offset(GEN12_VF_CAP_REG), value))
		return false;

	return value & GEN12_VF;
}

#ifdef CONFIG_PCI_IOV

static int pf_reduce_totalvfs(struct drm_i915_private *i915, int limit)
{
	int err;

	err = pci_sriov_set_totalvfs(to_pci_dev(i915->drm.dev), limit);
	drm_WARN(&i915->drm, err, "Failed to set number of VFs to %d (%pe)\n",
		 limit, ERR_PTR(err));
	return err;
}

static bool pf_has_valid_vf_bars(struct drm_i915_private *i915)
{
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);

	if (!i915_pci_resource_valid(pdev, GEN12_VF_GTTMMADR_BAR))
		return false;

	if (HAS_LMEM(i915) && !i915_pci_resource_valid(pdev, GEN12_VF_LMEM_BAR))
		return false;

	return true;
}

static bool pf_continue_as_native(struct drm_i915_private *i915, const char *why)
{
#if IS_ENABLED(CONFIG_DRM_I915_DEBUG_GEM)
	drm_dbg(&i915->drm, "PF: %s, continuing as native\n", why);
#endif
	pf_reduce_totalvfs(i915, 0);
	return false;
}

static bool pf_verify_readiness(struct drm_i915_private *i915)
{
	if (!pf_has_valid_vf_bars(i915))
		return pf_continue_as_native(i915, "VFs BAR not ready");

	return true;
}

#endif

/**
 * i915_sriov_probe - Probe I/O Virtualization mode.
 * @i915: the i915 struct
 *
 * This function should be called once and as soon as possible during
 * driver probe to detect whether we are driving a PF or a VF device.
 * SR-IOV PF mode detection is based on PCI @dev_is_pf() function.
 * SR-IOV VF mode detection is based on MMIO register read.
 */
enum i915_iov_mode i915_sriov_probe(struct drm_i915_private *i915)
{
	struct device *dev = i915->drm.dev;
	struct pci_dev *pdev = to_pci_dev(dev);

	if (!HAS_SRIOV(i915))
		return I915_IOV_MODE_NONE;

	if (gen12_pci_capability_is_vf(pdev))
		return I915_IOV_MODE_SRIOV_VF;

#ifdef CONFIG_PCI_IOV
	if (dev_is_pf(dev) && pf_verify_readiness(i915))
		return I915_IOV_MODE_SRIOV_PF;
#endif

	return I915_IOV_MODE_NONE;
}
