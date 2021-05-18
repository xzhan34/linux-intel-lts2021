// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include <linux/mm_types.h>
#include <linux/sched/mm.h>

#include "i915_drv.h"
#include "intel_memory_region.h"
#include "gem/i915_gem_context.h"

bool i915_ats_enabled(struct drm_i915_private *dev_priv)
{
	return test_bit(INTEL_FLAG_ATS_ENABLED, &dev_priv->flags);
}

void i915_enable_ats(struct drm_i915_private *i915)
{
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);
	int err = 0;

	if (!i915->params.address_translation_services)
		return;

	if (!pci_ats_supported(pdev)) {
		drm_info(&i915->drm,
			 "There is no Address Translation Services (ATS) support for the device\n");
		return;
	}

	err = iommu_dev_enable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA);
	if (err) {
		/*
		 * FIXME: Update the error check routine when the code in the
		 * Kernel that returns EINVAL due to lack of PRI support get
		 * updated - for now, we just log it and continue, without
		 * returning error
		 */
		drm_info(&i915->drm,
			 "Failed to enable SVA feature on the device - KMD will handle\n"
			 "faulting, no functional impact on the device - error: %pe\n",
			 ERR_PTR(err));
	}

	drm_info(&i915->drm,
		 "Succeeded in enabling SVA for Address Translation Services (ATS) support\n");

	/* Set ATS enabled flag with IOMMU successfully configured */
	set_bit(INTEL_FLAG_ATS_ENABLED, &i915->flags);
}

void i915_disable_ats(struct drm_i915_private *i915)
{
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);

	if (!i915_ats_enabled(i915))
		return;

	/*
	 * FIXME: disable/detach PASID associated with vm->id?
	 *
	 * Since call to enable SVA feature is failing due to the lack of PRI
	 * or PRS support, we don't need to disable SVA feature for now - So,
	 * we need to call the following function after final resolution in the
	 * kernel - "iommu_dev_disable_feature(&pdev->dev, IOMMU_DEV_FEAT_SVA)"
	 */
	pci_disable_ats(pdev);
	clear_bit(INTEL_FLAG_ATS_ENABLED, &i915->flags);
}
