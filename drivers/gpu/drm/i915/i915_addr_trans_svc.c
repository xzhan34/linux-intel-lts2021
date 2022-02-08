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

bool is_vm_pasid_active(struct i915_address_space *vm)
{
	return (i915_ats_enabled(vm->i915) && vm->has_pasid);
}

void i915_enable_ats(struct drm_i915_private *i915)
{
	struct pci_dev *pdev = to_pci_dev(i915->drm.dev);
	int err = 0;

	if (!i915->params.address_translation_services)
		return;

	i915->pasid_counter = 0;
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
	WRITE_ONCE(i915->pasid_counter, 0);
	pci_disable_ats(pdev);
	clear_bit(INTEL_FLAG_ATS_ENABLED, &i915->flags);
}

/* PASID value contains 20-bit wide */
void i915_destroy_pasid(struct i915_address_space *vm)
{
	if (!i915_ats_enabled(vm->i915))
		return;

	if (vm->sva && is_vm_pasid_active(vm)) {
		WRITE_ONCE(vm->i915->pasid_counter, vm->i915->pasid_counter - 1);
		iommu_sva_unbind_device(vm->sva);
		vm->has_pasid = false;
		vm->sva = NULL;
	}
}

int i915_create_pasid(struct i915_address_space *vm)
{
	struct drm_i915_private *i915 = vm->i915;
	struct iommu_sva *sva_handle;
	int err;
	u32 pasid;

	if (!i915_ats_enabled(i915))
		return -EINVAL;

	sva_handle = iommu_sva_bind_device(vm->dma, current->mm, NULL);
	if (IS_ERR(sva_handle)) {
		err = PTR_ERR(sva_handle);
		drm_err(&i915->drm,
			"Binding address space to the device in order to use PASID failed with error %d\n",
			err);
		return err;
	}

	pasid = i915_get_pasid(sva_handle);
	if (pasid == IOMMU_PASID_INVALID) {
		drm_err(&i915->drm,
			"Invalid PASID created - need to unbind the device and disable ATS %d\n",
			pasid);
		return -EINVAL;
	}

	/* update address space sva and pasid */
	vm->sva = sva_handle;
	vm->pasid = pasid;
	vm->has_pasid = true;

	/* Update pasid global counter */
	WRITE_ONCE(vm->i915->pasid_counter, vm->i915->pasid_counter + 1);

	return 0;
}

int i915_global_pasid_counter(struct drm_i915_private *i915)
{
	return i915->pasid_counter;
}
