// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include "i915_drv.h"
#include "intel_gt_sysfs.h"
#include "sysfs_gt_errors.h"

struct ext_attr{
	struct device_attribute attr;
	unsigned long id;
};

static ssize_t gt_error_show(struct device *dev,
			     struct device_attribute *attr,
			     char *buf)
{
	struct ext_attr *ea = container_of(attr, struct ext_attr, attr);
	struct intel_gt *gt = kobj_to_gt(&dev->kobj);

	return sysfs_emit(buf, "%lu\n", gt->errors.hw[ea->id]);
}

static ssize_t engine_reset_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct intel_gt *gt = kobj_to_gt(&dev->kobj);

	return sysfs_emit(buf, "%u\n", atomic_read(&gt->reset.engines_reset_count));
}

static ssize_t eu_attention_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buf)
{
	struct intel_gt *gt = kobj_to_gt(&dev->kobj);

	return sysfs_emit(buf, "%u\n", atomic_read(&gt->reset.eu_attention_count));
}

#define SYSFS_ERROR_ATTR_RO(_name,  _id) \
	struct ext_attr dev_attr_##_name = \
	{ __ATTR(_name, 0444, gt_error_show, NULL), (_id) }

static SYSFS_ERROR_ATTR_RO(correctable_l3_sng, INTEL_GT_HW_ERROR_COR_L3_SNG);
static SYSFS_ERROR_ATTR_RO(correctable_guc, INTEL_GT_HW_ERROR_COR_GUC);
static SYSFS_ERROR_ATTR_RO(correctable_sampler, INTEL_GT_HW_ERROR_COR_SAMPLER);
static SYSFS_ERROR_ATTR_RO(correctable_slm, INTEL_GT_HW_ERROR_COR_SLM);
static SYSFS_ERROR_ATTR_RO(correctable_eu_ic, INTEL_GT_HW_ERROR_COR_EU_IC);
static SYSFS_ERROR_ATTR_RO(correctable_eu_grf, INTEL_GT_HW_ERROR_COR_EU_GRF);
static SYSFS_ERROR_ATTR_RO(fatal_array_bist, INTEL_GT_HW_ERROR_FAT_ARR_BIST);
static SYSFS_ERROR_ATTR_RO(fatal_l3_double, INTEL_GT_HW_ERROR_FAT_L3_DOUB);
static SYSFS_ERROR_ATTR_RO(fatal_l3_ecc_checker, INTEL_GT_HW_ERROR_FAT_L3_ECC_CHK);
static SYSFS_ERROR_ATTR_RO(fatal_guc, INTEL_GT_HW_ERROR_FAT_GUC);
static SYSFS_ERROR_ATTR_RO(fatal_idi_parity, INTEL_GT_HW_ERROR_FAT_IDI_PAR);
static SYSFS_ERROR_ATTR_RO(fatal_sqidi, INTEL_GT_HW_ERROR_FAT_SQIDI);
static SYSFS_ERROR_ATTR_RO(fatal_sampler, INTEL_GT_HW_ERROR_FAT_SAMPLER);
static SYSFS_ERROR_ATTR_RO(fatal_slm, INTEL_GT_HW_ERROR_FAT_SLM);
static SYSFS_ERROR_ATTR_RO(fatal_eu_ic, INTEL_GT_HW_ERROR_FAT_EU_IC);
static SYSFS_ERROR_ATTR_RO(fatal_eu_grf, INTEL_GT_HW_ERROR_FAT_EU_GRF);

static DEVICE_ATTR_RO(engine_reset);
static DEVICE_ATTR_RO(eu_attention);

static const struct attribute *gt_error_attrs[] = {
	&dev_attr_correctable_l3_sng.attr.attr,
	&dev_attr_correctable_guc.attr.attr,
	&dev_attr_correctable_sampler.attr.attr,
	&dev_attr_correctable_slm.attr.attr,
	&dev_attr_correctable_eu_ic.attr.attr,
	&dev_attr_correctable_eu_grf.attr.attr,
	&dev_attr_fatal_array_bist.attr.attr,
	&dev_attr_fatal_l3_double.attr.attr,
	&dev_attr_fatal_l3_ecc_checker.attr.attr,
	&dev_attr_fatal_guc.attr.attr,
	&dev_attr_fatal_idi_parity.attr.attr,
	&dev_attr_fatal_sqidi.attr.attr,
	&dev_attr_fatal_sampler.attr.attr,
	&dev_attr_fatal_slm.attr.attr,
	&dev_attr_fatal_eu_ic.attr.attr,
	&dev_attr_fatal_eu_grf.attr.attr,
	&dev_attr_engine_reset.attr,
	&dev_attr_eu_attention.attr,
	NULL
};

void intel_gt_sysfs_register_errors(struct intel_gt *gt, struct kobject *parent)
{
	struct kobject *dir;

	if (!IS_DGFX(gt->i915))
		return;

	dir = intel_gt_create_kobj(gt, parent, "error_counter");
	if (!dir)
		goto err;

	if (sysfs_create_files(dir, gt_error_attrs))
		drm_warn(&gt->i915->drm, "Failed to create gt%u gt_error sysfs\n", gt->info.id);

	return;

err:
	drm_err(&gt->i915->drm,
		"Failed to create gt%u error_counter directory\n",
		gt->info.id);
	kobject_put(dir);
}
