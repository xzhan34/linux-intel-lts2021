// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include "i915_drv.h"
#include "intel_gt_sysfs.h"
#include "sysfs_gt_errors.h"

struct ext_attr {
	struct device_attribute attr;
	unsigned long id;
};

static ssize_t sgunit_error_show(struct device *dev,
			     struct device_attribute *attr,
			     char *buf)
{
	struct ext_attr *ea = container_of(attr, struct ext_attr, attr);
	struct intel_gt *gt = kobj_to_gt(&dev->kobj);

	return sysfs_emit(buf, "%lu\n", gt->errors.sgunit[ea->id]);
}

static ssize_t soc_error_show(struct device *dev,
			      struct device_attribute *attr,
			      char *buf)
{
	struct ext_attr *ea = container_of(attr, struct ext_attr, attr);
	struct intel_gt *gt = kobj_to_gt(&dev->kobj);

	return sysfs_emit(buf, "%lu\n", xa_to_value(xa_load(&gt->errors.soc, ea->id)));
}

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

#define SGUNIT_SYSFS_ERROR_ATTR_RO(_name,  _id) \
	struct ext_attr dev_attr_##_name = \
	{ __ATTR(_name, 0444, sgunit_error_show, NULL), (_id)}

#define SOC_SYSFS_ERROR_ATTR_RO(_name,  _id) \
	struct ext_attr dev_attr_##_name = \
	{ __ATTR(_name, 0444, soc_error_show, NULL), (_id)}

#define GT_SYSFS_ERROR_ATTR_RO(_name,  _id) \
	struct ext_attr dev_attr_##_name = \
	{ __ATTR(_name, 0444, gt_error_show, NULL), (_id)}

static GT_SYSFS_ERROR_ATTR_RO(correctable_l3_sng, INTEL_GT_HW_ERROR_COR_L3_SNG);
static GT_SYSFS_ERROR_ATTR_RO(correctable_guc, INTEL_GT_HW_ERROR_COR_GUC);
static GT_SYSFS_ERROR_ATTR_RO(correctable_sampler, INTEL_GT_HW_ERROR_COR_SAMPLER);
static GT_SYSFS_ERROR_ATTR_RO(correctable_slm, INTEL_GT_HW_ERROR_COR_SLM);
static GT_SYSFS_ERROR_ATTR_RO(correctable_eu_ic, INTEL_GT_HW_ERROR_COR_EU_IC);
static GT_SYSFS_ERROR_ATTR_RO(correctable_eu_grf, INTEL_GT_HW_ERROR_COR_EU_GRF);
static GT_SYSFS_ERROR_ATTR_RO(fatal_array_bist, INTEL_GT_HW_ERROR_FAT_ARR_BIST);
static GT_SYSFS_ERROR_ATTR_RO(fatal_l3_double, INTEL_GT_HW_ERROR_FAT_L3_DOUB);
static GT_SYSFS_ERROR_ATTR_RO(fatal_l3_ecc_checker, INTEL_GT_HW_ERROR_FAT_L3_ECC_CHK);
static GT_SYSFS_ERROR_ATTR_RO(fatal_guc, INTEL_GT_HW_ERROR_FAT_GUC);
static GT_SYSFS_ERROR_ATTR_RO(fatal_idi_parity, INTEL_GT_HW_ERROR_FAT_IDI_PAR);
static GT_SYSFS_ERROR_ATTR_RO(fatal_sqidi, INTEL_GT_HW_ERROR_FAT_SQIDI);
static GT_SYSFS_ERROR_ATTR_RO(fatal_sampler, INTEL_GT_HW_ERROR_FAT_SAMPLER);
static GT_SYSFS_ERROR_ATTR_RO(fatal_slm, INTEL_GT_HW_ERROR_FAT_SLM);
static GT_SYSFS_ERROR_ATTR_RO(fatal_eu_ic, INTEL_GT_HW_ERROR_FAT_EU_IC);
static GT_SYSFS_ERROR_ATTR_RO(fatal_eu_grf, INTEL_GT_HW_ERROR_FAT_EU_GRF);
static SGUNIT_SYSFS_ERROR_ATTR_RO(sgunit_correctable, HARDWARE_ERROR_CORRECTABLE);
static SGUNIT_SYSFS_ERROR_ATTR_RO(sgunit_nonfatal, HARDWARE_ERROR_NONFATAL);
static SGUNIT_SYSFS_ERROR_ATTR_RO(sgunit_fatal, HARDWARE_ERROR_FATAL);
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_psf_csc_0, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_PSF_CSC_0));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_psf_csc_1, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_PSF_CSC_1));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_psf_csc_2, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_PSF_CSC_2));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_punit, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_PUNIT));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_mdfi_east, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_MDFI_EAST));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_mdfi_west, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_MDFI_WEST));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_mdfi_south, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_MDFI_SOUTH));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss0_0, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS0_0));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss0_1, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS0_1));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss0_2, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS0_2));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss0_3, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS0_3));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss1_0, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS1_0));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss1_1, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS1_1));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss1_2, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS1_2));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss1_3, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_LOCAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS1_3));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_fabric_ss1_4, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_FABRIC_SS1_4));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_0, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_0));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_1, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_1));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_2, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_2));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_3, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_3));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_4, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_4));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_5, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_5));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_6, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_6));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_7, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_7));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_8, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_8));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_9, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_9));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_10, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_10));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_11, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_11));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_12, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_12));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_13, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_13));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_14, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_14));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss0_15, SOC_ERR_INDEX(INTEL_GT_SOC_IEH0, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS0_15));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_0, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_0));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_1, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_1));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_2, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_2));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_3, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_3));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_4, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_4));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_5, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_5));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_6, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_6));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_7, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_7));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_8, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_8));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_9, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_9));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_10, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_10));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_11, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_11));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_12, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_12));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_13, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_13));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_14, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_14));
static SOC_SYSFS_ERROR_ATTR_RO(soc_fatal_hbm_ss1_15, SOC_ERR_INDEX(INTEL_GT_SOC_IEH1, INTEL_SOC_REG_GLOBAL, HARDWARE_ERROR_FATAL, SOC_HBM_SS1_15));

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
	&dev_attr_sgunit_correctable.attr.attr,
	&dev_attr_sgunit_nonfatal.attr.attr,
	&dev_attr_sgunit_fatal.attr.attr,
	NULL
};

static const struct attribute *soc_error_attrs[] = {
	&dev_attr_soc_fatal_psf_csc_0.attr.attr,
	&dev_attr_soc_fatal_psf_csc_1.attr.attr,
	&dev_attr_soc_fatal_psf_csc_2.attr.attr,
	&dev_attr_soc_fatal_punit.attr.attr,
	&dev_attr_soc_fatal_mdfi_east.attr.attr,
	&dev_attr_soc_fatal_mdfi_west.attr.attr,
	&dev_attr_soc_fatal_mdfi_south.attr.attr,
	&dev_attr_soc_fatal_fabric_ss0_0.attr.attr,
	&dev_attr_soc_fatal_fabric_ss0_1.attr.attr,
	&dev_attr_soc_fatal_fabric_ss0_2.attr.attr,
	&dev_attr_soc_fatal_fabric_ss0_3.attr.attr,
	&dev_attr_soc_fatal_fabric_ss1_0.attr.attr,
	&dev_attr_soc_fatal_fabric_ss1_1.attr.attr,
	&dev_attr_soc_fatal_fabric_ss1_2.attr.attr,
	&dev_attr_soc_fatal_fabric_ss1_3.attr.attr,
	&dev_attr_soc_fatal_fabric_ss1_4.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_0.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_1.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_2.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_3.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_4.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_5.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_6.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_7.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_8.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_9.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_10.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_11.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_12.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_13.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_14.attr.attr,
	&dev_attr_soc_fatal_hbm_ss0_15.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_0.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_1.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_2.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_3.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_4.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_5.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_6.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_7.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_8.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_9.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_10.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_11.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_12.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_13.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_14.attr.attr,
	&dev_attr_soc_fatal_hbm_ss1_15.attr.attr,
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

	if (IS_XEHPSDV(gt->i915) &&
	    sysfs_create_files(dir, soc_error_attrs))
		drm_warn(&gt->i915->drm, "Failed to create gt%u soc_error sysfs\n", gt->info.id);

	return;

err:
	drm_err(&gt->i915->drm,
		"Failed to create gt%u error_counter directory\n",
		gt->info.id);
	kobject_put(dir);
}
