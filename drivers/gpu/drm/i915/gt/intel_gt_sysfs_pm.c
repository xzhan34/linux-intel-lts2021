// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include <drm/drm_device.h>
#include <linux/sysfs.h>
#include <linux/printk.h>

#include "i915_drv.h"
#include "intel_gt.h"
#include "intel_gt_regs.h"
#include "intel_rc6.h"
#include "intel_rps.h"
#include "intel_gt_sysfs.h"
#include "intel_gt_sysfs_pm.h"

#ifdef CONFIG_PM
static u32 get_residency(struct intel_gt *gt, i915_reg_t reg)
{
	intel_wakeref_t wakeref;
	u64 res = 0;

	with_intel_runtime_pm(gt->uncore->rpm, wakeref)
		res = intel_rc6_residency_us(&gt->rc6, reg);

	return DIV_ROUND_CLOSEST_ULL(res, 1000);
}

static ssize_t rc6_enable_store(struct device *dev,
				struct device_attribute *attr,
				const char *buff, size_t count)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	intel_wakeref_t wakeref;
	ssize_t ret;
	u32 val;

	ret = kstrtou32(buff, 0, &val);
	if (ret)
		return ret;

	wakeref = intel_runtime_pm_get(gt->uncore->rpm);

	if (val) {
		if (gt->rc6.enabled)
			goto unlock;

		if (!gt->rc6.wakeref)
			intel_rc6_rpm_get(&gt->rc6);

		intel_rc6_enable(&gt->rc6);
		intel_rc6_unpark(&gt->rc6);
	} else {
		intel_rc6_disable(&gt->rc6);

		if (gt->rc6.wakeref)
			intel_rc6_rpm_put(&gt->rc6);
	}

unlock:
	intel_runtime_pm_put(gt->uncore->rpm, wakeref);

	return count;
}

static ssize_t rc6_enable_show(struct device *dev,
			       struct device_attribute *attr,
			       char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);

	return scnprintf(buff, PAGE_SIZE, "%d\n", gt->rc6.enabled);
}

static ssize_t rc6_residency_ms_show(struct device *dev,
				     struct device_attribute *attr,
				     char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 rc6_residency = get_residency(gt, GEN6_GT_GFX_RC6);

	return scnprintf(buff, PAGE_SIZE, "%u\n", rc6_residency);
}

static ssize_t rc6p_residency_ms_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 rc6p_residency = get_residency(gt, GEN6_GT_GFX_RC6p);

	return scnprintf(buff, PAGE_SIZE, "%u\n", rc6p_residency);
}

static ssize_t rc6pp_residency_ms_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 rc6pp_residency = get_residency(gt, GEN6_GT_GFX_RC6pp);

	return scnprintf(buff, PAGE_SIZE, "%u\n", rc6pp_residency);
}

static ssize_t media_rc6_residency_ms_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 rc6_residency = get_residency(gt, VLV_GT_MEDIA_RC6);

	return scnprintf(buff, PAGE_SIZE, "%u\n", rc6_residency);
}

/* sysfs dual-location rc6 files under directories <dev>/power/ and <dev>/gt/gt<i>/ */

static DEVICE_ATTR_RW(rc6_enable);
static DEVICE_ATTR_RO(rc6_residency_ms);
static DEVICE_ATTR_RO(rc6p_residency_ms);
static DEVICE_ATTR_RO(rc6pp_residency_ms);
static DEVICE_ATTR_RO(media_rc6_residency_ms);

static struct attribute *rc6_attrs[] = {
	&dev_attr_rc6_enable.attr,
	&dev_attr_rc6_residency_ms.attr,
	NULL
};

static struct attribute *rc6p_attrs[] = {
	&dev_attr_rc6p_residency_ms.attr,
	&dev_attr_rc6pp_residency_ms.attr,
	NULL
};

static struct attribute *media_rc6_attrs[] = {
	&dev_attr_media_rc6_residency_ms.attr,
	NULL
};

static const struct attribute_group rc6_attr_group[] = {
	{ .name = power_group_name, .attrs = rc6_attrs },
	{ .attrs = rc6_attrs }
};

static const struct attribute_group rc6p_attr_group[] = {
	{ .name = power_group_name, .attrs = rc6p_attrs },
	{ .attrs = rc6p_attrs }
};

static const struct attribute_group media_rc6_attr_group[] = {
	{ .name = power_group_name, .attrs = media_rc6_attrs },
	{ .attrs = media_rc6_attrs }
};

static int __intel_gt_sysfs_create_group(struct kobject *kobj,
					 const struct attribute_group *grp)
{
	/* is_object_gt() returns 0 if parent device or 1 if gt/gt<i>. */
	int i = is_object_gt(kobj);

	/*
	 * For gt/gt<i>, sysfs_create_group() from grp[1] - group name = "".
	 * For <parent>, sysfs_merge_group()  from grp[0] - group name = "power"
	 * which must already exist.
	 */
	return i ? sysfs_create_group(kobj, &grp[i]) :
		   sysfs_merge_group(kobj, &grp[i]);
}

/*
 * intel_sysfs_rc6_init()
 * @gt: The gt being processed.
 * @kobj: The kobj in sysfs to which created files will be attached.
 *
 * Called unconditionally from intel_gt_sysfs_pm_init:
 * - Once with kobj specifying directory of parent_device (and gt specifying gt0).
 *   Places files under <dev>/power
 * - Once per gt, with kobj specifying directory gt/gt<i>
 *   Places files under <dev>/gt/gt<i>.
 */
static void intel_sysfs_rc6_init(struct intel_gt *gt, struct kobject *kobj)
{
	int ret;

	if (!HAS_RC6(gt->i915))
		return;

	ret = __intel_gt_sysfs_create_group(kobj, rc6_attr_group);
	if (ret)
		drm_err(&gt->i915->drm,
			"failed to create gt%u RC6 sysfs files\n", gt->info.id);

	if (HAS_RC6p(gt->i915)) {
		ret = __intel_gt_sysfs_create_group(kobj, rc6p_attr_group);
		if (ret)
			drm_err(&gt->i915->drm,
				"failed to create gt%u RC6p sysfs files\n",
				gt->info.id);
	}

	if (IS_VALLEYVIEW(gt->i915) || IS_CHERRYVIEW(gt->i915)) {
		ret = __intel_gt_sysfs_create_group(kobj, media_rc6_attr_group);
		if (ret)
			drm_err(&gt->i915->drm,
				"failed to create media %u RC6 sysfs files\n",
				gt->info.id);
	}
}
#else
static void intel_sysfs_rc6_init(struct intel_gt *gt, struct kobject *kobj)
{
}
#endif /* CONFIG_PM */

static ssize_t vlv_rpe_freq_mhz_show(struct device *dev,
				     struct device_attribute *attr, char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;

	return scnprintf(buff, PAGE_SIZE, "%d\n",
			intel_gpu_freq(rps, rps->efficient_freq));
}

static ssize_t act_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);

	return scnprintf(buff, PAGE_SIZE, "%d\n",
			intel_rps_read_actual_frequency(&gt->rps));
}

static ssize_t cur_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr, char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;

	return scnprintf(buff, PAGE_SIZE, "%d\n",
				intel_rps_get_requested_frequency(rps));
}

static ssize_t boost_freq_mhz_show(struct device *dev,
				   struct device_attribute *attr,
				   char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;

	return scnprintf(buff, PAGE_SIZE, "%d\n",
			intel_rps_get_boost_frequency(rps));
}

static ssize_t boost_freq_mhz_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buff, size_t count)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;
	ssize_t ret;
	u32 val;

	ret = kstrtou32(buff, 0, &val);
	if (ret)
		return ret;

	ret = intel_rps_set_boost_frequency(rps, val);

	return ret ?: count;
}

static ssize_t max_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;

	return scnprintf(buff, PAGE_SIZE, "%d\n", intel_rps_get_max_frequency(rps));
}

static ssize_t max_freq_mhz_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buff, size_t count)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;
	ssize_t ret;
	u32 val;

	ret = kstrtou32(buff, 0, &val);
	if (ret)
		return ret;

	ret = intel_rps_set_max_frequency(rps, val);

	return ret ?: count;
}

static ssize_t min_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;

	return scnprintf(buff, PAGE_SIZE, "%d\n",
			intel_rps_get_min_frequency(rps));
}

static ssize_t min_freq_mhz_store(struct device *dev,
				  struct device_attribute *attr,
				  const char *buff, size_t count)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;
	ssize_t ret;
	u32 val;

	ret = kstrtou32(buff, 0, &val);
	if (ret)
		return ret;

	ret = intel_rps_set_min_frequency(rps, val);

	return ret ?: count;
}

static ssize_t RP0_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;
	struct intel_guc_slpc *slpc = &gt->uc.guc.slpc;
	u32 val;

	if (intel_uc_uses_guc_slpc(&gt->uc))
		val = slpc->rp0_freq;
	else
		val = intel_gpu_freq(rps, rps->rp0_freq);

	return scnprintf(buff, PAGE_SIZE, "%d\n", val);
}

static ssize_t RP1_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;
	struct intel_guc_slpc *slpc = &gt->uc.guc.slpc;
	u32 val;

	if (intel_uc_uses_guc_slpc(&gt->uc))
		val = slpc->rp1_freq;
	else
		val = intel_gpu_freq(rps, rps->rp1_freq);

	return scnprintf(buff, PAGE_SIZE, "%d\n", val);
}

static ssize_t RPn_freq_mhz_show(struct device *dev,
				 struct device_attribute *attr,
				 char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	struct intel_rps *rps = &gt->rps;
	struct intel_guc_slpc *slpc = &gt->uc.guc.slpc;
	u32 val;

	if (intel_uc_uses_guc_slpc(&gt->uc))
		val = slpc->min_freq;
	else
		val = intel_gpu_freq(rps, rps->min_freq);

	return scnprintf(buff, PAGE_SIZE, "%d\n", val);
}

/* sysfs dual-location files <dev>/vlv_rpe_freq_mhz and <dev>/gt/gt0/vlv_rpe_freq_mhz */
static DEVICE_ATTR_RO(vlv_rpe_freq_mhz);

/* sysfs dual-location files <dev>/gt_* and <dev>/gt/gt<i>/rps_* */

#define INTEL_GT_RPS_SYSFS_ATTR(_name, __mode, __show, __store) \
	static struct device_attribute dev_attr_gt_##_name =    \
		__ATTR(gt_##_name, __mode, __show, __store);    \
	static struct device_attribute dev_attr_rps_##_name =   \
		__ATTR(rps_##_name, __mode, __show, __store)

/* Note: rps_ and gt_ share common show and store functions. */
#define INTEL_GT_RPS_SYSFS_ATTR_RO(_name)				\
		INTEL_GT_RPS_SYSFS_ATTR(_name, 0444, _name##_show, NULL)
#define INTEL_GT_RPS_SYSFS_ATTR_RW(_name)				\
		INTEL_GT_RPS_SYSFS_ATTR(_name, 0644, _name##_show, _name##_store)

INTEL_GT_RPS_SYSFS_ATTR_RO(act_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RO(cur_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RW(boost_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RW(max_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RW(min_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RO(RP0_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RO(RP1_freq_mhz);
INTEL_GT_RPS_SYSFS_ATTR_RO(RPn_freq_mhz);

#define GEN6_ATTR(s) { \
		&dev_attr_##s##_act_freq_mhz.attr, \
		&dev_attr_##s##_cur_freq_mhz.attr, \
		&dev_attr_##s##_boost_freq_mhz.attr, \
		&dev_attr_##s##_max_freq_mhz.attr, \
		&dev_attr_##s##_min_freq_mhz.attr, \
		&dev_attr_##s##_RP0_freq_mhz.attr, \
		&dev_attr_##s##_RP1_freq_mhz.attr, \
		&dev_attr_##s##_RPn_freq_mhz.attr, \
		NULL, \
	}

/* sysfs files <dev>/gt_* */
static const struct attribute * const gen6_rps_attrs[] = GEN6_ATTR(rps);

/* sysfs files <dev>/gt/gt<i>/rps_* */
static const struct attribute * const gen6_gt_attrs[]  = GEN6_ATTR(gt);

static ssize_t rapl_PL1_freq_mhz_show(struct device *dev,
				      struct device_attribute *attr,
				      char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 rapl_pl1 = intel_rps_read_rapl_pl1_frequency(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%d\n", rapl_pl1);
}

static ssize_t punit_req_freq_mhz_show(struct device *dev,
				       struct device_attribute *attr,
				       char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	u32 swreq = intel_rps_get_requested_frequency(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%d\n", swreq);
}

static ssize_t throttle_reason_status_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool status = !!intel_rps_read_throttle_reason_status(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", status);
}

static ssize_t throttle_reason_pl1_show(struct device *dev,
					struct device_attribute *attr,
					char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool pl1 = !!intel_rps_read_throttle_reason_pl1(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", pl1);
}

static ssize_t throttle_reason_pl2_show(struct device *dev,
					struct device_attribute *attr,
					char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool pl2 = !!intel_rps_read_throttle_reason_pl2(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", pl2);
}

static ssize_t throttle_reason_pl4_show(struct device *dev,
					struct device_attribute *attr,
					char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool pl4 = !!intel_rps_read_throttle_reason_pl4(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", pl4);
}

static ssize_t throttle_reason_thermal_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool thermal = !!intel_rps_read_throttle_reason_thermal(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", thermal);
}

static ssize_t throttle_reason_prochot_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool prochot = !!intel_rps_read_throttle_reason_prochot(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", prochot);
}

static ssize_t throttle_reason_ratl_show(struct device *dev,
					 struct device_attribute *attr,
					 char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool ratl = !!intel_rps_read_throttle_reason_ratl(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", ratl);
}

static ssize_t throttle_reason_vr_thermalert_show(struct device *dev,
						  struct device_attribute *attr,
						  char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool thermalert = !!intel_rps_read_throttle_reason_vr_thermalert(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", thermalert);
}

static ssize_t throttle_reason_vr_tdc_show(struct device *dev,
					   struct device_attribute *attr,
					   char *buff)
{
	struct intel_gt *gt = intel_gt_sysfs_get_drvdata(dev, attr->attr.name);
	bool tdc = !!intel_rps_read_throttle_reason_vr_tdc(&gt->rps);

	return scnprintf(buff, PAGE_SIZE, "%u\n", tdc);
}

/* dgfx sysfs files under directory <dev>/gt/gt<i>/ */
static DEVICE_ATTR_RO(rapl_PL1_freq_mhz);

/* gen12+ sysfs files under directory <dev>/gt/gt<i>/ */

static DEVICE_ATTR_RO(punit_req_freq_mhz);
static DEVICE_ATTR_RO(throttle_reason_status);
static DEVICE_ATTR_RO(throttle_reason_pl1);
static DEVICE_ATTR_RO(throttle_reason_pl2);
static DEVICE_ATTR_RO(throttle_reason_pl4);
static DEVICE_ATTR_RO(throttle_reason_thermal);
static DEVICE_ATTR_RO(throttle_reason_prochot);
static DEVICE_ATTR_RO(throttle_reason_ratl);
static DEVICE_ATTR_RO(throttle_reason_vr_thermalert);
static DEVICE_ATTR_RO(throttle_reason_vr_tdc);

static const struct attribute *freq_attrs[] = {
	&dev_attr_punit_req_freq_mhz.attr,
	&dev_attr_throttle_reason_status.attr,
	&dev_attr_throttle_reason_pl1.attr,
	&dev_attr_throttle_reason_pl2.attr,
	&dev_attr_throttle_reason_pl4.attr,
	&dev_attr_throttle_reason_thermal.attr,
	&dev_attr_throttle_reason_prochot.attr,
	&dev_attr_throttle_reason_ratl.attr,
	&dev_attr_throttle_reason_vr_thermalert.attr,
	&dev_attr_throttle_reason_vr_tdc.attr,
	NULL
};

static int intel_sysfs_rps_init_gt(struct intel_gt *gt, struct kobject *kobj)
{
	int ret;

	if (GRAPHICS_VER(gt->i915) >= 12) {
		ret = sysfs_create_files(kobj, freq_attrs);
		if (ret)
			return ret;
	}

	if (IS_DGFX(gt->i915)) {
		ret = sysfs_create_file(kobj, &dev_attr_rapl_PL1_freq_mhz.attr);
		if (ret)
			return ret;
	}

	return 0;
}

static int intel_sysfs_rps_init(struct intel_gt *gt, struct kobject *kobj)
{
	const struct attribute * const *attrs;
	int ret;

	if (is_object_gt(kobj))
		attrs = gen6_rps_attrs;
	else
		attrs = gen6_gt_attrs;
	ret = sysfs_create_files(kobj, attrs);
	if (ret)
		return ret;

	if (IS_VALLEYVIEW(gt->i915) || IS_CHERRYVIEW(gt->i915)) {
		ret = sysfs_create_file(kobj, &dev_attr_vlv_rpe_freq_mhz.attr);
		if (ret)
			return ret;
	}

	if (is_object_gt(kobj)) {
		/* attributes for only directory gt/gt<i> */
		ret = intel_sysfs_rps_init_gt(gt, kobj);
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * intel_gt_sysfs_pm_init()
 * @gt: The gt being processed.
 * @kobj: The kobj in sysfs to which created files will be attached.
 *
 * Called twice:
 * - Once with kobj == the device parent directory and gt == gt0.
 *   Populates those things whose parent directory is kobj.
 * - Once per gt, with kobj == that gt's kobject = gt/gt<i>
 *   Populates those things whose parent directory is gt/gt<i>.
 */
void intel_gt_sysfs_pm_init(struct intel_gt *gt, struct kobject *kobj)
{
	int ret;

	intel_sysfs_rc6_init(gt, kobj);

	if (GRAPHICS_VER(gt->i915) >= 6) {
		ret = intel_sysfs_rps_init(gt, kobj);
		if (ret) {
			drm_err(&gt->i915->drm,
				"failed to create gt%u RPS sysfs files",
				gt->info.id);
		}
	}
}
