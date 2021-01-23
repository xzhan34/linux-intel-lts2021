// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include <linux/kobject.h>
#include <linux/sysfs.h>

#include "i915_drv.h"
#include "i915_sysfs.h"
#include "intel_sysfs_mem_health.h"

static const char *
memory_error_to_str(const struct intel_mem_sparing_event *mem)
{
	switch (mem->health_status) {
	case MEM_HEALTH_ALARM:
		return "MEMORY_HEALTH_ALARM";
	case MEM_HEALTH_EC_PENDING:
		return "EC_PENDING";
	case MEM_HEALTH_DEGRADED:
		return "DEGRADED";
	case MEM_HEALTH_UNKNOWN:
		return "MEMORY_HEALTH_UNKNOWN";
	case MEM_HEALTH_OKAY:
	default:
		return "OK";
	}
}

static ssize_t
device_memory_health_show(struct device *kdev, struct device_attribute *attr,
			  char *buf)
{
	struct drm_i915_private *i915 = kdev_minor_to_i915(kdev);
	const char *mem_status;

	mem_status = memory_error_to_str(&to_gt(i915)->mem_sparing);
	return snprintf(buf, PAGE_SIZE, "%s\n", mem_status);
}

static const DEVICE_ATTR_RO(device_memory_health);

static const struct attribute *mem_health_attrs[] = {
	&dev_attr_device_memory_health.attr,
	NULL
};

void intel_mem_health_report_sysfs(struct drm_i915_private *i915)
{
	struct device *kdev = i915->drm.primary->kdev;

	if (!HAS_MEM_SPARING_SUPPORT(i915))
		return;

	if (sysfs_create_files(&kdev->kobj, mem_health_attrs)) {
		dev_err(kdev, "Failed to add sysfs files to show memory health status\n");
		return;
	}
}
