/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2020 Intel Corporation
 */

#ifndef INTEL_SYSFS_MEM_HEALTH_H
#define INTEL_SYSFS_MEM_HEALTH_H

struct drm_i915_private;

void intel_mem_health_report_sysfs(struct drm_i915_private *i915);
#endif /* INTEL_SYSFS_MEM_HEALTH_H */
