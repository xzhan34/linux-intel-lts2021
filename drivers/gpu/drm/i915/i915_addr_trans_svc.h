/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __I915_ADDR_TRANS_SVC_H__
#define __I915_ADDR_TRANS_SVC_H__

#include <linux/hmm.h>
#include <linux/intel-iommu.h>
#include <linux/pci-ats.h>
#include "i915_svm.h"
#include "i915_drv.h"

#include "gt/intel_gtt.h"

#if  IS_ENABLED(CONFIG_DRM_I915_ATS)
/* TODO: Private structure for ATS - need expansion */
struct i915_ats_priv {
	struct drm_i915_private *i915;
	struct device_domain_info *ats_info;
};

void i915_enable_ats(struct drm_i915_private *i915);
void i915_disable_ats(struct drm_i915_private *i915);
bool i915_ats_enabled(struct drm_i915_private *dev_priv);

#else /* CONFIG_DRM_I915_ATS */
struct i915_ats_priv { };
static inline void i915_enable_ats(struct drm_i915_private *i915) { }
static inline void i915_disable_ats(struct drm_i915_private *i915) { }
static inline bool i915_ats_enabled(struct drm_i915_private *dev_priv)
{ return false; }

#endif /* CONFIG_DRM_I915_ATS */
#endif /* __I915_ADDR_TRANS_SVC_H__ */
