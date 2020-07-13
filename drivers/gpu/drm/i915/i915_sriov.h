/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __I915_SRIOV_H__
#define __I915_SRIOV_H__

#include "i915_drv.h"
#include "i915_virtualization.h"

struct drm_i915_private;

#ifdef CONFIG_PCI_IOV
#define IS_SRIOV_PF(i915) (IOV_MODE(i915) == I915_IOV_MODE_SRIOV_PF)
#else
#define IS_SRIOV_PF(i915) false
#endif
#define IS_SRIOV_VF(i915) (IOV_MODE(i915) == I915_IOV_MODE_SRIOV_VF)

#define IS_SRIOV(i915) (IS_SRIOV_PF(i915) || IS_SRIOV_VF(i915))

enum i915_iov_mode i915_sriov_probe(struct drm_i915_private *i915);

#endif /* __I915_SRIOV_H__ */
