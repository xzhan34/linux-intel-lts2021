/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __I915_SRIOV_TYPES_H__
#define __I915_SRIOV_TYPES_H__

#include <linux/types.h>

/**
 * struct i915_sriov_pf - i915 SR-IOV PF data.
 * @__status: Status of the PF. Don't access directly!
 * @device_vfs: Number of VFs supported by the device.
 * @driver_vfs: Number of VFs supported by the driver.
 */
struct i915_sriov_pf {
	int __status;
	u16 device_vfs;
	u16 driver_vfs;
};

/**
 * struct i915_sriov - i915 SR-IOV data.
 * @pf: PF only data.
 */
struct i915_sriov {
	struct i915_sriov_pf pf;
};

#endif /* __I915_SRIOV_TYPES_H__ */
