/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __I915_SRIOV_TYPES_H__
#define __I915_SRIOV_TYPES_H__

/**
 * struct i915_sriov_pf - i915 SR-IOV PF data.
 * @__status: Status of the PF. Don't access directly!
 */
struct i915_sriov_pf {
	int __status;
};

/**
 * struct i915_sriov - i915 SR-IOV data.
 * @pf: PF only data.
 */
struct i915_sriov {
	struct i915_sriov_pf pf;
};

#endif /* __I915_SRIOV_TYPES_H__ */
