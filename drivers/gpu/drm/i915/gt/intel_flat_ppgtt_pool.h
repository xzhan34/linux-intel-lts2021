/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2020 Intel Corporation
 */

#ifndef INTEL_FLAT_PPGTT_POOL_H
#define INTEL_FLAT_PPGTT_POOL_H

struct intel_flat_ppgtt_pool;
struct i915_address_space;

void intel_flat_ppgtt_pool_init_early(struct intel_flat_ppgtt_pool *fpp);
int intel_flat_ppgtt_pool_init(struct intel_flat_ppgtt_pool *fpp,
			       struct i915_address_space *vm);
void intel_flat_ppgtt_pool_fini(struct intel_flat_ppgtt_pool *fpp);

#endif /* INTEL_FLAT_PPGTT_POOL_H */
