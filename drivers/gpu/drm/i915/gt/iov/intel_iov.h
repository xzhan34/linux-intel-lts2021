/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __INTEL_IOV_H__
#define __INTEL_IOV_H__

struct intel_iov;

void intel_iov_init_early(struct intel_iov *iov);
void intel_iov_release(struct intel_iov *iov);

int intel_iov_init(struct intel_iov *iov);
void intel_iov_fini(struct intel_iov *iov);

int intel_iov_init_hw(struct intel_iov *iov);

#endif /* __INTEL_IOV_H__ */
