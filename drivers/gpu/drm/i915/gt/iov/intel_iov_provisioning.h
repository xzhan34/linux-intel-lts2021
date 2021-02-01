/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __INTEL_IOV_PROVISIONING_H__
#define __INTEL_IOV_PROVISIONING_H__

#include <linux/types.h>

struct intel_iov;

void intel_iov_provisioning_init_early(struct intel_iov *iov);
void intel_iov_provisioning_release(struct intel_iov *iov);

int intel_iov_provisioning_set_ggtt(struct intel_iov *iov, unsigned int id, u64 size);
u64 intel_iov_provisioning_get_ggtt(struct intel_iov *iov, unsigned int id);

#endif /* __INTEL_IOV_PROVISIONING_H__ */
