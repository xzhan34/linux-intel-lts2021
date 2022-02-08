/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __INTEL_IOV_TYPES_H__
#define __INTEL_IOV_TYPES_H__

#include <linux/mutex.h>

/**
 * struct intel_iov_config - IOV configuration data.
 */
struct intel_iov_config {
};

/**
 * struct intel_iov_provisioning - IOV provisioning data.
 * @configs: flexible array with configuration data for PF and VFs.
 * @lock: protects provisionining data
 */
struct intel_iov_provisioning {
	struct intel_iov_config *configs;
	struct mutex lock;
};

#define VFID(n)		(n)
#define PFID		VFID(0)

/**
 * struct intel_iov - I/O Virtualization related data.
 * @pf.provisioning: provisioning data.
 */
struct intel_iov {
	struct {
		struct intel_iov_provisioning provisioning;
	} pf;
};

#endif /* __INTEL_IOV_TYPES_H__ */
