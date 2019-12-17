/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __INTEL_IOV_TYPES_H__
#define __INTEL_IOV_TYPES_H__

/**
 * struct intel_iov_config - IOV configuration data.
 */
struct intel_iov_config {
};

/**
 * struct intel_iov_provisioning - IOV provisioning data.
 * @configs: flexible array with configuration data for PF and VFs.
 */
struct intel_iov_provisioning {
	struct intel_iov_config *configs;
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
