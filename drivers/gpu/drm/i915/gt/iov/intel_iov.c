// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_provisioning.h"
#include "intel_iov_utils.h"

/**
 * intel_iov_init_early - Prepare IOV data.
 * @iov: the IOV struct
 *
 * Early initialization of the I/O Virtualization data.
 */
void intel_iov_init_early(struct intel_iov *iov)
{
	if (intel_iov_is_pf(iov))
		intel_iov_provisioning_init_early(iov);
}

/**
 * intel_iov_release - Release IOV data.
 * @iov: the IOV struct
 *
 * This function will release any data prepared in @intel_iov_init_early.
 */
void intel_iov_release(struct intel_iov *iov)
{
	if (intel_iov_is_pf(iov))
		intel_iov_provisioning_release(iov);
}

/**
 * intel_iov_init - Initialize IOV.
 * @iov: the IOV struct
 *
 * On PF this function performs initial partitioning of the shared resources
 * that can't be changed later (GuC submission contexts) to allow early PF
 * provisioning.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_init(struct intel_iov *iov)
{
	if (intel_iov_is_pf(iov))
		intel_iov_provisioning_init(iov);

	return 0;
}

/**
 * intel_iov_fini - Cleanup IOV.
 * @iov: the IOV struct
 *
 * This function will cleanup any data prepared in @intel_iov_init.
 */
void intel_iov_fini(struct intel_iov *iov)
{
	if (intel_iov_is_pf(iov))
		intel_iov_provisioning_fini(iov);
}
