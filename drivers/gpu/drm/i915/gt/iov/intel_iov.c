// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_utils.h"

/**
 * intel_iov_init_early - Prepare IOV data.
 * @iov: the IOV struct
 *
 * Early initialization of the I/O Virtualization data.
 */
void intel_iov_init_early(struct intel_iov *iov)
{
}

/**
 * intel_iov_release - Release IOV data.
 * @iov: the IOV struct
 *
 * This function will release any data prepared in @intel_iov_init_early.
 */
void intel_iov_release(struct intel_iov *iov)
{
}

/**
 * intel_iov_init - Initialize IOV.
 * @iov: the IOV struct
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_init(struct intel_iov *iov)
{
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
}
