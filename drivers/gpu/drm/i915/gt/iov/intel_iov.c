// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_provisioning.h"
#include "intel_iov_relay.h"
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

	intel_iov_relay_init_early(&iov->relay);
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

static void pf_enable_ggtt_guest_update(struct intel_iov *iov)
{
	struct intel_gt *gt = iov_to_gt(iov);

	/* Guest Direct GGTT Update Enable */
	intel_uncore_write(gt->uncore, GEN12_VIRTUAL_CTRL_REG,
			   GEN12_GUEST_GTT_UPDATE_EN);
}

/**
 * intel_iov_init_hw - Initialize SR-IOV hardware support.
 * @iov: the IOV struct
 *
 * PF must configure hardware to enable VF's access to GGTT.
 * PF also updates here runtime info (snapshot of registers values)
 * that will be shared with VFs.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_init_hw(struct intel_iov *iov)
{
	if (intel_iov_is_pf(iov))
		pf_enable_ggtt_guest_update(iov);

	return 0;
}
