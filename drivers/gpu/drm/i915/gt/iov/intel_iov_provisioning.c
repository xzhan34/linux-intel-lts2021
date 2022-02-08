// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_provisioning.h"
#include "intel_iov_utils.h"

/*
 * Resource configuration for VFs provisioning is maintained in the
 * flexible array where:
 *   - entry [0] contains resource config for the PF,
 *   - entries [1..n] contain provisioning configs for VF1..VFn::
 *
 *       <--------------------------- 1 + total_vfs ----------->
 *      +-------+-------+-------+-----------------------+-------+
 *      |   0   |   1   |   2   |                       |   n   |
 *      +-------+-------+-------+-----------------------+-------+
 *      |  PF   |  VF1  |  VF2  |      ...     ...      |  VFn  |
 *      +-------+-------+-------+-----------------------+-------+
 */

/**
 * intel_iov_provisioning_init_early - Allocate structures for provisioning.
 * @iov: the IOV struct
 *
 * VFs provisioning requires some data to be stored on the PF. Allocate
 * flexible structures to hold all required information for every possible
 * VF. In case of allocation failure PF will be in error state and will not
 * be able to create VFs.
 *
 * This function can only be called on PF.
 */
void intel_iov_provisioning_init_early(struct intel_iov *iov)
{
	struct intel_iov_config *configs;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(iov->pf.provisioning.configs);

	configs = kcalloc(1 + pf_get_totalvfs(iov), sizeof(*configs), GFP_KERNEL);
	if (unlikely(!configs)) {
		pf_update_status(iov, -ENOMEM, "provisioning");
		return;
	}

	iov->pf.provisioning.configs = configs;
	mutex_init(&iov->pf.provisioning.lock);
}

/**
 * intel_iov_provisioning_release - Release structures used for provisioning.
 * @iov: the IOV struct
 *
 * Release structures used for provisioning.
 * This function can only be called on PF.
 */
void intel_iov_provisioning_release(struct intel_iov *iov)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));

	mutex_destroy(&iov->pf.provisioning.lock);
	kfree(fetch_and_zero(&iov->pf.provisioning.configs));
}
