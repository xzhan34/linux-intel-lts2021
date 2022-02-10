// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_state.h"
#include "intel_iov_utils.h"

/**
 * intel_iov_state_init_early - Allocate structures for VFs state data.
 * @iov: the IOV struct
 *
 * VFs state data is maintained in the flexible array where:
 *   - entry [0] contains state data of the PF (if applicable),
 *   - entries [1..n] contain state data of VF1..VFn::
 *
 *       <--------------------------- 1 + total_vfs ----------->
 *      +-------+-------+-------+-----------------------+-------+
 *      |   0   |   1   |   2   |                       |   n   |
 *      +-------+-------+-------+-----------------------+-------+
 *      |  PF   |  VF1  |  VF2  |      ...     ...      |  VFn  |
 *      +-------+-------+-------+-----------------------+-------+
 *
 * This function can only be called on PF.
 */
void intel_iov_state_init_early(struct intel_iov *iov)
{
	struct intel_iov_data *data;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(iov->pf.state.data);

	data = kcalloc(1 + pf_get_totalvfs(iov), sizeof(*data), GFP_KERNEL);
	if (unlikely(!data)) {
		pf_update_status(iov, -ENOMEM, "state");
		return;
	}

	iov->pf.state.data = data;
}

/**
 * intel_iov_state_release - Release structures used VFs data.
 * @iov: the IOV struct
 *
 * Release structures used for VFs data.
 * This function can only be called on PF.
 */
void intel_iov_state_release(struct intel_iov *iov)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));

	kfree(fetch_and_zero(&iov->pf.state.data));
}
