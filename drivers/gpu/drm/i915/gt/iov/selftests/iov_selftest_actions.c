// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "gt/iov/abi/iov_actions_selftest_abi.h"
#include "gt/iov/intel_iov_utils.h"
#include "gt/iov/intel_iov_relay.h"
#include "iov_selftest_actions.h"

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
int intel_iov_service_perform_selftest_action(struct intel_iov *iov, u32 origin, u32 relay_id,
					      const u32 *msg, u32 len)
{
	u32 opcode;

	GEM_BUG_ON(!intel_iov_is_pf(iov));

	if (unlikely(len < VF2PF_PF_ST_ACTION_REQUEST_MSG_MIN_LEN ||
		     len > VF2PF_PF_ST_ACTION_REQUEST_MSG_MAX_LEN))
		return -EPROTO;

	opcode = FIELD_GET(VF2PF_PF_ST_ACTION_REQUEST_MSG_0_OPCODE, msg[0]);

	switch (opcode) {
	default:
		IOV_ERROR(iov, "Unsupported selftest opcode %#x from VF%u\n", opcode, origin);
		return -EBADRQC;
	}

	return intel_iov_relay_reply_ack_to_vf(&iov->relay, origin, relay_id, 0);
}
#endif /* IS_ENABLED(CONFIG_DRM_I915_SELFTEST) */
