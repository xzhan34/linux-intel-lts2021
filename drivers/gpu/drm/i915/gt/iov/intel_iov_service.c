// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include <linux/bitfield.h>

#include "abi/iov_actions_abi.h"
#include "abi/iov_errors_abi.h"
#include "abi/iov_messages_abi.h"
#include "abi/iov_version_abi.h"

#include "intel_iov_relay.h"
#include "intel_iov_service.h"
#include "intel_iov_types.h"
#include "intel_iov_utils.h"

static int reply_handshake(struct intel_iov *iov, u32 origin,
			   u32 relay_id, const u32 *msg, u32 len)
{
	struct intel_iov_relay *relay = &iov->relay;
	u32 response[VF2PF_HANDSHAKE_RESPONSE_MSG_LEN];
	u32 wanted_major, wanted_minor;
	u32 major, minor, mbz;

	GEM_BUG_ON(!origin);
	if (unlikely(len != VF2PF_HANDSHAKE_REQUEST_MSG_LEN))
		return -EMSGSIZE;

	wanted_major = FIELD_GET(VF2PF_HANDSHAKE_REQUEST_MSG_1_MAJOR, msg[1]);
	wanted_minor = FIELD_GET(VF2PF_HANDSHAKE_REQUEST_MSG_1_MINOR, msg[1]);
	IOV_DEBUG(iov, "VF%u wants ABI version %u.%02u\n", origin,
		  wanted_major, wanted_minor);

	mbz = FIELD_GET(VF2PF_HANDSHAKE_REQUEST_MSG_0_MBZ, msg[0]);
	if (unlikely(mbz))
		return -EINVAL;

	if (!wanted_major && !wanted_minor) {
		major = IOV_VERSION_LATEST_MAJOR;
		minor = IOV_VERSION_LATEST_MINOR;
	} else if (wanted_major > IOV_VERSION_LATEST_MAJOR) {
		major = IOV_VERSION_LATEST_MAJOR;
		minor = IOV_VERSION_LATEST_MINOR;
	} else if (wanted_major < IOV_VERSION_BASE_MAJOR) {
		return -EINVAL;
	} else if (wanted_major < IOV_VERSION_LATEST_MAJOR) {
		major = wanted_major;
		minor = wanted_minor;
	} else {
		major = wanted_major;
		minor = min_t(u32, IOV_VERSION_LATEST_MINOR, wanted_minor);
	}

	response[0] = FIELD_PREP(GUC_HXG_MSG_0_ORIGIN, GUC_HXG_ORIGIN_HOST) |
		      FIELD_PREP(GUC_HXG_MSG_0_TYPE, GUC_HXG_TYPE_RESPONSE_SUCCESS) |
		      FIELD_PREP(GUC_HXG_RESPONSE_MSG_0_DATA0, 0);

	response[1] = FIELD_PREP(VF2PF_HANDSHAKE_RESPONSE_MSG_1_MAJOR, major) |
		      FIELD_PREP(VF2PF_HANDSHAKE_RESPONSE_MSG_1_MINOR, minor);
	return intel_iov_relay_reply_to_vf(relay, origin, relay_id,
					   response, ARRAY_SIZE(response));
}

/**
 * intel_iov_service_process_msg - Service request message from VF.
 * @iov: the IOV struct
 * @origin: origin VF number
 * @relay_id: message ID
 * @msg: request message
 * @len: length of the message (in dwords)
 *
 * This function processes `IOV Message`_ from the VF.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_service_process_msg(struct intel_iov *iov, u32 origin,
				  u32 relay_id, const u32 *msg, u32 len)
{
	int err = -EOPNOTSUPP;
	u32 action;
	u32 data;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(len < GUC_HXG_MSG_MIN_LEN);
	GEM_BUG_ON(FIELD_GET(GUC_HXG_MSG_0_TYPE, msg[0]) != GUC_HXG_TYPE_REQUEST);

	action = FIELD_GET(GUC_HXG_REQUEST_MSG_0_ACTION, msg[0]);
	data = FIELD_GET(GUC_HXG_REQUEST_MSG_0_DATA0, msg[0]);
	IOV_DEBUG(iov, "servicing action %#x:%u from %u\n", action, data, origin);

	if (!origin)
		return -EPROTO;

	switch (action) {
	case IOV_ACTION_VF2PF_HANDSHAKE:
		err = reply_handshake(iov, origin, relay_id, msg, len);
		break;
	default:
		break;
	}

	return err;
}
