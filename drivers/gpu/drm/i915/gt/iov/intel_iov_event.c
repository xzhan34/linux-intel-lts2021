// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_event.h"
#include "intel_iov_utils.h"

static int threshold_key_to_enum(u32 threshold)
{
	switch (threshold) {
#define __iov_threshold_key_to_enum(K, ...) \
	case GUC_KLV_VF_CFG_THRESHOLD_##K##_KEY: return IOV_THRESHOLD_##K;
	IOV_THRESHOLDS(__iov_threshold_key_to_enum)
#undef __iov_threshold_key_to_enum
	}
	return -1; /* not found */
}

static void pf_update_event_counter(struct intel_iov *iov, u32 vfid,
				    enum intel_iov_threshold e)
{
	++iov->pf.state.data[vfid].adverse_events[e];
}

static int pf_handle_vf_threshold_event(struct intel_iov *iov, u32 vfid, u32 threshold)
{
	int e = threshold_key_to_enum(threshold);

	if (unlikely(!vfid || vfid > pf_get_totalvfs(iov)))
		return -EINVAL;

	if (unlikely(GEM_WARN_ON(e < 0)))
		return -EINVAL;

	IOV_DEBUG(iov, "VF%u threshold %04x\n", vfid, threshold);

	pf_update_event_counter(iov, vfid, e);

	return 0;
}

/**
 * intel_iov_event_process_guc2pf - Handle adverse event notification from GuC.
 * @iov: the IOV struct
 * @msg: message from the GuC
 * @len: length of the message
 *
 * This function is for PF only.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_event_process_guc2pf(struct intel_iov *iov,
				   const u32 *msg, u32 len)
{
	u32 vfid;
	u32 threshold;

	GEM_BUG_ON(!len);
	GEM_BUG_ON(FIELD_GET(GUC_HXG_MSG_0_ORIGIN, msg[0]) != GUC_HXG_ORIGIN_GUC);
	GEM_BUG_ON(FIELD_GET(GUC_HXG_MSG_0_TYPE, msg[0]) != GUC_HXG_TYPE_EVENT);
	GEM_BUG_ON(FIELD_GET(GUC_HXG_EVENT_MSG_0_ACTION, msg[0]) != GUC_ACTION_GUC2PF_ADVERSE_EVENT);

	if (unlikely(!intel_iov_is_pf(iov)))
		return -EPROTO;

	if (unlikely(FIELD_GET(GUC2PF_ADVERSE_EVENT_EVENT_MSG_0_MBZ, msg[0])))
		return -EPFNOSUPPORT;

	if (unlikely(len != GUC2PF_ADVERSE_EVENT_EVENT_MSG_LEN))
		return -EPROTO;

	vfid = FIELD_GET(GUC2PF_ADVERSE_EVENT_EVENT_MSG_1_VFID, msg[1]);
	threshold = FIELD_GET(GUC2PF_ADVERSE_EVENT_EVENT_MSG_2_THRESHOLD, msg[2]);

	return pf_handle_vf_threshold_event(iov, vfid, threshold);
}
