// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include <linux/bitfield.h>

#include "gt/uc/abi/guc_actions_vf_abi.h"
#include "gt/uc/abi/guc_version_abi.h"
#include "i915_drv.h"
#include "intel_iov_utils.h"
#include "intel_iov_types.h"
#include "intel_iov_query.h"

static int guc_action_vf_reset(struct intel_guc *guc)
{
	u32 request[GUC_HXG_REQUEST_MSG_MIN_LEN] = {
		FIELD_PREP(GUC_HXG_MSG_0_ORIGIN, GUC_HXG_ORIGIN_HOST) |
		FIELD_PREP(GUC_HXG_MSG_0_TYPE, GUC_HXG_TYPE_REQUEST) |
		FIELD_PREP(GUC_HXG_REQUEST_MSG_0_ACTION, GUC_ACTION_VF2GUC_VF_RESET),
	};
	int ret;

	ret = intel_guc_send_mmio(guc, request, ARRAY_SIZE(request), NULL, 0);

	return ret > 0 ? -EPROTO : ret;
}

static int vf_reset_guc_state(struct intel_iov *iov)
{
	struct intel_guc *guc = iov_to_guc(iov);
	int err;

	GEM_BUG_ON(!intel_iov_is_vf(iov));

	err = guc_action_vf_reset(guc);
	if (unlikely(err))
		IOV_PROBE_ERROR(iov, "Failed to reset GuC state (%pe)\n",
				ERR_PTR(err));

	return err;
}

static int guc_action_match_version(struct intel_guc *guc, u32 *branch,
				    u32 *major, u32 *minor, u32 *patch)
{
	u32 request[VF2GUC_MATCH_VERSION_REQUEST_MSG_LEN] = {
		FIELD_PREP(GUC_HXG_MSG_0_ORIGIN, GUC_HXG_ORIGIN_HOST) |
		FIELD_PREP(GUC_HXG_MSG_0_TYPE, GUC_HXG_TYPE_REQUEST) |
		FIELD_PREP(GUC_HXG_REQUEST_MSG_0_ACTION,
			   GUC_ACTION_VF2GUC_MATCH_VERSION),
		FIELD_PREP(VF2GUC_MATCH_VERSION_REQUEST_MSG_1_BRANCH,
			   *branch) |
		FIELD_PREP(VF2GUC_MATCH_VERSION_REQUEST_MSG_1_MAJOR,
			   *major) |
		FIELD_PREP(VF2GUC_MATCH_VERSION_REQUEST_MSG_1_MINOR,
			   *minor),
	};
	u32 response[VF2GUC_MATCH_VERSION_RESPONSE_MSG_LEN];
	int ret;

	ret = intel_guc_send_mmio(guc, request, ARRAY_SIZE(request),
				  response, ARRAY_SIZE(response));
	if (unlikely(ret < 0))
		return ret;

	GEM_BUG_ON(ret != VF2GUC_MATCH_VERSION_RESPONSE_MSG_LEN);
	if (unlikely(FIELD_GET(VF2GUC_MATCH_VERSION_RESPONSE_MSG_0_MBZ, response[0])))
		return -EPROTO;

	*branch = FIELD_GET(VF2GUC_MATCH_VERSION_RESPONSE_MSG_1_BRANCH, response[1]);
	*major = FIELD_GET(VF2GUC_MATCH_VERSION_RESPONSE_MSG_1_MAJOR, response[1]);
	*minor = FIELD_GET(VF2GUC_MATCH_VERSION_RESPONSE_MSG_1_MINOR, response[1]);
	*patch = FIELD_GET(VF2GUC_MATCH_VERSION_RESPONSE_MSG_1_PATCH, response[1]);

	return 0;
}

static int vf_handshake_with_guc(struct intel_iov *iov)
{
	struct intel_guc *guc = iov_to_guc(iov);
	u32 branch, major, minor, patch;
	int err;

	GEM_BUG_ON(!intel_iov_is_vf(iov));

	/* XXX for now, all platforms use same latest version */
	branch = GUC_VERSION_BRANCH_ANY;
	major = GUC_VF_VERSION_LATEST_MAJOR;
	minor = GUC_VF_VERSION_LATEST_MINOR;

	err = guc_action_match_version(guc, &branch, &major, &minor, &patch);
	if (unlikely(err))
		goto fail;

	/* XXX we only support one version, there must be a match */
	if (major != GUC_VF_VERSION_LATEST_MAJOR || minor != GUC_VF_VERSION_LATEST_MINOR)
		goto fail;

	dev_info(iov_to_dev(iov), "%s interface version %u.%u.%u.%u\n",
		 intel_uc_fw_type_repr(guc->fw.type),
		 branch, major, minor, patch);

	iov->vf.config.guc_abi.branch = branch;
	iov->vf.config.guc_abi.major = major;
	iov->vf.config.guc_abi.minor = minor;
	iov->vf.config.guc_abi.patch = patch;
	return 0;

fail:
	IOV_PROBE_ERROR(iov, "Unable to confirm version %u.%u (%pe)\n",
			major, minor, ERR_PTR(err));

	/* try again with *any* just to query which version is supported */
	branch = GUC_VERSION_BRANCH_ANY;
	major = GUC_VERSION_MAJOR_ANY;
	minor = GUC_VERSION_MINOR_ANY;
	if (!guc_action_match_version(guc, &branch, &major, &minor, &patch))
		IOV_PROBE_ERROR(iov, "Found interface version %u.%u.%u.%u\n",
				branch, major, minor, patch);

	return err;
}

/**
 * intel_iov_query_bootstrap - Query interface version data over MMIO.
 * @iov: the IOV struct
 *
 * This function is for VF use only.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_query_bootstrap(struct intel_iov *iov)
{
	int err;

	GEM_BUG_ON(!intel_iov_is_vf(iov));

	err = vf_reset_guc_state(iov);
	if (unlikely(err))
		return err;

	err = vf_handshake_with_guc(iov);
	if (unlikely(err))
		return err;

	return 0;
}
