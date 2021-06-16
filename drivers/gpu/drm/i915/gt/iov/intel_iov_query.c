// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include <drm/drm_print.h>
#include <linux/bitfield.h>

#include "gt/uc/abi/guc_actions_vf_abi.h"
#include "gt/uc/abi/guc_klvs_abi.h"
#include "gt/uc/abi/guc_version_abi.h"
#include "i915_drv.h"
#include "intel_iov_relay.h"
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

static int guc_action_query_single_klv(struct intel_guc *guc, u32 key,
				       u32 *value, u32 value_len)
{
	u32 request[VF2GUC_QUERY_SINGLE_KLV_REQUEST_MSG_LEN] = {
		FIELD_PREP(GUC_HXG_MSG_0_ORIGIN, GUC_HXG_ORIGIN_HOST) |
		FIELD_PREP(GUC_HXG_MSG_0_TYPE, GUC_HXG_TYPE_REQUEST) |
		FIELD_PREP(GUC_HXG_REQUEST_MSG_0_ACTION,
			   GUC_ACTION_VF2GUC_QUERY_SINGLE_KLV),
		FIELD_PREP(VF2GUC_QUERY_SINGLE_KLV_REQUEST_MSG_1_KEY, key),
	};
	u32 response[VF2GUC_QUERY_SINGLE_KLV_RESPONSE_MSG_MAX_LEN];
	u32 length;
	int ret;

	ret = intel_guc_send_mmio(guc, request, ARRAY_SIZE(request),
				  response, ARRAY_SIZE(response));
	if (unlikely(ret < 0))
		return ret;

	GEM_BUG_ON(ret != VF2GUC_QUERY_SINGLE_KLV_RESPONSE_MSG_MAX_LEN);
	if (unlikely(FIELD_GET(VF2GUC_QUERY_SINGLE_KLV_RESPONSE_MSG_0_MBZ, response[0])))
		return -EPROTO;

	length = FIELD_GET(VF2GUC_QUERY_SINGLE_KLV_RESPONSE_MSG_0_LENGTH, response[0]);
	if (unlikely(length > value_len))
		return -EOVERFLOW;
	if (unlikely(length < value_len))
		return -ENODATA;

	GEM_BUG_ON(length != value_len);
	switch (value_len) {
	default:
		GEM_BUG_ON(value_len);
		return -EINVAL;
	case 3:
		value[2] = FIELD_GET(VF2GUC_QUERY_SINGLE_KLV_RESPONSE_MSG_3_VALUE96, response[3]);
		fallthrough;
	case 2:
		value[1] = FIELD_GET(VF2GUC_QUERY_SINGLE_KLV_RESPONSE_MSG_2_VALUE64, response[2]);
		fallthrough;
	case 1:
		value[0] = FIELD_GET(VF2GUC_QUERY_SINGLE_KLV_RESPONSE_MSG_1_VALUE32, response[1]);
		fallthrough;
	case 0:
		break;
	}

	return 0;
}

static int guc_action_query_single_klv32(struct intel_guc *guc, u32 key, u32 *value32)
{
	return guc_action_query_single_klv(guc, key, value32, 1);
}

static int guc_action_query_single_klv64(struct intel_guc *guc, u32 key, u64 *value64)
{
	u32 value[2];
	int err;

	err = guc_action_query_single_klv(guc, key, value, ARRAY_SIZE(value));
	if (unlikely(err))
		return err;

	*value64 = (u64)value[1] << 32 | value[0];
	return 0;
}

static int vf_get_ggtt_info(struct intel_iov *iov)
{
	struct intel_guc *guc = iov_to_guc(iov);
	u64 start, size;
	int err;

	GEM_BUG_ON(!intel_iov_is_vf(iov));
	GEM_BUG_ON(iov->vf.config.ggtt_size);

	err = guc_action_query_single_klv64(guc, GUC_KLV_VF_CFG_GGTT_START_KEY, &start);
	if (unlikely(err))
		return err;

	err = guc_action_query_single_klv64(guc, GUC_KLV_VF_CFG_GGTT_SIZE_KEY, &size);
	if (unlikely(err))
		return err;

	IOV_DEBUG(iov, "GGTT %#llx-%#llx = %lluK\n",
		  start, start + size -1, size / SZ_1K);

	iov->vf.config.ggtt_base = start;
	iov->vf.config.ggtt_size = size;

	return iov->vf.config.ggtt_size ? 0 : -ENODATA;
}

static int vf_get_submission_cfg(struct intel_iov *iov)
{
	struct intel_guc *guc = iov_to_guc(iov);
	u32 num_ctxs, num_dbs;
	int err;

	GEM_BUG_ON(!intel_iov_is_vf(iov));
	GEM_BUG_ON(iov->vf.config.num_ctxs);

	err = guc_action_query_single_klv32(guc, GUC_KLV_VF_CFG_NUM_CONTEXTS_KEY, &num_ctxs);
	if (unlikely(err))
		return err;

	err = guc_action_query_single_klv32(guc, GUC_KLV_VF_CFG_NUM_DOORBELLS_KEY, &num_dbs);
	if (unlikely(err))
		return err;

	IOV_DEBUG(iov, "CTXs %u DBs %u\n", num_ctxs, num_dbs);

	iov->vf.config.num_ctxs = num_ctxs;
	iov->vf.config.num_dbs = num_dbs;

	return iov->vf.config.num_ctxs ? 0 : -ENODATA;
}

/**
 * intel_iov_query_config - Query IOV config data over MMIO.
 * @iov: the IOV struct
 *
 * This function is for VF use only.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_query_config(struct intel_iov *iov)
{
	int err;

	GEM_BUG_ON(!intel_iov_is_vf(iov));

	err = vf_get_ggtt_info(iov);
	if (unlikely(err))
		return err;

	err = vf_get_submission_cfg(iov);
	if (unlikely(err))
		return err;

	return 0;
}

/**
 * intel_iov_query_print_config - Print queried VF config.
 * @iov: the IOV struct
 * @p: the DRM printer
 *
 * This function is for VF use only.
 */
void intel_iov_query_print_config(struct intel_iov *iov, struct drm_printer *p)
{
	GEM_BUG_ON(!intel_iov_is_vf(iov));

	drm_printf(p, "GGTT range:\t%#08llx-%#08llx\n",
			iov->vf.config.ggtt_base,
			iov->vf.config.ggtt_base + iov->vf.config.ggtt_size - 1);
	drm_printf(p, "GGTT size:\t%lluK\n", iov->vf.config.ggtt_size / SZ_1K);

	drm_printf(p, "contexts:\t%hu\n", iov->vf.config.num_ctxs);
	drm_printf(p, "doorbells:\t%hu\n", iov->vf.config.num_dbs);
}
