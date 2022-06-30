// SPDX-License-Identifier: MIT
/*
 * Copyright 2021, Intel Corporation.
 */

#include "i915_drv.h"
#include "gt/uc/intel_gsc_fw.h"
#include "gt/uc/intel_gsc_fwif.h"
#include "gem/i915_gem_region.h"
#include "i915_utils.h"
#include "display/intel_hdcp_gsc.h"

struct intel_hdcp_gsc_message {
	struct drm_i915_gem_object *obj;
	struct i915_vma *vma;
	void *hdcp_cmd;
};

/*This function helps allocate memory for the command that we will send to gsc cs */
static int intel_initialize_hdcp_gsc_message(struct drm_i915_private *i915,
		struct intel_hdcp_gsc_message *hdcp_message)
{
	struct intel_gt *gt = i915->media_gt;
	struct drm_i915_gem_object *obj = NULL;
	struct i915_vma *vma = NULL;
	void *cmd;
	int err;

	hdcp_message->obj = NULL;
	hdcp_message->hdcp_cmd = NULL;
	hdcp_message->vma = NULL;

	/* allocate object of one page for HDCP command memory and store it */
	obj = i915_gem_object_create_shmem(gt->i915, PAGE_SIZE);

	if (IS_ERR(obj)) {
		drm_err(&gt->i915->drm, "Failed to allocate HDCP streaming command!\n");
		return PTR_ERR(obj);
	}

	cmd = i915_gem_object_pin_map_unlocked(obj, i915_coherent_map_type(gt->i915, obj, true));
	if (IS_ERR(cmd)) {
		drm_err(&gt->i915->drm, "Failed to map gsc message page!\n");
		err = PTR_ERR(cmd);
		goto out_unpin;
	}

	vma = i915_vma_instance(obj, &gt->ggtt->vm, NULL);
	if (IS_ERR(vma)) {
		err = PTR_ERR(vma);
		goto out_unmap;
	}

	err = i915_vma_pin(vma, 0, 0, PIN_GLOBAL);
	if (err)
		goto out_unmap;

	memset(cmd, 0, obj->base.size);

	hdcp_message->obj = obj;
	hdcp_message->hdcp_cmd = cmd;
	hdcp_message->vma = vma;

	return 0;

out_unmap:
	i915_gem_object_unpin_map(obj);
out_unpin:
	i915_gem_object_put(obj);
	return err;
}

static void intel_free_hdcp_gsc_message(struct intel_hdcp_gsc_message *hdcp_message)
{
	struct drm_i915_gem_object *obj = fetch_and_zero(&hdcp_message->obj);

	if (!obj)
		return;

	if (hdcp_message->vma)
		i915_vma_unpin(fetch_and_zero(&hdcp_message->vma));

	i915_gem_object_unpin_map(obj);
	i915_gem_object_put(obj);
	kfree(hdcp_message);
}

static int intel_gsc_send_sync(struct drm_i915_private *i915,
		struct intel_gsc_mtl_header *header, u64 addr,
		size_t msg_out_len)
{
	struct intel_gt *gt = i915->media_gt;
	int ret;

	header->flags = 0;
	ret = intel_gsc_fw_heci_send(&gt->uc.gsc, addr, header->message_size,
			     addr, msg_out_len + sizeof(*header));
	if (ret) {
		drm_err(&i915->drm, "failed to send gsc HDCP msg (%d)\n", ret);
		return ret;
	}
	/*
	 * Checking validity marker for memory sanity
	 */
	if (header->validity_marker != GSC_HECI_VALIDITY_MARKER) {
		drm_err(&i915->drm, "invalid validity marker\n");
		return -EINVAL;
	}

	if (header->status != 0) {
		drm_err(&i915->drm, "header status indicates error %d\n",
			header->status);
		return -EINVAL;
	}

	if (header->flags & INTEL_GSC_MSG_PENDING)
		return -EAGAIN;

	return 0;
}

/*
 * This function can now be used for sending requests and will also handle
 * receipt of reply messages hence no different function of message retrieval
 * is required. We will initialize intel_hdcp_gsc_message structure then add
 * gsc cs memory header as stated in specs after which the normal HDCP payload
 * will follow
 */
ssize_t intel_hdcp_gsc_msg_send(struct drm_i915_private *i915, u8 *msg_in,
		size_t msg_in_len, u8 *msg_out, size_t msg_out_len)
{
	struct intel_gt *gt = i915->media_gt;
	struct intel_gsc_mtl_header *header;
	const size_t max_msg_size = PAGE_SIZE - sizeof(*header);
	struct intel_hdcp_gsc_message *hdcp_message;
	u64 addr;
	u32 reply_size;
	int ret, tries = 0;

	if (!intel_uc_uses_gsc_uc(&gt->uc))
		return -ENODEV;

	if (msg_in_len > max_msg_size || msg_out_len > max_msg_size)
		return -ENOSPC;

	hdcp_message = kzalloc(sizeof(*hdcp_message), GFP_KERNEL);

	if (!hdcp_message)
		return -ENOMEM;

	ret = intel_initialize_hdcp_gsc_message(i915, hdcp_message);

	if (ret) {
		drm_err(&i915->drm,
			"Could not initialize hdcp_message\n");
		goto err;
	}

	header = hdcp_message->hdcp_cmd;
	addr = i915_ggtt_offset(hdcp_message->vma);

	memset(header, 0, sizeof(*header));
	header->validity_marker = GSC_HECI_VALIDITY_MARKER;
	header->gsc_address = HECI_MEADDRESS_HDCP;
	header->host_session_handle = 0;
	header->header_version = MTL_GSC_HEADER_VERSION;
	header->message_size = msg_in_len + sizeof(*header);

	memcpy(hdcp_message->hdcp_cmd + sizeof(*header), msg_in, msg_in_len);

	/*
	 * Keep sending request in case the pending bit is set no need to add
	 * message handle as we are using same address hence loc. of header is
	 * same and it will contain the message handle. we will send the message
	 * 20 times each message 50 ms apart
	 */
	do {
		ret = intel_gsc_send_sync(i915, header, addr, msg_out_len);

		/* Only try again if gsc says so */
		if (ret != -EAGAIN)
			break;

		msleep(50);

	} while (++tries < 20);

	if (ret)
		goto err;

	/* we use the same mem for the reply, so header is in the same loc */
	reply_size = header->message_size - sizeof(*header);
	if (reply_size > msg_out_len) {
		drm_warn(&i915->drm, "caller with insufficient HDCP reply size %u (%d)\n",
			 reply_size, (u32)msg_out_len);
		reply_size = msg_out_len;
	} else if (reply_size != msg_out_len) {
		drm_dbg_kms(&i915->drm, "caller unexpected HCDP reply size %u (%d)\n",
			reply_size, (u32)msg_out_len);
	}

	memcpy(msg_out, hdcp_message->hdcp_cmd + sizeof(*header), msg_out_len);

err:
	intel_free_hdcp_gsc_message(hdcp_message);
	return ret;
}
