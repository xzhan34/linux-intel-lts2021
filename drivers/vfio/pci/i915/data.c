// SPDX-License-Identifier: GPL-2.0-only

#include "i915_vfio_pci.h"

#define BITSTREAM_MAGIC 0x4f49465635313949ULL
#define BITSTREAM_VERSION 0x1

struct i915_vfio_fw_state {
	struct list_head link;
	void *buf;
};

enum {
	I915_VFIO_DATA_GGTT = 0,
	I915_VFIO_DATA_LMEM,
	I915_VFIO_DATA_GUC,
	I915_VFIO_DATA_DONE,
};

static const char *i915_vfio_data_type_str(u32 type)
{
	switch (type) {
	case I915_VFIO_DATA_GGTT: return "ggtt";
	case I915_VFIO_DATA_LMEM: return "lmem";
	case I915_VFIO_DATA_GUC: return "guc";
	case I915_VFIO_DATA_DONE: return "done";
	default: return "";
	}
}

void i915_vfio_data_release(struct i915_vfio_pci_core_device *i915_vdev)
{
	struct i915_vfio_fw_state *state, *next;

	kvfree(i915_vdev->data.buf);

	memset(&i915_vdev->data, 0, sizeof(i915_vdev->data));

	list_for_each_entry_safe(state, next, &i915_vdev->fw_state, link) {
		list_del(&state->link);
		kvfree(state->buf);
		kfree(state);
	}
}

static int i915_vfio_data_alloc(struct i915_vfio_pci_core_device *i915_vdev, size_t size)
{
	void *buf;

	buf = kvrealloc(i915_vdev->data.buf, i915_vdev->data.buf_size,
			size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	i915_vdev->data.buf = buf;
	i915_vdev->data.buf_size = size;

	return 0;
}

static bool i915_vfio_is_last_type(struct i915_vfio_pci_core_device *i915_vdev)
{
	return i915_vdev->data.type == I915_VFIO_DATA_DONE;
}

static void i915_vfio_next_type(struct i915_vfio_pci_core_device *i915_vdev)
{
	/*
	 * Outer loop is iterating over types, inner loop is iterating over
	 * tiles.
	 */
	i915_vdev->data.tile = 0;
	i915_vdev->data.type++;
}

static bool i915_vfio_is_last_tile(struct i915_vfio_pci_core_device *i915_vdev)
{
	return i915_vdev->data.tile == fls(i915_vdev->tile_mask) - 1;
}

static void i915_vfio_next_tile(struct i915_vfio_pci_core_device *i915_vdev)
{
	set_bit(find_next_bit(&i915_vdev->tile_mask, BITS_PER_TYPE(i915_vdev->tile_mask),
			      i915_vdev->data.tile),
		&i915_vdev->data.tile);
}

static bool i915_vfio_data_next(struct i915_vfio_pci_core_device *i915_vdev)
{
	if (i915_vdev->data.offset == i915_vdev->data.size) {
		if (i915_vfio_is_last_tile(i915_vdev))
			i915_vfio_next_type(i915_vdev);
		else
			i915_vfio_next_tile(i915_vdev);

		i915_vdev->data.offset = 0;
	}

	i915_vdev->data.ready = false;

	if (i915_vfio_is_last_type(i915_vdev))
		return false;

	return true;
}

static void i915_vfio_data_header_prepare(struct i915_vfio_pci_core_device *i915_vdev)
{
	struct i915_vfio_pci_migration_header *hdr = i915_vdev->data.buf;

	hdr->magic = BITSTREAM_MAGIC;
	hdr->version = BITSTREAM_VERSION;
	hdr->device = i915_vdev->core_device.pdev->device;
	hdr->type = i915_vdev->data.type;
	hdr->tile = i915_vdev->data.tile;
	hdr->flags = 0;
}

static bool i915_vfio_data_header_check(struct i915_vfio_pci_core_device *i915_vdev)
{
	struct i915_vfio_pci_migration_header *hdr = i915_vdev->data.buf;

	if (hdr->magic != BITSTREAM_MAGIC)
		return false;

	if (hdr->version != BITSTREAM_VERSION)
		return false;

	if (hdr->device != i915_vdev->core_device.pdev->device)
		return false;

	if (hdr->type != i915_vdev->data.type)
		return false;

	if (hdr->tile != i915_vdev->data.tile)
		return false;

	return true;
}

static int _i915_vfio_data_prepare(struct i915_vfio_pci_core_device *i915_vdev)
{
	struct drm_i915_private *i915 = i915_vdev->pf;
	unsigned int vfid = i915_vdev->vfid;
	size_t size;
	bool next;

	if (i915_vdev->tile_mask == 0) {
		dev_err(i915_vdev_to_dev(i915_vdev), "Invalid tile mask\n");
		return -EIO;
	}

	if (i915_vfio_is_last_type(i915_vdev))
		return 0;

	if (i915_vdev->data.ready) {
		if (i915_vdev->data.type != I915_VFIO_DATA_LMEM &&
		    i915_vdev->data.offset != i915_vdev->data.size) {
			dev_dbg(i915_vdev_to_dev(i915_vdev),
				"Multi-part %s state, expecting single part\n",
				i915_vfio_data_type_str(i915_vdev->data.type));
			return -EINVAL;
		}

		next = i915_vfio_data_next(i915_vdev);
		if (!next) {
			i915_vdev->info.pending_bytes = 0;
			return 0;
		}
	}

	if (i915_vdev->data.offset != 0)
		return 0;

	switch (i915_vdev->data.type) {
	case I915_VFIO_DATA_GGTT:
		size = i915_sriov_pf_get_vf_ggtt_size(i915, vfid, i915_vdev->data.tile);
		break;
	case I915_VFIO_DATA_LMEM:
		size = i915_pf_get_vf_lmem_size(i915, vfid, i915_vdev->data.tile);
		break;
	case I915_VFIO_DATA_GUC:
		size = i915_pf_get_vf_fw_state_size(i915, vfid, i915_vdev->data.tile);
		break;
	default:
		return -EINVAL;
	}

	if (size < 0) {
		dev_err(i915_vdev_to_dev(i915_vdev),
			"Failed to obtain %s%lu size: %ld\n",
			i915_vfio_data_type_str(i915_vdev->data.type),
			i915_vdev->data.tile, size);
		return size;
	}

	i915_vdev->data.size = size;
	if (size == 0) {
		next = i915_vfio_data_next(i915_vdev);
		if (!next) {
			i915_vdev->info.pending_bytes = 0;
			return 0;
		}
		return -EAGAIN;
	}

	if (size > I915_VFIO_MAX_DATA_SIZE)
		size = I915_VFIO_MAX_DATA_SIZE;

	size += sizeof(struct i915_vfio_pci_migration_header);

	i915_vdev->info.pending_bytes = size;

	dev_dbg(i915_vdev_to_dev(i915_vdev),
		"prepare_%s: tile%ld, size: %#lx\n",
		i915_vfio_data_type_str(i915_vdev->data.type), i915_vdev->data.tile, size);

	return i915_vfio_data_alloc(i915_vdev, size);
}

static int i915_vfio_data_prepare(struct i915_vfio_pci_core_device *i915_vdev)
{
	int ret;

	do {
		ret = _i915_vfio_data_prepare(i915_vdev);
	} while (ret == -EAGAIN);

	return ret;
}

int i915_vfio_data_save_prepare(struct i915_vfio_pci_core_device *i915_vdev)
{
	int ret;

	ret = i915_vfio_data_prepare(i915_vdev);
	if (ret)
		return ret;

	i915_vfio_data_header_prepare(i915_vdev);

	return 0;
}

int i915_vfio_data_save_state(struct i915_vfio_pci_core_device *i915_vdev)
{
	struct i915_vfio_pci_migration_header *hdr = i915_vdev->data.buf;
	struct drm_i915_private *i915 = i915_vdev->pf;
	unsigned int vfid = i915_vdev->vfid;
	unsigned int type = i915_vdev->data.type;
	unsigned int tile = i915_vdev->data.tile;
	size_t buf_size = i915_vdev->data.buf_size - sizeof(*hdr);
	void *buf = i915_vdev->data.buf + sizeof(*hdr);
	ssize_t size;

	if (i915_vdev->data.ready)
		return 0;

	hdr->offset = i915_vdev->data.offset;

	switch (type) {
	case I915_VFIO_DATA_GGTT:
		size = i915_sriov_pf_save_vf_ggtt(i915, vfid, tile, buf, buf_size);
		i915_vdev->data.offset = i915_vdev->data.size;
		break;
	case I915_VFIO_DATA_LMEM:
		size = i915_sriov_pf_save_vf_lmem(i915, vfid, tile, buf,
						  i915_vdev->data.offset, buf_size);
		i915_vdev->data.offset += size;
		break;
	case I915_VFIO_DATA_GUC:
		size = i915_sriov_pf_save_vf_fw_state(i915, vfid, tile, buf, buf_size);
		i915_vdev->data.offset = i915_vdev->data.size;
		break;
	default:
		size = -EINVAL;
	}

	if (size < 0)
		return size;

	hdr->size = size;
	i915_vdev->data.ready = true;

	i915_vdev->info.data_size = size + sizeof(*hdr);

	return 0;
}

int i915_vfio_data_load_prepare(struct i915_vfio_pci_core_device *i915_vdev)
{
	int ret;

	ret = i915_vfio_data_prepare(i915_vdev);
	if (ret)
		return ret;

	i915_vdev->info.data_size = i915_vdev->data.size +
		sizeof(struct i915_vfio_pci_migration_header);

	return 0;
}

int i915_vfio_data_load_state(struct i915_vfio_pci_core_device *i915_vdev, size_t size)
{
	struct i915_vfio_pci_migration_header *hdr = i915_vdev->data.buf;
	struct drm_i915_private *i915 = i915_vdev->pf;
	unsigned int vfid = i915_vdev->vfid;
	void *buf = i915_vdev->data.buf + sizeof(*hdr);
	struct i915_vfio_fw_state *fw_state;
	int ret;

	if (!i915_vfio_data_header_check(i915_vdev)) {
		dev_dbg(i915_vdev_to_dev(i915_vdev), "Invalid header\n");
		print_hex_dump_debug("hdr:", DUMP_PREFIX_ADDRESS, 32, 8,  hdr,
				     sizeof(*hdr), true);
		return -EINVAL;
	}

	if (size != hdr->size + sizeof(*hdr)) {
		dev_dbg(i915_vdev_to_dev(i915_vdev), "Unexpected size: %lx (expected %llx)\n",
			size, hdr->size + sizeof(*hdr));
		return -EINVAL;
	}

	switch (hdr->type) {
	case I915_VFIO_DATA_GGTT:
		if (hdr->offset != 0)
			return -EINVAL;

		ret = i915_sriov_pf_load_vf_ggtt(i915, vfid, hdr->tile, buf, hdr->size);
		if (ret)
			return ret;
		i915_vdev->data.offset = i915_vdev->data.size;
		break;
	case I915_VFIO_DATA_LMEM:
		ret = i915_sriov_pf_load_vf_lmem(i915, vfid, hdr->tile, buf,
						 hdr->offset, hdr->size);
		if (ret)
			return ret;
		i915_vdev->data.offset += hdr->size;
		break;
	case I915_VFIO_DATA_GUC:
		if (hdr->offset != 0)
			return -EINVAL;

		/*
		 * We can't restore GuC FW state straight away, since this
		 * would immediately move device into "RUNNING" state.
		 * Moreover, state restore causes GuC FW to update VF CTB
		 * descriptor status (which is a write to memory).
		 * Unfortunately, at this point we're usually at a point where
		 * device model has yet to restore RAM, which means that this
		 * memory write will be lost.
		 */
		fw_state = kzalloc(sizeof(*fw_state), GFP_KERNEL);
		if (!fw_state)
			return -ENOMEM;

		fw_state->buf = i915_vdev->data.buf;
		i915_vdev->data.buf = NULL;
		i915_vdev->data.buf_size = 0;
		list_add_tail(&fw_state->link, &i915_vdev->fw_state);

		i915_vdev->data.offset = i915_vdev->data.size;

		break;
	default:
		return -EINVAL;
	}

	i915_vdev->data.ready = true;

	return 0;
}

int i915_vfio_load_fw_state(struct i915_vfio_pci_core_device *i915_vdev)
{
	struct drm_i915_private *i915 = i915_vdev->pf;
	unsigned int vfid = i915_vdev->vfid;
	struct i915_vfio_fw_state *state, *next;
	struct i915_vfio_pci_migration_header *hdr;
	void *buf;
	int ret;

	list_for_each_entry_safe(state, next, &i915_vdev->fw_state, link) {
		hdr = state->buf;
		buf = state->buf + sizeof(*hdr);

		ret = i915_sriov_pf_load_vf_fw_state(i915, vfid, hdr->tile, buf, hdr->size);
		if (ret)
			return ret;

		list_del(&state->link);
		kvfree(state->buf);
		kfree(state);
	}

	return 0;
}
