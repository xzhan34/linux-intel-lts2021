// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bitmap.h>
#include <linux/vfio.h>
#include "i915_vfio_pci.h"

enum {
	MIG_STATE_RUNNING = VFIO_DEVICE_STATE_RUNNING,
	MIG_STATE_PRECOPY = VFIO_DEVICE_STATE_RUNNING | VFIO_DEVICE_STATE_SAVING,
	MIG_STATE_STOPCOPY = VFIO_DEVICE_STATE_SAVING,
	MIG_STATE_STOP = VFIO_DEVICE_STATE_STOP,
	MIG_STATE_RESUMING = VFIO_DEVICE_STATE_RESUMING,
	MIG_STATE_ERROR = VFIO_DEVICE_STATE_SAVING | VFIO_DEVICE_STATE_RESUMING,
};

static const char *i915_vfio_dev_state_str(u32 state)
{
	switch (state) {
	case MIG_STATE_RUNNING: return "running";
	case MIG_STATE_PRECOPY: return "precopy";
	case MIG_STATE_STOPCOPY: return "stopcopy";
	case MIG_STATE_STOP: return "stop";
	case MIG_STATE_RESUMING: return "resuming";
	case MIG_STATE_ERROR: return "error";
	default: return "";
	}
}

void i915_vfio_reset(struct i915_vfio_pci_core_device *i915_vdev)
{
	i915_vdev->info.device_state = MIG_STATE_RUNNING;
	i915_vdev->info.data_size = 0;
	i915_vdev->info.pending_bytes = 0;
	i915_vfio_data_release(i915_vdev);
}

static u32
i915_vfio_state_get(struct i915_vfio_pci_core_device *i915_vdev)
{
	return i915_vdev->info.device_state;
}

static int
i915_vfio_state_set(struct i915_vfio_pci_core_device *i915_vdev, u32 new)
{
	u32 cur = i915_vfio_state_get(i915_vdev);
	int ret;

	if (new == cur)
		return 0;

	if (new == MIG_STATE_ERROR) {
		dev_err(i915_vdev_to_dev(i915_vdev), "device_state: (%s -> %s)\n",
			i915_vfio_dev_state_str(cur), i915_vfio_dev_state_str(new));
		i915_vdev->info.device_state = new;

		return 0;
	}

	switch (cur) {
	case MIG_STATE_RUNNING:
		if (new != MIG_STATE_PRECOPY &&
		    new != MIG_STATE_STOPCOPY &&
		    new != MIG_STATE_STOP &&
		    new != MIG_STATE_RESUMING) {
			ret = -EINVAL;
			goto err;
		}

		i915_vdev->tile_mask = i915_sriov_pf_get_vf_tile_mask(i915_vdev->pf,
								      i915_vdev->vfid);
		if (i915_vdev->tile_mask == 0) {
			ret = -EIO;
			goto err;
		}

		if (new == MIG_STATE_STOPCOPY || new == MIG_STATE_STOP) {
			ret = i915_sriov_pf_pause_vf(i915_vdev->pf, i915_vdev->vfid);
			if (ret)
				goto err;
		}

		if (new == MIG_STATE_RESUMING) {
			ret = i915_vfio_data_load_prepare(i915_vdev);
			if (ret)
				goto err;
		}

		break;
	case MIG_STATE_PRECOPY:
		if (new != MIG_STATE_STOPCOPY) {
			ret = -EINVAL;
			goto err;
		}

		ret = i915_sriov_pf_pause_vf(i915_vdev->pf, i915_vdev->vfid);
		if (ret)
			goto err;

		break;
	case MIG_STATE_STOPCOPY:
		if (new != MIG_STATE_STOP) {
			ret = -EINVAL;
			goto err;
		}

		i915_vfio_data_release(i915_vdev);

		break;
	case MIG_STATE_STOP:
		if (new != MIG_STATE_RUNNING &&
		    new != MIG_STATE_STOPCOPY) {
			ret = -EINVAL;
			goto err;
		}

		if (new == MIG_STATE_RUNNING) {
			ret = i915_sriov_pf_resume_vf(i915_vdev->pf, i915_vdev->vfid);
			if (ret)
				goto err;
		}

		break;
	case MIG_STATE_RESUMING:
		if (new != MIG_STATE_RUNNING) {
			ret = -EINVAL;
			goto err;
		}

		ret = i915_vfio_load_fw_state(i915_vdev);
		if (ret)
			goto err;

		i915_vfio_reset(i915_vdev);

		break;
	case MIG_STATE_ERROR:
		ret = -EINVAL;
		goto err;

		break;
	}

	dev_info(i915_vdev_to_dev(i915_vdev), "device_state: (%s -> %s)\n",
		 i915_vfio_dev_state_str(cur), i915_vfio_dev_state_str(new));
	i915_vdev->info.device_state = new;

	return 0;

err:
	dev_err(i915_vdev_to_dev(i915_vdev), "Failed to set device_state: (%s -> %s) %d\n",
		i915_vfio_dev_state_str(cur), i915_vfio_dev_state_str(new), ret);

	return ret;
}

int
i915_vfio_pci_handle_device_state(struct i915_vfio_pci_core_device *i915_vdev,
				  char __user *buf, size_t count, bool is_write)
{
	u32 state;
	int ret = 0;

	if (count != sizeof(i915_vdev->info.device_state))
		return -EINVAL;

	if (is_write) {
		if (copy_from_user(&state, buf, sizeof(state)))
			return -EFAULT;

		ret = i915_vfio_state_set(i915_vdev, state);
		if (ret)
			i915_vfio_state_set(i915_vdev, MIG_STATE_ERROR);
	} else {
		state = i915_vfio_state_get(i915_vdev);
		if (copy_to_user(buf, &state, sizeof(state)))
			return -EFAULT;
	}

	return ret;
}

int
i915_vfio_pci_handle_pending_bytes(struct i915_vfio_pci_core_device *i915_vdev,
				   char __user *buf, size_t count, bool is_write)
{
	int ret;

	if (is_write)
		return -EPERM;

	if (count != sizeof(i915_vdev->info.pending_bytes))
		return -EINVAL;

	if (i915_vfio_state_get(i915_vdev) == MIG_STATE_STOPCOPY) {
		ret = i915_vfio_data_save_prepare(i915_vdev);
		if (ret)
			return ret;
	}

	if (copy_to_user(buf, &i915_vdev->info.pending_bytes,
			 sizeof(i915_vdev->info.pending_bytes)))
		return -EFAULT;

	return 0;
}

static bool i915_vfio_data_access_valid(struct i915_vfio_pci_core_device *i915_vdev, bool is_write)
{
	u32 state = i915_vfio_state_get(i915_vdev);

	if (is_write) {
		if (state != MIG_STATE_RESUMING)
			return false;
	} else {
		if (state != MIG_STATE_PRECOPY &&
		    state != MIG_STATE_STOPCOPY &&
		    state != MIG_STATE_RESUMING)
			return false;
	}

	return true;
}

int
i915_vfio_pci_handle_data_offset(struct i915_vfio_pci_core_device *i915_vdev,
				 char __user *buf, size_t count, bool is_write)
{
	u32 state;
	int ret;

	if (is_write)
		return -EPERM;

	if (count != sizeof(i915_vdev->info.data_offset))
		return -EINVAL;

	if (!i915_vfio_data_access_valid(i915_vdev, is_write))
		return -EINVAL;

	state = i915_vfio_state_get(i915_vdev);
	if (state == MIG_STATE_PRECOPY || state == MIG_STATE_STOPCOPY) {
		ret = i915_vfio_data_save_state(i915_vdev);
		if (ret)
			return ret;
	}

	if (copy_to_user(buf, &i915_vdev->info.data_offset, sizeof(i915_vdev->info.data_offset)))
		return -EFAULT;

	return 0;
}

static int i915_vfio_size_set(struct i915_vfio_pci_core_device *i915_vdev, u64 size)
{
	int ret;

	ret = i915_vfio_data_load_state(i915_vdev, size);
	if (ret)
		return ret;

	ret = i915_vfio_data_load_prepare(i915_vdev);
	if (ret)
		return ret;

	return 0;
}

static u64 i915_vfio_size_get(struct i915_vfio_pci_core_device *i915_vdev)
{
	return i915_vdev->info.data_size;
}

int
i915_vfio_pci_handle_data_size(struct i915_vfio_pci_core_device *i915_vdev,
			       char __user *buf, size_t count, bool is_write)
{
	u64 size;
	int ret = 0;

	if (count != sizeof(i915_vdev->info.data_size))
		return -EINVAL;

	if (!i915_vfio_data_access_valid(i915_vdev, is_write))
		return -EINVAL;

	if (is_write) {
		if (copy_from_user(&size, buf, sizeof(size)))
			return -EFAULT;

		ret = i915_vfio_size_set(i915_vdev, size);
	} else {
		size = i915_vfio_size_get(i915_vdev);
		if (copy_to_user(buf, &size, sizeof(size)))
			return -EFAULT;
	}

	return ret;
}

int
i915_vfio_pci_handle_data_access(struct i915_vfio_pci_core_device *i915_vdev, char __user *buf,
				 loff_t offset, size_t count, bool is_write)
{
	void *data = i915_vdev->data.buf + offset;

	if (offset + count > i915_vdev->info.data_size)
		return -EINVAL;

	if (!is_write) {
		if (copy_to_user(buf, data, count))
			return -EFAULT;
	} else {
		if (copy_from_user(data, buf, count))
			return -EFAULT;
	}

	return 0;
}
