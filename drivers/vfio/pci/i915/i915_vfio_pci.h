/* SPDX-License-Identifier: GPL-2.0-only */

#include <linux/vfio_pci_core.h>
#include <linux/sizes.h>
#include <drm/i915_sriov.h>

#define I915_VFIO_MAX_DATA_SIZE SZ_32M

/**
 * struct i915_vfio_pci_core_device - i915-specific vfio_pci_core_device
 *
 * Top level structure of i915_vfio_pci.
 */
struct i915_vfio_pci_core_device {
	/** @core_device: vendor-agnostic VFIO device */
	struct vfio_pci_core_device core_device;
	/** @info: migration info exposed directly to userspace */
	struct vfio_device_migration_info info;

	/** @vfid: VF number used by PF, i915 uses 1-based indexing for vfid */
	unsigned int vfid;

	/** @pf: pointer to driver_private of physical function */
	struct drm_i915_private *pf;

	/** @tile_mask: mask with tiles that contain useful device data */
	unsigned long tile_mask;

	/** @fw_state: list with GuC FW state (one for each tile), kept around
	 * inside the driver during resume due to GuC quirkiness.
	 */
	struct list_head fw_state;

	/** @data: internal state for current device data iteration */
	struct {
		/** @buf: buffer used for transfering individual device data iteration to userspace */
		void *buf;
		/** @buf_size: size of the buffer */
		ssize_t buf_size;
		/** @type: type of device data in current iteration */
		unsigned int type;
		/** @tile: tile on which the current device data iteration operates */
		unsigned long tile;
		/** @offset: offset for current device data iteration, used for Local Memory */
		loff_t offset;
		/** @size: size of current device data iteration */
		size_t size;
		/** @ready: device data is ready to be accessed from userspace */
		bool ready;
	} data;
};

/**
 * struct i915_vfio_pci_migration_header - Migration header
 *
 * Header describing each individual iteration of device data.
 */
struct i915_vfio_pci_migration_header {
	/** @magic: constant, driver specific value */
	u64 magic;
	/** @version: device data version */
	u64 version;
	/** @device: device model identifier */
	u64 device;
	/** @type: type of device state */
	u64 type;
	/** @tile: tile from which the device state comes from */
	u64 tile;
	/** @offset: offset from which the device state was captured, used for Local Memory */
	u64 offset;
	/** @size: size of device data that follows */
	u64 size;
	/** @flags: optional flags */
	u64 flags;
} __packed;

#define i915_vdev_to_dev(i915_vdev) (&(i915_vdev)->core_device.pdev->dev)

void i915_vfio_reset(struct i915_vfio_pci_core_device *i915_vdev);
void i915_vfio_data_release(struct i915_vfio_pci_core_device *i915_vdev);

int i915_vfio_data_save_prepare(struct i915_vfio_pci_core_device *i915_vdev);
int i915_vfio_data_save_state(struct i915_vfio_pci_core_device *i915_vdev);
int i915_vfio_data_load_prepare(struct i915_vfio_pci_core_device *i915_vdev);
int i915_vfio_data_load_state(struct i915_vfio_pci_core_device *i915_vdev, size_t size);

int i915_vfio_load_fw_state(struct i915_vfio_pci_core_device *i915_vdev);

int
i915_vfio_pci_handle_device_state(struct i915_vfio_pci_core_device *priv,
				  char __user *buf, size_t count, bool is_write);

int
i915_vfio_pci_handle_data_offset(struct i915_vfio_pci_core_device *priv,
				 char __user *buf, size_t count, bool is_write);

int
i915_vfio_pci_handle_data_size(struct i915_vfio_pci_core_device *priv,
			       char __user *buf, size_t count, bool is_write);

int
i915_vfio_pci_handle_pending_bytes(struct i915_vfio_pci_core_device *priv,
				   char __user *buf, size_t count, bool is_write);

int
i915_vfio_pci_handle_data_access(struct i915_vfio_pci_core_device *priv, char __user *buf,
				 loff_t offset, size_t count, bool is_write);
