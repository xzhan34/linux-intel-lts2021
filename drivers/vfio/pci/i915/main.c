// SPDX-License-Identifier: GPL-2.0-only

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/types.h>
#include <linux/vfio.h>

#include "i915_vfio_pci.h"

static void i915_vfio_pci_reset_done(struct pci_dev *pdev)
{
	struct i915_vfio_pci_core_device *i915_vdev = pci_get_drvdata(pdev);
	int ret;

	ret = i915_sriov_pf_wait_vf_flr_done(i915_vdev->pf, i915_vdev->vfid);
	if (ret)
		dev_err(&pdev->dev, "Failed to wait for FLR: %d\n", ret);

	i915_vfio_reset(i915_vdev);
}

static const struct pci_error_handlers i915_vfio_pci_err_handlers = {
	.reset_done = &i915_vfio_pci_reset_done,
};

static ssize_t
i915_vfio_pci_migration_region_rw(struct vfio_pci_core_device *vdev, char __user *buf,
				  size_t count, loff_t *ppos, bool is_write)
{
	unsigned int i = VFIO_PCI_OFFSET_TO_INDEX(*ppos) - VFIO_PCI_NUM_REGIONS;
	struct i915_vfio_pci_core_device *i915_vdev = vdev->region[i].data;
	loff_t offset = *ppos & VFIO_PCI_OFFSET_MASK;
	int ret;

	switch (offset) {
	case offsetof(struct vfio_device_migration_info, device_state):
		ret = i915_vfio_pci_handle_device_state(i915_vdev, buf, count, is_write);
		if (ret)
			return ret;

		break;
	case offsetof(struct vfio_device_migration_info, data_offset):
		ret = i915_vfio_pci_handle_data_offset(i915_vdev, buf, count, is_write);
		if (ret)
			return ret;

		break;
	case offsetof(struct vfio_device_migration_info, data_size):
		ret = i915_vfio_pci_handle_data_size(i915_vdev, buf, count, is_write);
		if (ret)
			return ret;

		break;
	case offsetof(struct vfio_device_migration_info, pending_bytes):
		ret = i915_vfio_pci_handle_pending_bytes(i915_vdev, buf, count, is_write);
		if (ret)
			return ret;

		break;
	default:
		if (offset < sizeof(i915_vdev->info))
			return -EINVAL;

		offset -= sizeof(i915_vdev->info);
		ret = i915_vfio_pci_handle_data_access(i915_vdev, buf, offset, count, is_write);
		if (ret)
			return ret;

		break;
	}

	return count;
}

static void i915_vfio_pci_migration_region_release(struct vfio_pci_core_device *vdev,
						   struct vfio_pci_region *region)
{
	struct i915_vfio_pci_core_device *i915_vdev = region->data;

	i915_vfio_data_release(i915_vdev);
}

static const struct vfio_pci_regops i915_vfio_pci_regops = {
	.rw = i915_vfio_pci_migration_region_rw,
	.release = i915_vfio_pci_migration_region_release,
};

static int i915_vfio_pci_open_device(struct vfio_device *core_vdev)
{
	struct i915_vfio_pci_core_device *i915_vdev =
		container_of(core_vdev, struct i915_vfio_pci_core_device, core_device.vdev);
	struct vfio_pci_core_device *vdev = &i915_vdev->core_device;
	int ret;

	ret = vfio_pci_core_enable(vdev);
	if (ret)
		return ret;

	ret = vfio_pci_register_dev_region(vdev, VFIO_REGION_TYPE_MIGRATION,
					   VFIO_REGION_SUBTYPE_MIGRATION,
					   &i915_vfio_pci_regops,
					   sizeof(i915_vdev->info) + I915_VFIO_MAX_DATA_SIZE +
					   sizeof(struct i915_vfio_pci_migration_header),
					   VFIO_REGION_INFO_FLAG_READ | VFIO_REGION_INFO_FLAG_WRITE,
					   i915_vdev);
	if (ret) {
		vfio_pci_core_disable(vdev);
		return ret;
	}

	vfio_pci_core_finish_enable(vdev);

	return 0;
}

static const struct vfio_device_ops i915_vfio_pci_ops = {
	.name		= "i915-vfio-pci",
	.open_device	= i915_vfio_pci_open_device,
	.close_device	= vfio_pci_core_close_device,
	.ioctl		= vfio_pci_core_ioctl,
	.read		= vfio_pci_core_read,
	.write		= vfio_pci_core_write,
	.mmap		= vfio_pci_core_mmap,
	.request	= vfio_pci_core_request,
	.match		= vfio_pci_core_match,
};

static void unregister_i915_vdev(void *data)
{
	struct i915_vfio_pci_core_device *i915_vdev = data;

	vfio_pci_core_unregister_device(&i915_vdev->core_device);
	vfio_pci_core_uninit_device(&i915_vdev->core_device);
}

static int i915_vfio_pci_probe(struct pci_dev *pdev, const struct pci_device_id *id)
{
	struct i915_vfio_pci_core_device *i915_vdev;
	int ret;

	i915_vdev = devm_kzalloc(&pdev->dev, sizeof(*i915_vdev), GFP_KERNEL);
	if (!i915_vdev)
		return -ENOMEM;
	vfio_pci_core_init_device(&i915_vdev->core_device, pdev, &i915_vfio_pci_ops);

	ret = vfio_pci_core_register_device(&i915_vdev->core_device);
	if (ret) {
		vfio_pci_core_uninit_device(&i915_vdev->core_device);
		return ret;
	}

	ret = devm_add_action_or_reset(&pdev->dev, unregister_i915_vdev, i915_vdev);
	if (ret)
		return ret;

	ret = pci_iov_vf_id(pdev);
	if (WARN_ON(ret < 0))
		return ret;

	if (strcmp(pdev->physfn->dev.driver->name, "i915"))
		return -EINVAL;

	/* vfid starts from 1 for i915 */
	i915_vdev->vfid = ret + 1;
	i915_vdev->pf = pci_get_drvdata(pdev->physfn);
	i915_vdev->info.data_offset = sizeof(i915_vdev->info);
	INIT_LIST_HEAD(&i915_vdev->fw_state);

	dev_set_drvdata(&pdev->dev, i915_vdev);

	return 0;
}

static const struct pci_device_id i915_vfio_pci_table[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_INTEL, PCI_ANY_ID),
	  .class = PCI_BASE_CLASS_DISPLAY << 8, .class_mask = 0xff << 16,
	  .override_only = PCI_ID_F_VFIO_DRIVER_OVERRIDE },
	{}
};
MODULE_DEVICE_TABLE(pci, i915_vfio_pci_table);

static struct pci_driver i915_vfio_pci_driver = {
	.name = "i915-vfio-pci",
	.id_table = i915_vfio_pci_table,
	.probe = i915_vfio_pci_probe,
	.err_handler = &i915_vfio_pci_err_handlers,
};
module_pci_driver(i915_vfio_pci_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Michał Winiarski <michal.winiarski@intel.com>");
MODULE_DESCRIPTION("VFIO PCI driver with migration support for Intel Graphics");
MODULE_IMPORT_NS(I915);
