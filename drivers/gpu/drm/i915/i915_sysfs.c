/*
 * Copyright © 2012 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Ben Widawsky <ben@bwidawsk.net>
 *
 */

#include <linux/device.h>
#include <linux/module.h>
#include <linux/stat.h>
#include <linux/sysfs.h>

#include "gt/intel_gt_regs.h"
#include "gt/intel_rc6.h"
#include "gt/intel_rps.h"
#include "gt/sysfs_engines.h"

#include "i915_drv.h"
#include "i915_sysfs.h"
#include "intel_pm.h"

struct ext_attr {
	struct device_attribute attr;
	unsigned long id;
};

struct drm_i915_private *kdev_minor_to_i915(struct device *kdev)
{
	struct drm_minor *minor = dev_get_drvdata(kdev);
	return to_i915(minor->dev);
}

static int l3_access_valid(struct drm_i915_private *i915, loff_t offset)
{
	if (!HAS_L3_DPF(i915))
		return -EPERM;

	if (!IS_ALIGNED(offset, sizeof(u32)))
		return -EINVAL;

	if (offset >= GEN7_L3LOG_SIZE)
		return -ENXIO;

	return 0;
}

static ssize_t
i915_l3_read(struct file *filp, struct kobject *kobj,
	     struct bin_attribute *attr, char *buf,
	     loff_t offset, size_t count)
{
	struct device *kdev = kobj_to_dev(kobj);
	struct drm_i915_private *i915 = kdev_minor_to_i915(kdev);
	int slice = (int)(uintptr_t)attr->private;
	int ret;

	ret = l3_access_valid(i915, offset);
	if (ret)
		return ret;

	count = round_down(count, sizeof(u32));
	count = min_t(size_t, GEN7_L3LOG_SIZE - offset, count);
	memset(buf, 0, count);

	spin_lock_irq(&i915->gem.contexts.lock);
	if (i915->l3_parity.remap_info[slice])
		memcpy(buf,
		       i915->l3_parity.remap_info[slice] + offset / sizeof(u32),
		       count);
	spin_unlock_irq(&i915->gem.contexts.lock);

	return count;
}

static ssize_t
i915_l3_write(struct file *filp, struct kobject *kobj,
	      struct bin_attribute *attr, char *buf,
	      loff_t offset, size_t count)
{
	struct device *kdev = kobj_to_dev(kobj);
	struct drm_i915_private *i915 = kdev_minor_to_i915(kdev);
	int slice = (int)(uintptr_t)attr->private;
	u32 *remap_info, *freeme = NULL;
	struct i915_gem_context *ctx;
	int ret;

	ret = l3_access_valid(i915, offset);
	if (ret)
		return ret;

	if (count < sizeof(u32))
		return -EINVAL;

	remap_info = kzalloc(GEN7_L3LOG_SIZE, GFP_KERNEL);
	if (!remap_info)
		return -ENOMEM;

	spin_lock_irq(&i915->gem.contexts.lock);

	if (i915->l3_parity.remap_info[slice]) {
		freeme = remap_info;
		remap_info = i915->l3_parity.remap_info[slice];
	} else {
		i915->l3_parity.remap_info[slice] = remap_info;
	}

	count = round_down(count, sizeof(u32));
	memcpy(remap_info + offset / sizeof(u32), buf, count);

	/* NB: We defer the remapping until we switch to the context */
	list_for_each_entry(ctx, &i915->gem.contexts.list, link)
		ctx->remap_slice |= BIT(slice);

	spin_unlock_irq(&i915->gem.contexts.lock);
	kfree(freeme);

	/*
	 * TODO: Ideally we really want a GPU reset here to make sure errors
	 * aren't propagated. Since I cannot find a stable way to reset the GPU
	 * at this point it is left as a TODO.
	*/

	return count;
}

static const struct bin_attribute dpf_attrs = {
	.attr = {.name = "l3_parity", .mode = (S_IRUSR | S_IWUSR)},
	.size = GEN7_L3LOG_SIZE,
	.read = i915_l3_read,
	.write = i915_l3_write,
	.mmap = NULL,
	.private = (void *)0
};

static const struct bin_attribute dpf_attrs_1 = {
	.attr = {.name = "l3_parity_slice_1", .mode = (S_IRUSR | S_IWUSR)},
	.size = GEN7_L3LOG_SIZE,
	.read = i915_l3_read,
	.write = i915_l3_write,
	.mmap = NULL,
	.private = (void *)1
};

#if IS_ENABLED(CONFIG_DRM_I915_CAPTURE_ERROR)

static ssize_t error_state_read(struct file *filp, struct kobject *kobj,
				struct bin_attribute *attr, char *buf,
				loff_t off, size_t count)
{

	struct device *kdev = kobj_to_dev(kobj);
	struct drm_i915_private *i915 = kdev_minor_to_i915(kdev);
	struct i915_gpu_coredump *gpu;
	ssize_t ret;

	gpu = i915_first_error_state(i915);
	if (IS_ERR(gpu)) {
		ret = PTR_ERR(gpu);
	} else if (gpu) {
		ret = i915_gpu_coredump_copy_to_buffer(gpu, buf, off, count);
		i915_gpu_coredump_put(gpu);
	} else {
		const char *str = "No error state collected\n";
		size_t len = strlen(str);

		ret = min_t(size_t, count, len - off);
		memcpy(buf, str + off, ret);
	}

	return ret;
}

static ssize_t error_state_write(struct file *file, struct kobject *kobj,
				 struct bin_attribute *attr, char *buf,
				 loff_t off, size_t count)
{
	struct device *kdev = kobj_to_dev(kobj);
	struct drm_i915_private *dev_priv = kdev_minor_to_i915(kdev);

	drm_dbg(&dev_priv->drm, "Resetting error state\n");
	i915_reset_error_state(dev_priv);

	return count;
}

static const struct bin_attribute error_state_attr = {
	.attr.name = "error",
	.attr.mode = S_IRUSR | S_IWUSR,
	.size = 0,
	.read = error_state_read,
	.write = error_state_write,
};

static void i915_setup_error_capture(struct device *kdev)
{
	if (sysfs_create_bin_file(&kdev->kobj, &error_state_attr))
		DRM_ERROR("error_state sysfs setup failed\n");
}

static void i915_teardown_error_capture(struct device *kdev)
{
	sysfs_remove_bin_file(&kdev->kobj, &error_state_attr);
}
#else
static void i915_setup_error_capture(struct device *kdev) {}
static void i915_teardown_error_capture(struct device *kdev) {}
#endif

static ssize_t prelim_uapi_version_show(struct device *dev,
					struct device_attribute *attr,
					char *buf)
{
	return sysfs_emit(buf, "%d.%d\n", PRELIM_UAPI_MAJOR, PRELIM_UAPI_MINOR);
}

static DEVICE_ATTR_RO(prelim_uapi_version);

static ssize_t i915_driver_error_show(struct device *dev,
				    struct device_attribute *attr,
				    char *buf)
{
	struct device *kdev = kobj_to_dev(dev->kobj.parent);
	struct drm_i915_private *i915 = kdev_minor_to_i915(kdev);
	struct ext_attr *ea = container_of(attr, struct ext_attr, attr);

	if (GEM_WARN_ON(ea->id > ARRAY_SIZE(i915->errors)))
		return -ENOENT;

	return scnprintf(buf, PAGE_SIZE, "%lu\n", i915->errors[ea->id]);
}

#define I915_DRIVER_SYSFS_ERROR_ATTR_RO(_name,  _id) \
	struct ext_attr dev_attr_##_name = \
	{ __ATTR(_name, 0444, i915_driver_error_show, NULL), (_id)}

static I915_DRIVER_SYSFS_ERROR_ATTR_RO(driver_object_migration, I915_DRIVER_ERROR_OBJECT_MIGRATION);

static const struct attribute *i915_error_counter_attrs[] = {
	&dev_attr_driver_object_migration.attr.attr,
	NULL
};

static void i915_setup_error_counter(struct drm_i915_private *i915)
{
	struct device *kdev = i915->drm.primary->kdev;
	struct kobject *kobj;
	int ret;

	kobj = kobject_create_and_add("error_counter", &kdev->kobj);
	if (!kobj)
		goto err;

	ret = sysfs_create_files(kobj, i915_error_counter_attrs);
	if (ret)
		goto err;

	return;

err:
	drm_notice(&i915->drm, "Failed to create error_counter sysfs files at device level\n");
	kobject_put(kobj);
}

static struct kobject *i915_setup_gt_sysfs(struct kobject *parent)
{
	return kobject_create_and_add("gt", parent);
}

void i915_setup_sysfs(struct drm_i915_private *dev_priv)
{
	struct device *kdev = dev_priv->drm.primary->kdev;
	int ret;

	if (sysfs_create_file(&kdev->kobj, &dev_attr_prelim_uapi_version.attr))
		dev_err(kdev, "Failed adding prelim_uapi_version to sysfs\n");

	dev_priv->clients.root =
		kobject_create_and_add("clients", &kdev->kobj);
	if (!dev_priv->clients.root)
		drm_warn(&dev_priv->drm, "Per-client sysfs setup failed\n");

	if (HAS_L3_DPF(dev_priv)) {
		ret = device_create_bin_file(kdev, &dpf_attrs);
		if (ret)
			drm_err(&dev_priv->drm,
				"l3 parity sysfs setup failed\n");

		if (NUM_L3_SLICES(dev_priv) > 1) {
			ret = device_create_bin_file(kdev,
						     &dpf_attrs_1);
			if (ret)
				drm_err(&dev_priv->drm,
					"l3 parity slice 1 setup failed\n");
		}
	}

	dev_priv->sysfs_gt = i915_setup_gt_sysfs(&kdev->kobj);
	if (!dev_priv->sysfs_gt)
		drm_err(&dev_priv->drm,
			"failed to register GT sysfs directory\n");

	i915_setup_error_capture(kdev);

	i915_setup_error_counter(dev_priv);

	intel_engines_add_sysfs(dev_priv);
}

void i915_teardown_sysfs(struct drm_i915_private *dev_priv)
{
	struct device *kdev = dev_priv->drm.primary->kdev;

	sysfs_remove_file(&kdev->kobj, &dev_attr_prelim_uapi_version.attr);

	i915_teardown_error_capture(kdev);

	device_remove_bin_file(kdev,  &dpf_attrs_1);
	device_remove_bin_file(kdev,  &dpf_attrs);

	if (dev_priv->clients.root)
		kobject_put(dev_priv->clients.root);

	kobject_put(dev_priv->sysfs_gt);
}
