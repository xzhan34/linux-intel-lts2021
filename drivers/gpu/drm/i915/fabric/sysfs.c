// SPDX-License-Identifier: MIT
/*
 * Copyright(c) 2020 - 2022 Intel Corporation.
 *
 */

#include <linux/device.h>
#include "csr.h"
#include "iaf_drv.h"
#include "ops.h"
#include "sysfs.h"

static ssize_t sd_failure_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	struct fsubdev *sd;

	sd = container_of(attr, struct fsubdev, sd_failure);

	return sysfs_emit(buf, "%u\n", test_bit(SD_ERROR_FAILED, sd->errors));
}

static ssize_t iaf_fabric_id_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	struct fdev *fdev = dev_get_drvdata(dev);

	return sysfs_emit(buf, "0x%x\n", fdev->fabric_id);
}

static DEVICE_ATTR_RO(iaf_fabric_id);

static const struct attribute *iaf_attrs[] = {
	&dev_attr_iaf_fabric_id.attr,
	NULL,
};

static void iaf_sysfs_cleanup(struct fsubdev *sd)
{
	kobject_put(sd->kobj);
	sd->kobj = NULL;
}

typedef ssize_t (*show_fn)(struct device *dev, struct device_attribute *attr, char *buf);

static int iaf_sysfs_add_node(const char *name, umode_t mode, show_fn show,
			      struct device_attribute *attr, struct kobject *parent)
{
	sysfs_attr_init(&attr->attr);
	attr->attr.name = name;
	attr->attr.mode = mode;
	attr->show = show;

	return sysfs_create_file(parent, &attr->attr);
}

static int iaf_sysfs_add_sd_nodes(struct fsubdev *sd)
{
	int err;

	err = iaf_sysfs_add_node("sd_failure", 0400, sd_failure_show, &sd->sd_failure, sd->kobj);
	if (err)
		sd_warn(sd, "Failed to add sysfs node %s for %s\n", "sd_failure", sd->name);

	return err;
}

static void iaf_sysfs_sd_init(struct fsubdev *sd)
{
	int err;

	sd->kobj = kobject_create_and_add(sd->name, &sd->fdev->pdev->dev.kobj);
	if (!sd->kobj) {
		sd_warn(sd, "Failed to add sysfs directory %s\n", sd->name);
		return;
	}

	err = iaf_sysfs_add_sd_nodes(sd);
	if (err)
		goto error_return;

	return;

error_return:
	iaf_sysfs_cleanup(sd);
}

void iaf_sysfs_init(struct fdev *fdev)
{
	u8 i;

	for (i = 0; i < fdev->pd->sd_cnt; i++)
		iaf_sysfs_sd_init(&fdev->sd[i]);
}

void iaf_sysfs_remove(struct fdev *fdev)
{
	u8 i;

	for (i = 0; i < fdev->pd->sd_cnt; i++)
		iaf_sysfs_cleanup(&fdev->sd[i]);

	sysfs_remove_files(&fdev->pdev->dev.kobj, iaf_attrs);
}

int iaf_sysfs_probe(struct fdev *fdev)
{
	int err;

	err = sysfs_create_files(&fdev->pdev->dev.kobj, iaf_attrs);
	if (err) {
		dev_err(&fdev->pdev->dev, "Failed to add sysfs\n");
		return err;
	}
	return 0;
}
