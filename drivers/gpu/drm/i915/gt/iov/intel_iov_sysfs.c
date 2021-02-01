// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov_provisioning.h"
#include "intel_iov_sysfs.h"
#include "intel_iov_types.h"
#include "intel_iov_utils.h"

/*
 * /sys/class/drm/card*
 * └── iov
 *     ├── pf/
 *     │   └── gt/
 *     │       └── ...
 *     ├── vf1/
 *     │   └── gt/
 *     │       └── ...
 */

#define IOV_KOBJ_GT_NAME "gt"

struct iov_kobj {
	struct kobject base;
	struct intel_iov *iov;
};
#define to_iov_kobj(x) container_of(x, struct iov_kobj, base)

static struct intel_iov *kobj_to_iov(struct kobject *kobj)
{
	return to_iov_kobj(kobj)->iov;
}

static unsigned int kobj_to_id(struct kobject *kobj)
{
	return to_sriov_ext_kobj(kobj->parent)->id;
}

struct iov_attr {
	struct attribute attr;
	ssize_t (*show)(struct intel_iov *iov, unsigned int id, char *buf);
	ssize_t (*store)(struct intel_iov *iov, unsigned int id,
			 const char *buf, size_t count);
};
#define to_iov_attr(x) container_of(x, struct iov_attr, attr)

#define IOV_ATTR(name) \
static struct iov_attr name##_iov_attr = \
	__ATTR(name, 0644, name##_iov_attr_show, name##_iov_attr_store)

#define IOV_ATTR_RO(name) \
static struct iov_attr name##_iov_attr = \
	__ATTR(name, 0444, name##_iov_attr_show, NULL)

/* common attributes */

static struct attribute *iov_attrs[] = {
	NULL
};

static const struct attribute_group iov_attr_group = {
	.attrs = iov_attrs,
};

static const struct attribute_group *default_iov_attr_groups[] = {
	&iov_attr_group,
	NULL
};

/* PF only attributes */

static struct attribute *pf_attrs[] = {
	NULL
};

static const struct attribute_group pf_attr_group = {
	.attrs = pf_attrs,
};

static const struct attribute_group *pf_attr_groups[] = {
	&pf_attr_group,
	NULL
};

/* VFs only attributes */

static ssize_t ggtt_quota_iov_attr_show(struct intel_iov *iov,
					unsigned int id, char *buf)
{
	u64 size = intel_iov_provisioning_get_ggtt(iov, id);

	return sysfs_emit(buf, "%llu\n", size);
}

static ssize_t ggtt_quota_iov_attr_store(struct intel_iov *iov,
					 unsigned int id,
					 const char *buf, size_t count)
{
	u64 size;
	int err;

	err = kstrtou64(buf, 0, &size);
	if (err)
		return err;

	err = intel_iov_provisioning_set_ggtt(iov, id, size);
	return err ?: count;
}

IOV_ATTR(ggtt_quota);

static struct attribute *vf_attrs[] = {
	&ggtt_quota_iov_attr.attr,
	NULL
};

static const struct attribute_group vf_attr_group = {
	.attrs = vf_attrs,
};

static const struct attribute_group *vf_attr_groups[] = {
	&vf_attr_group,
	NULL
};

static const struct attribute_group** iov_attr_groups(unsigned int id)
{
	return id ? vf_attr_groups : pf_attr_groups;
}

/* no user serviceable parts below */

static ssize_t iov_attr_show(struct kobject *kobj,
			     struct attribute *attr, char *buf)
{
	struct iov_attr *iov_attr = to_iov_attr(attr);
	struct intel_iov *iov = kobj_to_iov(kobj);
	unsigned int id = kobj_to_id(kobj);

	return iov_attr->show ? iov_attr->show(iov, id, buf) : -EIO;
}

static ssize_t iov_attr_store(struct kobject *kobj,
			      struct attribute *attr,
			      const char *buf, size_t count)
{
	struct iov_attr *iov_attr = to_iov_attr(attr);
	struct intel_iov *iov = kobj_to_iov(kobj);
	unsigned int id = kobj_to_id(kobj);

	return iov_attr->store ? iov_attr->store(iov, id, buf, count) : -EIO;
}

static const struct sysfs_ops iov_sysfs_ops = {
	.show = iov_attr_show,
	.store = iov_attr_store,
};

static struct kobject *iov_kobj_alloc(struct intel_iov *iov)
{
	struct iov_kobj *iov_kobj;

	iov_kobj = kzalloc(sizeof(*iov_kobj), GFP_KERNEL);
	if (!iov_kobj)
		return NULL;

	iov_kobj->iov = iov;

	return &iov_kobj->base;
}

static void iov_kobj_release(struct kobject *kobj)
{
	struct iov_kobj *iov_kobj = to_iov_kobj(kobj);

	kfree(iov_kobj);
}

static struct kobj_type iov_ktype = {
	.release = iov_kobj_release,
	.sysfs_ops = &iov_sysfs_ops,
	.default_groups = default_iov_attr_groups,
};

static int pf_setup_provisioning(struct intel_iov *iov)
{
	struct i915_sriov_ext_kobj **parents = iov_to_i915(iov)->sriov.pf.sysfs.kobjs;
	struct kobject **kobjs;
	struct kobject *kobj;
	unsigned int count = 1 + pf_get_totalvfs(iov);
	unsigned int n;
	int err;

	GEM_BUG_ON(!intel_iov_is_pf(iov));

	if (!parents) {
		err = -ENODEV;
		goto failed;
	}

	err = i915_inject_probe_error(iov_to_i915(iov), -ENOMEM);
	if (unlikely(err))
		goto failed;

	kobjs = kcalloc(count, sizeof(*kobjs), GFP_KERNEL);
	if (unlikely(!kobjs)) {
		err = -ENOMEM;
		goto failed;
	}

	for (n = 0; n < count; n++) {
		struct kobject *parent;

		err = i915_inject_probe_error(iov_to_i915(iov), -ENOMEM);
		if (unlikely(err)) {
			kobj = NULL;
			goto failed_kobj_n;
		}

		kobj = iov_kobj_alloc(iov);
		if (unlikely(!kobj)) {
			err = -ENOMEM;
			goto failed_kobj_n;
		}

		parent = &parents[n]->base;

		err = kobject_init_and_add(kobj, &iov_ktype, parent, IOV_KOBJ_GT_NAME);
		if (unlikely(err))
			goto failed_kobj_n;

		err = i915_inject_probe_error(iov_to_i915(iov), -EEXIST);
		if (unlikely(err))
			goto failed_kobj_n;

		err = sysfs_create_groups(kobj, iov_attr_groups(n));
		if (unlikely(err))
			goto failed_kobj_n;

		kobjs[n] = kobj;
	}

	GEM_BUG_ON(iov->pf.sysfs.entries);
	iov->pf.sysfs.entries = kobjs;
	return 0;

failed_kobj_n:
	if (kobj)
		kobject_put(kobj);
	while (n--) {
		sysfs_remove_groups(kobjs[n], iov_attr_groups(n));
		kobject_put(kobjs[n]);
	}
	kfree(kobjs);
failed:
	return err;
}

static void pf_teardown_provisioning(struct intel_iov *iov)
{
	struct kobject **kobjs;
	unsigned int count = 1 + pf_get_totalvfs(iov);
	unsigned int n;

	kobjs = fetch_and_zero(&iov->pf.sysfs.entries);
	if (!kobjs)
		return;

	for (n = 0; n < count; n++) {
		sysfs_remove_groups(kobjs[n], iov_attr_groups(n));
		kobject_put(kobjs[n]);
	}

	kfree(kobjs);
}

/**
 * intel_iov_sysfs_setup - Setup GT IOV sysfs.
 * @iov: the IOV struct
 *
 * Setup GT IOV provisioning sysfs.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_sysfs_setup(struct intel_iov *iov)
{
	int err;

	if (!intel_iov_is_pf(iov))
		return 0;

	if (pf_in_error(iov))
		return 0;

	err = pf_setup_provisioning(iov);
	if (unlikely(err))
		goto failed;

	return 0;

failed:
	IOV_PROBE_ERROR(iov, "Failed to setup sysfs (%pe)\n", ERR_PTR(err));
	return err;
}

/**
 * intel_iov_sysfs_teardown - Cleanup GT IOV sysfs.
 * @iov: the IOV struct
 *
 * Remove GT IOV provisioning sysfs.
 */
void intel_iov_sysfs_teardown(struct intel_iov *iov)
{
	if (!intel_iov_is_pf(iov))
		return;

	pf_teardown_provisioning(iov);
}
