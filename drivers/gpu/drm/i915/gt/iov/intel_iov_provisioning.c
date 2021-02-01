// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_provisioning.h"
#include "intel_iov_utils.h"

/*
 * Resource configuration for VFs provisioning is maintained in the
 * flexible array where:
 *   - entry [0] contains resource config for the PF,
 *   - entries [1..n] contain provisioning configs for VF1..VFn::
 *
 *       <--------------------------- 1 + total_vfs ----------->
 *      +-------+-------+-------+-----------------------+-------+
 *      |   0   |   1   |   2   |                       |   n   |
 *      +-------+-------+-------+-----------------------+-------+
 *      |  PF   |  VF1  |  VF2  |      ...     ...      |  VFn  |
 *      +-------+-------+-------+-----------------------+-------+
 */

/**
 * intel_iov_provisioning_init_early - Allocate structures for provisioning.
 * @iov: the IOV struct
 *
 * VFs provisioning requires some data to be stored on the PF. Allocate
 * flexible structures to hold all required information for every possible
 * VF. In case of allocation failure PF will be in error state and will not
 * be able to create VFs.
 *
 * This function can only be called on PF.
 */
void intel_iov_provisioning_init_early(struct intel_iov *iov)
{
	struct intel_iov_config *configs;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(iov->pf.provisioning.configs);

	configs = kcalloc(1 + pf_get_totalvfs(iov), sizeof(*configs), GFP_KERNEL);
	if (unlikely(!configs)) {
		pf_update_status(iov, -ENOMEM, "provisioning");
		return;
	}

	iov->pf.provisioning.configs = configs;
	mutex_init(&iov->pf.provisioning.lock);
}

/**
 * intel_iov_provisioning_release - Release structures used for provisioning.
 * @iov: the IOV struct
 *
 * Release structures used for provisioning.
 * This function can only be called on PF.
 */
void intel_iov_provisioning_release(struct intel_iov *iov)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));

	mutex_destroy(&iov->pf.provisioning.lock);
	kfree(fetch_and_zero(&iov->pf.provisioning.configs));
}

static struct mutex *pf_provisioning_mutex(struct intel_iov *iov)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));
	return &iov->pf.provisioning.lock;
}

static u64 pf_get_ggtt_alignment(struct intel_iov *iov)
{
	/* this might be platform dependent */
	return SZ_4K;
}

static int pf_provision_ggtt(struct intel_iov *iov, unsigned int id, u64 size)
{
	struct intel_iov_provisioning *provisioning = &iov->pf.provisioning;
	struct intel_iov_config *config = &provisioning->configs[id];
	struct drm_mm_node *node = &config->ggtt_region;
	struct i915_ggtt *ggtt = iov_to_gt(iov)->ggtt;
	u64 alignment = pf_get_ggtt_alignment(iov);
	int err;

	if (check_round_up_overflow(size, alignment, &size))
		return -EOVERFLOW;

	if (drm_mm_node_allocated(node)) {
		if (size == node->size)
			return 0;

		mutex_lock(&ggtt->vm.mutex);
		drm_mm_remove_node(node);
		mutex_unlock(&ggtt->vm.mutex);
	}
	GEM_BUG_ON(drm_mm_node_allocated(node));

	if (!size)
		return 0;

	if (size > ggtt->vm.total)
		return -E2BIG;

	mutex_lock(&ggtt->vm.mutex);
	err = i915_gem_gtt_insert(&ggtt->vm, node, size, alignment,
		I915_COLOR_UNEVICTABLE,
		ggtt->pin_bias, GUC_GGTT_TOP,
		PIN_HIGH);
	mutex_unlock(&ggtt->vm.mutex);
	if (unlikely(err))
		return err;

	IOV_DEBUG(iov, "VF%u provisioned GGTT %llx-%llx (%lluK)\n",
		  id, node->start, node->start + node->size - 1, node->size / SZ_1K);
	return 0;
}

/**
 * intel_iov_provisioning_set_ggtt - Provision VF with GGTT.
 * @iov: the IOV struct
 * @id: VF identifier
 * @size: requested GGTT size
 *
 * This function can only be called on PF.
 */
int intel_iov_provisioning_set_ggtt(struct intel_iov *iov, unsigned int id, u64 size)
{
	struct intel_runtime_pm *rpm = iov_to_gt(iov)->uncore->rpm;
	intel_wakeref_t wakeref;
	int err = -ENONET;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));
	GEM_BUG_ON(id == PFID);

	mutex_lock(pf_provisioning_mutex(iov));

	with_intel_runtime_pm(rpm, wakeref)
		err = pf_provision_ggtt(iov, id, size);

	if (unlikely(err))
		IOV_ERROR(iov, "Failed to provision VF%u with %llu of GGTT (%pe)\n",
			  id, size, ERR_PTR(err));

	mutex_unlock(pf_provisioning_mutex(iov));
	return err;
}

/**
 * intel_iov_provisioning_get_ggtt - Query size of GGTT provisioned for VF.
 * @iov: the IOV struct
 * @id: VF identifier
 *
 * This function can only be called on PF.
 */
u64 intel_iov_provisioning_get_ggtt(struct intel_iov *iov, unsigned int id)
{
	struct intel_iov_provisioning *provisioning = &iov->pf.provisioning;
	struct drm_mm_node *node = &provisioning->configs[id].ggtt_region;
	u64 size;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));
	GEM_BUG_ON(id == PFID);

	mutex_lock(pf_provisioning_mutex(iov));
	size = drm_mm_node_allocated(node) ? node->size : 0;
	mutex_unlock(pf_provisioning_mutex(iov));

	return size;
}
