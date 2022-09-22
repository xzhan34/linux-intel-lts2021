// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */

#include "intel_iov.h"
#include "intel_iov_provisioning.h"
#include "intel_iov_utils.h"
#include "gt/uc/abi/guc_actions_pf_abi.h"
#include "gt/uc/abi/guc_klvs_abi.h"

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

/*
 * Return: number of klvs that were successfully parsed and saved,
 *         negative error code on failure.
 */
static int guc_action_update_vf_cfg(struct intel_guc *guc, u32 vfid,
				    u64 addr, u32 size)
{
	u32 request[] = {
		GUC_ACTION_PF2GUC_UPDATE_VF_CFG,
		vfid,
		lower_32_bits(addr),
		upper_32_bits(addr),
		size,
	};

	return intel_guc_send(guc, request, ARRAY_SIZE(request));
}

/*
 * Return: 0 on success, -ENOKEY if klv was not parsed, -EPROTO if reply was malformed,
 *         negative error code on failure.
 */
static int guc_update_vf_klv32(struct intel_guc *guc, u32 vfid, u16 key, u32 value)
{
	const u32 len = 1; /* 32bit value fits into 1 klv dword */
	const u32 cfg_size = (GUC_KLV_LEN_MIN + len);
	struct i915_vma *vma;
	u32 *cfg;
	int ret;

	ret = intel_guc_allocate_and_map_vma(guc, cfg_size * sizeof(u32), &vma, (void **)&cfg);
	if (unlikely(ret))
		return ret;

	*cfg++ = FIELD_PREP(GUC_KLV_0_KEY, key) | FIELD_PREP(GUC_KLV_0_LEN, len);
	*cfg++ = value;

	ret = guc_action_update_vf_cfg(guc, vfid, intel_guc_ggtt_offset(guc, vma), cfg_size);

	i915_vma_unpin_and_release(&vma, I915_VMA_RELEASE_MAP);

	if (unlikely(ret < 0))
		return ret;
	if (unlikely(!ret))
		return -ENOKEY;
	if (unlikely(ret > 1))
		return -EPROTO;

	return 0;
}

static u64 pf_get_ggtt_alignment(struct intel_iov *iov)
{
	/* this might be platform dependent */
	return SZ_4K;
}

static u64 pf_get_min_spare_ggtt(struct intel_iov *iov)
{
	/* this might be platform dependent */
	return SZ_64M; /* XXX: preliminary */
}

static u64 pf_get_spare_ggtt(struct intel_iov *iov)
{
	u64 spare;

	spare = iov->pf.provisioning.spare.ggtt_size;
	spare = max_t(u64, spare, pf_get_min_spare_ggtt(iov));

	return spare;
}

/**
 * intel_iov_provisioning_set_spare_ggtt - Set size of the PF spare GGTT.
 * @iov: the IOV struct
 *
 * This function can only be called on PF.
 */
int intel_iov_provisioning_set_spare_ggtt(struct intel_iov *iov, u64 size)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));

	if (size && size < pf_get_min_spare_ggtt(iov))
		return -EINVAL;

	if (check_round_up_overflow(size, pf_get_ggtt_alignment(iov), &size))
		size = U64_MAX;

	mutex_lock(pf_provisioning_mutex(iov));
	iov->pf.provisioning.spare.ggtt_size = size;
	mutex_unlock(pf_provisioning_mutex(iov));

	return 0;
}

/**
 * intel_iov_provisioning_get_spare_ggtt - Get size of the PF spare GGTT.
 * @iov: the IOV struct
 *
 * This function can only be called on PF.
 */
u64 intel_iov_provisioning_get_spare_ggtt(struct intel_iov *iov)
{
	u64 spare;

	GEM_BUG_ON(!intel_iov_is_pf(iov));

	mutex_lock(pf_provisioning_mutex(iov));
	spare = pf_get_spare_ggtt(iov);
	mutex_unlock(pf_provisioning_mutex(iov));

	return spare;
}

static bool pf_is_valid_config_ggtt(struct intel_iov *iov, unsigned int id)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));
	lockdep_assert_held(pf_provisioning_mutex(iov));

	return drm_mm_node_allocated(&iov->pf.provisioning.configs[id].ggtt_region);
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

static u16 pf_get_min_spare_ctxs(struct intel_iov *iov)
{
	return SZ_256;
}

static u16 pf_get_spare_ctxs(struct intel_iov *iov)
{
	u16 spare;

	spare = iov->pf.provisioning.spare.num_ctxs;
	spare = max_t(u16, spare, pf_get_min_spare_ctxs(iov));

	return spare;
}

/**
 * intel_iov_provisioning_get_spare_ctxs - Get number of the PF's spare contexts.
 * @iov: the IOV struct
 *
 * This function can only be called on PF.
 */
u16 intel_iov_provisioning_get_spare_ctxs(struct intel_iov *iov)
{
	u16 spare;

	GEM_BUG_ON(!intel_iov_is_pf(iov));

	mutex_lock(pf_provisioning_mutex(iov));
	spare = pf_get_spare_ctxs(iov);
	mutex_unlock(pf_provisioning_mutex(iov));

	return spare;
}

/**
 * intel_iov_provisioning_set_spare_ctxs - Set number of the PF's spare contexts.
 * @iov: the IOV struct
 *
 * This function can only be called on PF.
 */
int intel_iov_provisioning_set_spare_ctxs(struct intel_iov *iov, u16 spare)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));

	if (spare > GUC_MAX_CONTEXT_ID)
		return -EINVAL;

	if (spare && spare < pf_get_min_spare_ctxs(iov))
		return -EINVAL;

	mutex_lock(pf_provisioning_mutex(iov));
	iov->pf.provisioning.spare.num_ctxs = spare;
	mutex_unlock(pf_provisioning_mutex(iov));

	return 0;
}

static bool pf_is_valid_config_ctxs(struct intel_iov *iov, unsigned int id)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));
	lockdep_assert_held(pf_provisioning_mutex(iov));

	return iov->pf.provisioning.configs[id].num_ctxs;
}

/*
 * To facilitate the implementation of dynamic context provisioning, we introduced
 * the concept of granularity of contexts. For this purpose, we divided all contexts
 * into packages with size CTXS_GRANULARITY. The exception is the first package, whose
 * size is CTXS_MODULO, because GUC_MAX_CONTEXT_ID is an odd number.
 */
#define CTXS_GRANULARITY 128
#define CTXS_MODULO (GUC_MAX_CONTEXT_ID % CTXS_GRANULARITY)
#define CTXS_DELTA (CTXS_GRANULARITY - CTXS_MODULO)

static u16 ctxs_bitmap_total_bits(void)
{
	return ALIGN(GUC_MAX_CONTEXT_ID, CTXS_GRANULARITY) / CTXS_GRANULARITY;
}

static u16 __encode_ctxs_count(u16 num_ctxs, bool first)
{
	GEM_BUG_ON(!first && !IS_ALIGNED(num_ctxs, CTXS_GRANULARITY));
	GEM_BUG_ON(first && !IS_ALIGNED(num_ctxs + CTXS_DELTA, CTXS_GRANULARITY));

	return (!first) ? num_ctxs / CTXS_GRANULARITY :
			  (num_ctxs + CTXS_DELTA) / CTXS_GRANULARITY;
}

static u16 encode_vf_ctxs_count(u16 num_ctxs)
{
	return __encode_ctxs_count(num_ctxs, false);
}

static u16 __encode_ctxs_start(u16 start_ctx, bool first)
{
	if (!start_ctx)
		return 0;

	GEM_BUG_ON(!first && !IS_ALIGNED(start_ctx + CTXS_DELTA, CTXS_GRANULARITY));
	GEM_BUG_ON(first && start_ctx);

	return (!first) ? (start_ctx + CTXS_DELTA) / CTXS_GRANULARITY : 0;
}

static u16 __decode_ctxs_start(u16 start_bit, bool first)
{
	GEM_BUG_ON(first && start_bit);

	return (!first) ? start_bit * CTXS_GRANULARITY - CTXS_DELTA : 0;
}

static u16 decode_vf_ctxs_start(u16 start_bit)
{
	return __decode_ctxs_start(start_bit, false);
}

static u16 pf_get_ctxs_quota(struct intel_iov *iov, unsigned int id)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));
	lockdep_assert_held(pf_provisioning_mutex(iov));

	return iov->pf.provisioning.configs[id].num_ctxs;
}

static u16 align_ctxs(unsigned int id, u16 num_ctxs)
{
	if (num_ctxs == 0)
		return 0;

	num_ctxs = ALIGN(num_ctxs, CTXS_GRANULARITY);
	return id ? num_ctxs : num_ctxs - CTXS_DELTA;
}

static unsigned long *pf_get_ctxs_bitmap(struct intel_iov *iov)
{
	struct intel_iov_provisioning *provisioning = &iov->pf.provisioning;
	unsigned int id, total_vfs = pf_get_totalvfs(iov);
	const u16 total_bits = ctxs_bitmap_total_bits();
	unsigned long *ctxs_bitmap = bitmap_zalloc(total_bits, GFP_KERNEL);

	if (unlikely(!ctxs_bitmap))
		return NULL;

	for (id = 0; id <= total_vfs; id++) {
		struct intel_iov_config *config = &provisioning->configs[id];

		if (!config->num_ctxs)
			continue;

		bitmap_set(ctxs_bitmap, __encode_ctxs_start(config->begin_ctx, !id),
			   __encode_ctxs_count(config->num_ctxs, !id));
	}

	/* caller must use bitmap_free */
	return ctxs_bitmap;
}

static int pf_alloc_vf_ctxs_range(struct intel_iov *iov, unsigned int id, u16 num_ctxs)
{
	unsigned long *ctxs_bitmap = pf_get_ctxs_bitmap(iov);
	u16 num_bits = encode_vf_ctxs_count(num_ctxs);
	u16 max_size = U16_MAX;
	u16 index = U16_MAX;
	u16 last_equal = 0;
	unsigned int rs, re;

	if (unlikely(!ctxs_bitmap))
		return -ENOMEM;

	GEM_BUG_ON(!intel_iov_is_pf(iov));

	bitmap_for_each_clear_region(ctxs_bitmap, rs, re, 0, ctxs_bitmap_total_bits()) {
		u16 size_bits = re - rs;

		/*
		 * The best-fit hole would be one that was as close to the end as possible and
		 * equal to the number of contexts searched.
		 * Second, we look for a hole that is as small as possible but larger than
		 * the required size
		 *
		 */
		if (size_bits == num_bits) {
			last_equal = rs;
		} else if (size_bits > num_bits && num_bits < max_size) {
			index = re - num_bits;
			max_size = size_bits;
		}
	}

	bitmap_free(ctxs_bitmap);

	if (last_equal != 0)
		index = last_equal;

	if (index >= U16_MAX)
		return -ENOSPC;

	return decode_vf_ctxs_start(index);
}

static int pf_alloc_ctxs_range(struct intel_iov *iov, unsigned int id, u16 num_ctxs)
{
	int ret;

	ret = pf_alloc_vf_ctxs_range(iov, id, num_ctxs);

	if (ret >= 0)
		IOV_DEBUG(iov, "ctxs found %u-%u (%u)\n", ret, ret + num_ctxs - 1, num_ctxs);

	return ret;
}

static int __pf_provision_vf_ctxs(struct intel_iov *iov, unsigned int id, u16 start_ctx, u16 num_ctxs)
{
	struct intel_iov_config *config = &iov->pf.provisioning.configs[id];

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id == PFID);
	lockdep_assert_held(pf_provisioning_mutex(iov));

	config->begin_ctx = start_ctx;
	config->num_ctxs = num_ctxs;

	return 0;
}

static int __pf_provision_ctxs(struct intel_iov *iov, unsigned int id, u16 start_ctx, u16 num_ctxs)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));

	return __pf_provision_vf_ctxs(iov, id, start_ctx, num_ctxs);
}

static int pf_provision_ctxs(struct intel_iov *iov, unsigned int id, u16 num_ctxs)
{
	u16 ctxs_quota = align_ctxs(id, num_ctxs);
	int ret;

	GEM_BUG_ON(!intel_iov_is_pf(iov));

	if (id == PFID)
		return -EOPNOTSUPP;

	if (ctxs_quota == pf_get_ctxs_quota(iov, id))
		return 0;

	IOV_DEBUG(iov, "provisioning VF%u with %hu contexts (aligned to %hu)\n",
		  id, num_ctxs, ctxs_quota);

	ret = __pf_provision_ctxs(iov, id, 0, 0);
	if (!num_ctxs || ret)
		return ret;

	ret = pf_alloc_ctxs_range(iov, id, ctxs_quota);
	if (ret >= 0)
		return __pf_provision_ctxs(iov, id, ret, ctxs_quota);

	return ret;
}

/**
 * intel_iov_provisioning_set_ctxs - Provision VF with contexts.
 * @iov: the IOV struct
 * @id: VF identifier
 * @num_ctxs: requested contexts
 *
 * This function can only be called on PF.
 */
int intel_iov_provisioning_set_ctxs(struct intel_iov *iov, unsigned int id, u16 num_ctxs)
{
	struct intel_runtime_pm *rpm = iov_to_gt(iov)->uncore->rpm;
	intel_wakeref_t wakeref;
	int err = -ENONET;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));

	mutex_lock(pf_provisioning_mutex(iov));

	with_intel_runtime_pm(rpm, wakeref)
		err = pf_provision_ctxs(iov, id, num_ctxs);

	if (unlikely(err))
		IOV_ERROR(iov, "Failed to provision VF%u with %hu contexts (%pe)\n",
			  id, num_ctxs, ERR_PTR(err));

	mutex_unlock(pf_provisioning_mutex(iov));
	return err;
}

/**
 * intel_iov_provisioning_get_ctxs - Get VF contexts quota.
 * @iov: the IOV struct
 * @id: VF identifier
 *
 * This function can only be called on PF.
 */
u16 intel_iov_provisioning_get_ctxs(struct intel_iov *iov, unsigned int id)
{
	u16 num_ctxs;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));

	mutex_lock(pf_provisioning_mutex(iov));
	num_ctxs = pf_get_ctxs_quota(iov, id);
	mutex_unlock(pf_provisioning_mutex(iov));

	return num_ctxs;
}

static u16 pf_get_min_spare_dbs(struct intel_iov *iov)
{
	/* we don't use doorbells yet */
	return 0;
}

static u16 pf_get_spare_dbs(struct intel_iov *iov)
{
	u16 spare;

	spare = iov->pf.provisioning.spare.num_dbs;
	spare = max_t(u16, spare, pf_get_min_spare_dbs(iov));

	return spare;
}

/**
 * intel_iov_provisioning_get_spare_dbs - Get number of the PF's spare doorbells.
 * @iov: the IOV struct
 *
 * This function can only be called on PF.
 */
u16 intel_iov_provisioning_get_spare_dbs(struct intel_iov *iov)
{
	u16 spare;

	GEM_BUG_ON(!intel_iov_is_pf(iov));

	mutex_lock(pf_provisioning_mutex(iov));
	spare = pf_get_spare_dbs(iov);
	mutex_unlock(pf_provisioning_mutex(iov));

	return spare;
}

/**
 * intel_iov_provisioning_set_spare_dbs - Set number of the PF's spare doorbells.
 * @iov: the IOV struct
 *
 * This function can only be called on PF.
 */
int intel_iov_provisioning_set_spare_dbs(struct intel_iov *iov, u16 spare)
{
	GEM_BUG_ON(!intel_iov_is_pf(iov));

	if (spare > GUC_NUM_DOORBELLS)
		return -EINVAL;

	if (spare && spare < pf_get_min_spare_dbs(iov))
		return -EINVAL;

	mutex_lock(pf_provisioning_mutex(iov));
	iov->pf.provisioning.spare.num_dbs = spare;
	mutex_unlock(pf_provisioning_mutex(iov));

	return 0;
}

static unsigned long *pf_get_dbs_bitmap(struct intel_iov *iov)
{
	unsigned long *dbs_bitmap = bitmap_zalloc(GUC_NUM_DOORBELLS, GFP_KERNEL);
	struct intel_iov_provisioning *provisioning = &iov->pf.provisioning;
	unsigned int n, total_vfs = pf_get_totalvfs(iov);
	struct intel_iov_config *config;

	lockdep_assert_held(pf_provisioning_mutex(iov));

	if (unlikely(!dbs_bitmap))
		return NULL;

	/* don't count PF here, we will treat it differently */
	for (n = 1; n <= total_vfs; n++) {
		config = &provisioning->configs[n];
		if (!config->num_dbs)
			continue;
		bitmap_set(dbs_bitmap, config->begin_db, config->num_dbs);
	}

	/* caller must use bitmap_free */
	return dbs_bitmap;
}

static int pf_alloc_dbs_range(struct intel_iov *iov, u16 num_dbs)
{
	unsigned long *dbs_bitmap = pf_get_dbs_bitmap(iov);
	unsigned long index;

	if (unlikely(!dbs_bitmap))
		return -ENOMEM;

	index = bitmap_find_next_zero_area(dbs_bitmap, GUC_NUM_DOORBELLS, 0, num_dbs, 0);
	bitmap_free(dbs_bitmap);

	if (index >= GUC_NUM_DOORBELLS)
		return -ENOSPC;

	IOV_DEBUG(iov, "dbs found %lu-%lu (%u)\n",
		  index, index + num_dbs - 1, num_dbs);
	return index;
}

static int pf_provision_dbs(struct intel_iov *iov, unsigned int id, u16 num_dbs)
{
	struct intel_iov_provisioning *provisioning = &iov->pf.provisioning;
	struct intel_iov_config *config = &provisioning->configs[id];
	int ret;

	lockdep_assert_held(pf_provisioning_mutex(iov));

	if (num_dbs == config->num_dbs)
		return 0;

	IOV_DEBUG(iov, "provisioning VF%u with %hu doorbells\n", id, num_dbs);

	if (config->num_dbs) {
		config->begin_db = 0;
		config->num_dbs = 0;
	}

	if (!num_dbs)
		return 0;

	ret = pf_alloc_dbs_range(iov, num_dbs);
	if (unlikely(ret < 0))
		return ret;

	config->begin_db = ret;
	config->num_dbs = num_dbs;

	return 0;
}

/**
 * intel_iov_provisioning_set_dbs - Set VF doorbells quota.
 * @iov: the IOV struct
 * @id: VF identifier
 * @num_dbs: requested doorbells
 *
 * This function can only be called on PF.
 */
int intel_iov_provisioning_set_dbs(struct intel_iov *iov, unsigned int id, u16 num_dbs)
{
	struct intel_runtime_pm *rpm = iov_to_gt(iov)->uncore->rpm;
	intel_wakeref_t wakeref;
	int err = -ENONET;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));

	mutex_lock(pf_provisioning_mutex(iov));

	with_intel_runtime_pm(rpm, wakeref)
		err = pf_provision_dbs(iov, id, num_dbs);

	if (unlikely(err))
		IOV_ERROR(iov, "Failed to provision VF%u with %hu doorbells (%pe)\n",
			  id, num_dbs, ERR_PTR(err));

	mutex_unlock(pf_provisioning_mutex(iov));
	return err;
}

/**
 * intel_iov_provisioning_get_dbs - Get VF doorbells quota.
 * @iov: the IOV struct
 * @id: VF identifier
 *
 * This function can only be called on PF.
 */
u16 intel_iov_provisioning_get_dbs(struct intel_iov *iov, unsigned int id)
{
	u16 num_dbs;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));

	mutex_lock(pf_provisioning_mutex(iov));
	num_dbs = iov->pf.provisioning.configs[id].num_dbs;
	mutex_unlock(pf_provisioning_mutex(iov));

	return num_dbs;
}

static const char* exec_quantum_unit(u32 exec_quantum)
{
	return exec_quantum ? "ms" : "(inifinity)";
}

static int pf_provision_exec_quantum(struct intel_iov *iov, unsigned int id,
				     u32 exec_quantum)
{
	struct intel_iov_provisioning *provisioning = &iov->pf.provisioning;
	struct intel_iov_config *config = &provisioning->configs[id];
	int err;

	lockdep_assert_held(pf_provisioning_mutex(iov));

	if (exec_quantum == config->exec_quantum)
		return 0;

	err = guc_update_vf_klv32(iov_to_guc(iov), id,
				  GUC_KLV_VF_CFG_EXEC_QUANTUM_KEY, exec_quantum);
	if (unlikely(err))
		return err;

	config->exec_quantum = exec_quantum;

	IOV_DEBUG(iov, "VF%u provisioned with %u%s execution quantum\n",
		  id, exec_quantum, exec_quantum_unit(exec_quantum));
	return 0;
}

/**
 * intel_iov_provisioning_set_exec_quantum - Provision VF with execution quantum.
 * @iov: the IOV struct
 * @id: VF identifier
 * @exec_quantum: requested execution quantum
 *
 * This function can only be called on PF.
 */
int intel_iov_provisioning_set_exec_quantum(struct intel_iov *iov, unsigned int id,
					    u32 exec_quantum)
{
	struct intel_runtime_pm *rpm = iov_to_gt(iov)->uncore->rpm;
	intel_wakeref_t wakeref;
	int err = -ENONET;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));

	mutex_lock(pf_provisioning_mutex(iov));

	with_intel_runtime_pm(rpm, wakeref)
		err = pf_provision_exec_quantum(iov, id, exec_quantum);

	if (unlikely(err))
		IOV_ERROR(iov, "Failed to provision VF%u with %u%s execution quantum (%pe)\n",
			  id, exec_quantum, exec_quantum_unit(exec_quantum), ERR_PTR(err));

	mutex_unlock(pf_provisioning_mutex(iov));
	return err;
}

/**
 * intel_iov_provisioning_get_exec_quantum - Get VF execution quantum.
 * @iov: the IOV struct
 * @id: VF identifier
 *
 * This function can only be called on PF.
 */
u32 intel_iov_provisioning_get_exec_quantum(struct intel_iov *iov, unsigned int id)
{
	u32 exec_quantum;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));

	mutex_lock(pf_provisioning_mutex(iov));
	exec_quantum = iov->pf.provisioning.configs[id].exec_quantum;
	mutex_unlock(pf_provisioning_mutex(iov));

	return exec_quantum;
}

static const char* preempt_timeout_unit(u32 preempt_timeout)
{
	return preempt_timeout ? "us" : "(inifinity)";
}

static int pf_provision_preempt_timeout(struct intel_iov *iov, unsigned int id,
					u32 preempt_timeout)
{
	struct intel_iov_provisioning *provisioning = &iov->pf.provisioning;
	struct intel_iov_config *config = &provisioning->configs[id];
	int err;

	lockdep_assert_held(pf_provisioning_mutex(iov));

	if (preempt_timeout == config->preempt_timeout)
		return 0;

	err = guc_update_vf_klv32(iov_to_guc(iov), id,
				  GUC_KLV_VF_CFG_PREEMPT_TIMEOUT_KEY,
				  preempt_timeout);
	if (unlikely(err))
		return err;

	config->preempt_timeout = preempt_timeout;

	IOV_DEBUG(iov, "VF%u provisioned with %u%s preemption timeout\n",
		  id, preempt_timeout, preempt_timeout_unit(preempt_timeout));
	return 0;
}

/**
 * intel_iov_provisioning_set_preempt_timeout - Provision VF with preemption timeout.
 * @iov: the IOV struct
 * @id: VF identifier
 * @preempt_timeout: requested preemption timeout
 */
int intel_iov_provisioning_set_preempt_timeout(struct intel_iov *iov, unsigned int id, u32 preempt_timeout)
{
	struct intel_runtime_pm *rpm = iov_to_gt(iov)->uncore->rpm;
	intel_wakeref_t wakeref;
	int err = -ENONET;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));

	mutex_lock(pf_provisioning_mutex(iov));

	with_intel_runtime_pm(rpm, wakeref)
		err = pf_provision_preempt_timeout(iov, id, preempt_timeout);

	if (unlikely(err))
		IOV_ERROR(iov, "Failed to provision VF%u with %u%s preemption timeout (%pe)\n",
			  id, preempt_timeout, preempt_timeout_unit(preempt_timeout), ERR_PTR(err));

	mutex_unlock(pf_provisioning_mutex(iov));
	return err;
}

/**
 * intel_iov_provisioning_get_preempt_timeout - Get VF preemption timeout.
 * @iov: the IOV struct
 * @id: VF identifier
 *
 * This function can only be called on PF.
 */
u32 intel_iov_provisioning_get_preempt_timeout(struct intel_iov *iov, unsigned int id)
{
	u32 preempt_timeout;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(id > pf_get_totalvfs(iov));

	mutex_lock(pf_provisioning_mutex(iov));
	preempt_timeout = iov->pf.provisioning.configs[id].preempt_timeout;
	mutex_unlock(pf_provisioning_mutex(iov));

	return preempt_timeout;
}

static int pf_validate_config(struct intel_iov *iov, unsigned int id)
{
	bool valid_ggtt = pf_is_valid_config_ggtt(iov, id);
	bool valid_ctxs = pf_is_valid_config_ctxs(iov, id);
	bool valid_any = valid_ggtt || valid_ctxs;
	bool valid_all = valid_ggtt && valid_ctxs;

	if (!valid_all) {
		IOV_DEBUG(iov, "%u: invalid config: %s%s\n", id,
			  valid_ggtt ? "" : "GGTT ",
			  valid_ctxs ? "" : "contexts ");
		return valid_any ? -ENOKEY : -ENODATA;
	}

	return 0;
}

/**
 * intel_iov_provisioning_verify() - TBD
 * @iov: the IOV struct
 * @num_vfs: number of VFs configurations to verify
 *
 * Verify that VFs configurations are valid.
 *
 * This function shall be called only on PF.
 *
 * Return: 0 on success or a negative error code on failure.
 */
int intel_iov_provisioning_verify(struct intel_iov *iov, unsigned int num_vfs)
{
	unsigned int num_empty = 0;
	unsigned int num_valid = 0;
	unsigned int n;
	int err;

	GEM_BUG_ON(!intel_iov_is_pf(iov));
	GEM_BUG_ON(num_vfs > pf_get_totalvfs(iov));
	GEM_BUG_ON(num_vfs < 1);

	mutex_lock(pf_provisioning_mutex(iov));

	for (n = 1; n <= num_vfs; n++) {
		err = pf_validate_config(iov, n);
		if (!err)
			num_valid++;
		else if (err == -ENODATA)
			num_empty++;
	}

	mutex_unlock(pf_provisioning_mutex(iov));

	IOV_DEBUG(iov, "found valid(%u) invalid(%u) empty(%u) configs\n",
		  num_valid, num_vfs - num_valid, num_empty);

	if (num_empty == num_vfs)
		return -ENODATA;

	if (num_valid + num_empty != num_vfs)
		return -ENOKEY;

	return 0;
}
