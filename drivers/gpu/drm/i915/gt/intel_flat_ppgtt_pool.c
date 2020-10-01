// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include "gem/i915_gem_internal.h"
#include "gem/i915_gem_object.h"

#include "i915_drv.h"
#include "intel_flat_ppgtt_pool.h"

void intel_flat_ppgtt_pool_fini(struct intel_flat_ppgtt_pool *fpp)
{
	struct intel_gt *gt = container_of(fpp, struct intel_gt, fpp);
	struct intel_pte_bo *item, *temp;

	gt->i915->bind_ctxt_ready = false;

	list_for_each_entry_safe(item, temp, &fpp->free_list, link) {
		i915_vma_unpin_and_release(&item->vma, I915_VMA_RELEASE_MAP);
		kfree(item);
	}
	INIT_LIST_HEAD(&fpp->free_list);

	/*
	 * Flush the i915 wq to ensure objects freed from above unpin on vm are
	 * all freed to avoid the race with below remove node which is called
	 * without any locking.
	 */
	i915_gem_drain_freed_objects(gt->i915);
}

int intel_flat_ppgtt_pool_init(struct intel_flat_ppgtt_pool *fpp,
			       struct i915_address_space *vm)
{
	struct intel_gt *gt = container_of(fpp, struct intel_gt, fpp);
	struct drm_i915_gem_object *obj;
	struct intel_pte_bo *item;
	int i, ret;

	if (!i915_is_mem_wa_enabled(gt->i915, I915_WA_USE_FLAT_PPGTT_UPDATE))
		return 0;

	for (i = 0; i < INTEL_FLAT_PPGTT_MAX_PINNED_OBJS; i++) {
		item = kmalloc(sizeof(*item), GFP_KERNEL);
		if (!item) {
			ret = -ENOMEM;
			goto err;
		}

		obj = i915_gem_object_create_internal(gt->i915,
						      INTEL_FLAT_PPGTT_BB_OBJ_SIZE);
		if (IS_ERR(obj)) {
			ret = PTR_ERR(obj);
			goto err_item;
		}

		item->vma = i915_vma_instance(obj, vm, NULL);
		if (IS_ERR(item->vma)) {
			ret = PTR_ERR(item->vma);
			goto err_obj;
		}

		item->cmd = i915_gem_object_pin_map_unlocked(obj, I915_MAP_WC);
		if (IS_ERR(item->cmd)) {
			ret = PTR_ERR(item->cmd);
			goto err_obj;
		}

		ret = i915_vma_pin(item->vma, 0, 0, PIN_USER);
		if (ret)
			goto err_map;

		list_add(&item->link, &fpp->free_list);
	}

	drm_info(&gt->i915->drm, "Using level-4 WA gt %d\n", gt->info.id);
	return 0;

err_map:
	i915_gem_object_unpin_map(obj);
err_obj:
	i915_gem_object_put(obj);
err_item:
	kfree(item);
err:
	intel_flat_ppgtt_pool_fini(fpp);
	return ret;
}

void intel_flat_ppgtt_pool_init_early(struct intel_flat_ppgtt_pool *fpp)
{
	init_waitqueue_head(&fpp->bind_wq);
	INIT_LIST_HEAD(&fpp->free_list);
}
