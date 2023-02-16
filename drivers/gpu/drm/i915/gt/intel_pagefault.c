// SPDX-License-Identifier: MIT
/*
 * Copyright © 2022 Intel Corporation
 */
#include "gem/i915_gem_lmem.h"
#include "gem/i915_gem_mman.h"
#include "gem/i915_gem_userptr.h"

#include "i915_drv.h"
#include "i915_trace.h"

#include "gen8_ppgtt.h"
#include "intel_context.h"
#include "intel_engine_heartbeat.h"
#include "intel_gt.h"
#include "intel_gt_debug.h"
#include "intel_gt_mcr.h"
#include "intel_gt_regs.h"
#include "intel_tlb.h"
#include "intel_pagefault.h"
#include "uc/intel_guc.h"
#include "uc/intel_guc_fwif.h"

struct recoverable_page_fault_info {
       u64 page_addr;
       u32 asid;
       u16 pdata;
       u8 vfid;
       u8 access_type;
       u8 fault_type;
       u8 fault_level;
       u8 engine_class;
       u8 engine_instance;
       u8 fault_unsuccessful;
};

enum access_type {
	ACCESS_TYPE_READ = 0,
	ACCESS_TYPE_WRITE = 1,
	ACCESS_TYPE_ATOMIC = 2,
	ACCESS_TYPE_RESERVED = 3,
};

void intel_gt_pagefault_process_cat_error_msg(struct intel_gt *gt, u32 guc_ctx_id)
{
	struct drm_device *drm = &gt->i915->drm;
	struct intel_guc *guc = &gt->uc.guc;
	struct intel_context *ce;
	char buf[11];

	ce = xa_load(&guc->context_lookup, guc_ctx_id);
	if (ce) {
		snprintf(buf, sizeof(buf), "%#04x", guc_ctx_id);
		intel_context_ban(ce, NULL);
	} else {
		snprintf(buf, sizeof(buf), "n/a");
	}

	trace_intel_gt_cat_error(gt, buf);

	drm_err(drm, "GPU catastrophic memory error. GT: %d, GuC context: %s\n", gt->info.id, buf);
}

static u64 fault_va(u32 fault_data1, u32 fault_data0)
{
	return ((u64)(fault_data1 & FAULT_VA_HIGH_BITS) << GEN12_FAULT_VA_HIGH_SHIFT) |
	       ((u64)fault_data0 << GEN12_FAULT_VA_LOW_SHIFT);
}

int intel_gt_pagefault_process_page_fault_msg(struct intel_gt *gt, const u32 *msg, u32 len)
{
	struct drm_i915_private *i915 = gt->i915;
	u64 address;
	u32 fault_reg, fault_data0, fault_data1;

	if (GRAPHICS_VER(i915) < 12)
		return -EPROTO;

	if (len != GUC2HOST_NOTIFY_PAGE_FAULT_MSG_LEN)
		return -EPROTO;

	if (FIELD_GET(GUC2HOST_NOTIFY_PAGE_FAULT_MSG_0_MBZ, msg[0]) != 0)
		return -EPROTO;

	fault_reg = FIELD_GET(GUC2HOST_NOTIFY_PAGE_FAULT_MSG_1_ALL_ENGINE_FAULT_REG, msg[1]);
	fault_data0 = FIELD_GET(GUC2HOST_NOTIFY_PAGE_FAULT_MSG_2_FAULT_TLB_RD_DATA0, msg[2]);
	fault_data1 = FIELD_GET(GUC2HOST_NOTIFY_PAGE_FAULT_MSG_3_FAULT_TLB_RD_DATA1, msg[3]);

	address = fault_va(fault_data1, fault_data0);

	trace_intel_gt_pagefault(gt, address, fault_reg, fault_data1 & FAULT_GTT_SEL);

	drm_err(&i915->drm, "Unexpected fault\n"
			    "\tGT: %d\n"
			    "\tAddr: 0x%llx\n"
			    "\tAddress space%s\n"
			    "\tEngine ID: %u\n"
			    "\tSource ID: %u\n"
			    "\tType: %u\n"
			    "\tFault Level: %u\n"
			    "\tAccess type: %s\n",
			    gt->info.id,
			    address,
			    fault_data1 & FAULT_GTT_SEL ? "GGTT" : "PPGTT",
			    GEN8_RING_FAULT_ENGINE_ID(fault_reg),
			    RING_FAULT_SRCID(fault_reg),
			    RING_FAULT_FAULT_TYPE(fault_reg),
			    RING_FAULT_LEVEL(fault_reg),
			    !!(fault_reg & RING_FAULT_ACCESS_TYPE) ? "Write" : "Read");

	return 0;
}

static void print_recoverable_fault(struct recoverable_page_fault_info *info)
{
	/*XXX: Move to trace_printk */
	DRM_DEBUG_DRIVER("\n\tASID: %d\n"
			 "\tVFID: %d\n"
			 "\tPDATA: 0x%04x\n"
			 "\tFaulted Address: 0x%08x_%08x\n"
			 "\tFaultType: %d\n"
			 "\tAccessType: %d\n"
			 "\tFaultLevel: %d\n"
			 "\tEngineClass: %d\n"
			 "\tEngineInstance: %d\n",
			 info->asid,
			 info->vfid,
			 info->pdata,
			 upper_32_bits(info->page_addr),
			 lower_32_bits(info->page_addr),
			 info->fault_type,
			 info->access_type,
			 info->fault_level,
			 info->engine_class,
			 info->engine_instance);
}

static bool userptr_needs_rebind(struct drm_i915_gem_object *obj)
{
	struct drm_i915_private *i915 = to_i915(obj->base.dev);
	bool ret = false;

	if (!i915_gem_object_is_userptr(obj))
		return ret;
	i915_gem_userptr_lock_mmu_notifier(i915);
	if (i915_gem_object_userptr_submit_done(obj))
		ret = true;
	i915_gem_userptr_unlock_mmu_notifier(i915);
	return ret;
}

static int migrate_to_lmem(struct drm_i915_gem_object *obj,
			   struct intel_gt *gt,
			   enum intel_region_id lmem_id,
			   struct i915_gem_ww_ctx *ww)
{
	struct intel_context *ce;

	/* return if object has single placement or already in lmem_id */
	if (!i915_gem_object_migratable(obj) ||
	    obj->mm.region.mem->id == lmem_id)
		return 0;

	if (!gt->engine[BCS0])
		return -ENODEV;

	ce = gt->engine[BCS0]->blitter_context;

	/*
	 * FIXME: Move this to BUG_ON later when uapi enforces object alignment
	 * to 64K for objects that can reside on both SMEM and LMEM.
	 */
	if (HAS_64K_PAGES(gt->i915) &&
	    !IS_ALIGNED(obj->base.size, I915_GTT_PAGE_SIZE_64K)) {
		DRM_DEBUG_DRIVER("Cannot migrate objects of different page sizes\n");
		return -ENOTSUPP;
	}

	i915_gem_object_release_mmap(obj);
	GEM_BUG_ON(obj->mm.mapping);
	GEM_BUG_ON(obj->base.filp && mapping_mapped(obj->base.filp->f_mapping));

	return i915_gem_object_migrate(obj, ww, ce, lmem_id, true);
}

static inline bool access_is_atomic(struct recoverable_page_fault_info *info)
{
	return (info->access_type == ACCESS_TYPE_ATOMIC);
}

static enum intel_region_id get_lmem_region_id(struct drm_i915_gem_object *obj, struct intel_gt *gt)
{
	int i;

	if (obj->mm.preferred_region &&
	    obj->mm.preferred_region->type == INTEL_MEMORY_LOCAL)
		return obj->mm.preferred_region->id;

	if (BIT(gt->lmem->id) & obj->memory_mask)
		return gt->lmem->id;

	for (i = 0; i < obj->mm.n_placements; i++) {
		struct intel_memory_region *mr = obj->mm.placements[i];

		if (mr->type == INTEL_MEMORY_LOCAL)
			return mr->id;
	}

	return 0;
}

static int validate_fault(struct drm_i915_private *i915, struct i915_vma *vma,
			  struct recoverable_page_fault_info *info)
{
	/* combined access_type and fault_type */
	enum {
		FAULT_READ_NOT_PRESENT = 0x0,
		FAULT_WRITE_NOT_PRESENT = 0x1,
		FAULT_ATOMIC_NOT_PRESENT = 0x2,
		FAULT_WRITE_ACCESS_VIOLATION = 0x5,
		FAULT_ATOMIC_ACCESS_VIOLATION = 0xa,
	} err_code;
	int err = 0;

	err_code = (info->fault_type << 2) | info->access_type;

	switch (err_code & 0xF) {
	case FAULT_READ_NOT_PRESENT:
		break;
	case FAULT_WRITE_NOT_PRESENT:
		if (i915_gem_object_is_readonly(vma->obj)) {
			drm_err(&i915->drm, "Write Access Violation: read only\n");
			err = -EACCES;
		}
		break;
	case FAULT_ATOMIC_NOT_PRESENT:
		/*
		 * This case is early detection of ATOMIC ACCESS_VIOLATION.
		 *
		 * Imported (dma-buf) objects do not have a memory_mask (or
		 * placement list), so allow the NOT_PRESENT fault to proceed
		 * as we cannot test placement list.
		 * The replayed memory access will catch a true ATOMIC
		 * ACCESS_VIOLATION and fail appropriately.
		 */
		if (!vma->obj->memory_mask)
			break;
		fallthrough;
	case FAULT_ATOMIC_ACCESS_VIOLATION:
		if (!(vma->obj->memory_mask & REGION_LMEM_MASK)) {
			drm_err(&i915->drm, "Atomic Access Violation\n");
			err = -EACCES;
		}
		break;
	case FAULT_WRITE_ACCESS_VIOLATION:
		drm_err(&i915->drm, "Write Access Violation\n");
		err = -EACCES;
		break;
	default:
		drm_err(&i915->drm, "Undefined Fault Type\n");
		err = -EACCES;
		break;
	}

	return err;
}

static struct i915_address_space *faulted_vm(struct intel_guc *guc, u32 asid)
{
	if (GEM_WARN_ON(asid >= I915_MAX_ASID))
		return NULL;

	return xa_load(&guc_to_gt(guc)->i915->asid_resv.xa, asid);
}

static struct intel_engine_cs *
lookup_engine(struct intel_gt *gt, u8 class, u8 instance)
{
	if (class >= ARRAY_SIZE(gt->engine_class) ||
	    instance >= ARRAY_SIZE(gt->engine_class[class]))
		return NULL;

	return gt->engine_class[class][instance];
}

static void
mark_engine_as_active(struct intel_gt *gt,
		      int engine_class, int engine_instance)
{
	struct intel_engine_cs *engine;

	engine = lookup_engine(gt, engine_class, engine_instance);
	if (!engine)
		return;

	WRITE_ONCE(engine->stats.irq_count,
		   READ_ONCE(engine->stats.irq_count) + 1);
}

static struct i915_gpu_coredump *
pf_coredump(struct intel_gt *gt, struct recoverable_page_fault_info *info)
{
	struct i915_gpu_coredump *error;
	struct intel_engine_cs *engine;

	engine = lookup_engine(gt, info->engine_class, info->engine_instance);
	if (!engine)
		return NULL;
	GEM_BUG_ON(engine->gt != gt);

	error = i915_gpu_coredump_create_for_engine(engine, GFP_KERNEL);
	if (!error)
		return NULL;

	error->fault.addr = info->page_addr | BIT(0);
	error->fault.type = info->fault_type;
	error->fault.level = info->fault_level;
	error->fault.access = info->access_type;

	rcu_read_lock();
	error->private = intel_engine_find_active_request(engine);
	if (error->private)
		error->private = i915_request_get_rcu(error->private);
	rcu_read_unlock();

	return error;
}

static struct dma_fence *
handle_i915_mm_fault(struct intel_guc *guc,
		     struct recoverable_page_fault_info *info,
		     struct i915_gpu_coredump **dump)
{
	struct intel_gt *gt = guc_to_gt(guc);
	struct dma_fence *fence = NULL;
	struct i915_address_space *vm;
	enum intel_region_id lmem_id;
	struct i915_gem_ww_ctx ww;
	struct i915_vma *vma;
	int err = 0;

	vm = faulted_vm(guc, info->asid);
	/* The active context [asid] is protected while servicing a fault */
	if (GEM_WARN_ON(!vm))
		return ERR_PTR(-ENOENT);

	if (!i915_vm_page_fault_enabled(vm))
		return ERR_PTR(-ENOENT);

	vma = i915_find_vma(vm, info->page_addr);
	if (vma)
		vma = i915_vma_tryget(vma);
	if (!vma) {
		/* Each EU thread may trigger its own pf to the same address! */
		if (!vm->invalidate_tlb_scratch)
			*dump = pf_coredump(gt, info);

		if (vm->has_scratch) {
			/* Map the out-of-bound access to scratch page.
			 *
			 * Out-of-bound virtual address range is not tracked,
			 * so whenever we bind a new vma we do not know if it
			 * is replacing a scratch mapping, and so we must always
			 * flush the TLB of the vma's address range so that the
			 * next access will not load scratch. Set invalidate_tlb_scratch
			 * flag so we know on next vm_bind.
			 *
			 * This is an exceptional path to ease userspace development.
			 * Once user space fixes all the out-of-bound access, this
			 * logic will be removed.
			 */
			gen12_init_fault_scratch(vm,
						 info->page_addr,
						 BIT(vm->scratch_order + PAGE_SHIFT),
						 true);
			return NULL;
		}

		return ERR_PTR(-ENOENT);
	}

	mark_engine_as_active(gt, info->engine_class, info->engine_instance);

	err = validate_fault(gt->i915, vma, info);
	if (err)
		goto put_vma;

	/*
	 * With lots of concurrency to the same unbound VMA, HW will generate a storm
	 * of page faults. Test this upfront so that the redundant fault requests
	 * return as early as possible.
	 */
	if (i915_vma_is_bound(vma, PIN_RESIDENT))
		goto put_vma;

 retry_userptr:
	if (i915_gem_object_is_userptr(vma->obj)) {
		err = i915_gem_object_userptr_submit_init(vma->obj);
		if (err)
			goto put_vma;
	}

	i915_gem_ww_ctx_init(&ww, false);

 retry:
	err = i915_gem_object_lock(vma->obj, &ww);
	if (err)
		goto err_ww;

	vma->obj->flags |= I915_BO_FAULT_CLEAR;

	lmem_id = get_lmem_region_id(vma->obj, gt);
	if (i915_gem_object_should_migrate_lmem(vma->obj, lmem_id,
						access_is_atomic(info))) {
		err = migrate_to_lmem(vma->obj, gt, lmem_id, &ww);
		/*
		 * Migration is best effort.
		 * if we see -EDEADLK handle that with proper backoff. Otherwise
		 * for scenarios like atomic operation, if migration fails,
		 * gpu will fault again and we can retry.
		 */
		if (err == -EDEADLK)
			goto err_ww;

	}

	err = i915_vma_bind(vma, &ww);
	if (!err && userptr_needs_rebind(vma->obj)) {
		i915_gem_ww_ctx_fini(&ww);
		goto retry_userptr;
	}
 err_ww:
	if (err == -EDEADLK) {
		err = i915_gem_ww_ctx_backoff(&ww);
		if (!err)
			goto retry;
	}

	i915_gem_ww_ctx_fini(&ww);
put_vma:
	if (i915_gem_object_is_userptr(vma->obj)) {
		if (err == -EAGAIN)
			/* Need to try again in the next page fault. */
			err = 0;
	}

	fence = i915_active_fence_get_or_error(&vma->active.excl);

	i915_vma_put(vma);

	return fence ?: ERR_PTR(err);
}

static void get_fault_info(const u32 *payload, struct recoverable_page_fault_info *info)
{
	const struct intel_guc_pagefault_desc *desc;

	desc = (const struct intel_guc_pagefault_desc *)payload;

	info->fault_level = FIELD_GET(PAGE_FAULT_DESC_FAULT_LEVEL, desc->dw0);
	info->engine_class = FIELD_GET(PAGE_FAULT_DESC_ENG_CLASS, desc->dw0);
	info->engine_instance = FIELD_GET(PAGE_FAULT_DESC_ENG_INSTANCE, desc->dw0);
	info->pdata = FIELD_GET(PAGE_FAULT_DESC_PDATA_HI,
				desc->dw1) << PAGE_FAULT_DESC_PDATA_HI_SHIFT;
	info->pdata |= FIELD_GET(PAGE_FAULT_DESC_PDATA_LO, desc->dw0);
	info->asid =  FIELD_GET(PAGE_FAULT_DESC_ASID, desc->dw1);
	info->vfid =  FIELD_GET(PAGE_FAULT_DESC_VFID, desc->dw2);
	info->access_type = FIELD_GET(PAGE_FAULT_DESC_ACCESS_TYPE, desc->dw2);
	info->fault_type = FIELD_GET(PAGE_FAULT_DESC_FAULT_TYPE, desc->dw2);
	info->page_addr = (u64)(FIELD_GET(PAGE_FAULT_DESC_VIRTUAL_ADDR_HI,
					  desc->dw3)) << PAGE_FAULT_DESC_VIRTUAL_ADDR_HI_SHIFT;
	info->page_addr |= FIELD_GET(PAGE_FAULT_DESC_VIRTUAL_ADDR_LO,
				     desc->dw2) << PAGE_FAULT_DESC_VIRTUAL_ADDR_LO_SHIFT;
}

struct fault_reply {
	struct dma_fence_work base;
	struct recoverable_page_fault_info info;
	struct i915_sw_dma_fence_cb cb;
	struct i915_gpu_coredump *dump;
	struct intel_guc *guc;
	struct intel_gt *gt;
	intel_wakeref_t wakeref;
};

static int fault_work(struct dma_fence_work *work)
{
	return 0;
}

static int send_fault_reply(const struct fault_reply *f)
{
	u32 action[] = {
		INTEL_GUC_ACTION_PAGE_FAULT_RES_DESC,

		(FIELD_PREP(PAGE_FAULT_REPLY_VALID, 1) |
		 FIELD_PREP(PAGE_FAULT_REPLY_SUCCESS,
			    f->info.fault_unsuccessful) |
		 FIELD_PREP(PAGE_FAULT_REPLY_REPLY,
			    PAGE_FAULT_REPLY_ACCESS) |
		 FIELD_PREP(PAGE_FAULT_REPLY_DESC_TYPE,
			    FAULT_RESPONSE_DESC) |
		 FIELD_PREP(PAGE_FAULT_REPLY_ASID,
			    f->info.asid)),

		(FIELD_PREP(PAGE_FAULT_REPLY_VFID,
			    f->info.vfid) |
		 FIELD_PREP(PAGE_FAULT_REPLY_ENG_INSTANCE,
			    f->info.engine_instance) |
		 FIELD_PREP(PAGE_FAULT_REPLY_ENG_CLASS,
			    f->info.engine_class) |
		 FIELD_PREP(PAGE_FAULT_REPLY_PDATA,
			    f->info.pdata)),
	};

	return intel_guc_send(f->guc, action, ARRAY_SIZE(action));
}

static void coredump_add_request(struct i915_gpu_coredump *dump,
				 struct i915_request *rq,
				 gfp_t gfp)
{
	struct intel_gt_coredump *gt = dump->gt;
	struct intel_engine_capture_vma *vma;
	struct i915_page_compress *compress;

	compress = i915_vma_capture_prepare(gt);
	if (!compress)
		return;

	vma = intel_engine_coredump_add_request(gt->engine, rq, gfp, compress);
	if (vma)
		intel_engine_coredump_add_vma(gt->engine, vma, compress);

	i915_vma_capture_finish(gt, compress);
}

static void fault_complete(struct dma_fence_work *work)
{
	struct fault_reply *f = container_of(work, typeof(*f), base);

	if (work->dma.error) {
		print_recoverable_fault(&f->info);
		f->info.fault_unsuccessful = true;
	}

	GEM_WARN_ON(send_fault_reply(f));

	if (f->dump) {
		struct i915_gpu_coredump *dump = f->dump;
		struct intel_gt_coredump *gt = dump->gt;

		if (dump->private) {
			coredump_add_request(dump, dump->private, GFP_KERNEL);
			i915_request_put(dump->private);
		}

		if (intel_gt_mcr_read_any(f->gt, TD_CTL)) {
			struct intel_engine_cs *engine =
				(struct intel_engine_cs *)gt->engine->engine;

			intel_eu_attentions_read(f->gt, &gt->attentions.resolved,
						 INTEL_GT_ATTENTION_TIMEOUT_MS);

			/* Reset and cleanup if there are any ATTN leftover */
			intel_engine_schedule_heartbeat(engine);
		}

		i915_error_state_store(dump);
		i915_gpu_coredump_put(dump);
	}

	intel_gt_pm_put(f->gt, f->wakeref);
}

static const struct dma_fence_work_ops reply_ops = {
	.name = "pagefault",
	.work = fault_work,
	.complete = fault_complete,
};

int intel_pagefault_req_process_msg(struct intel_guc *guc,
				    const u32 *payload,
				    u32 len)
{
	struct fault_reply *reply;
	struct dma_fence *fence;

	if (unlikely(len != 4))
		return -EPROTO;

	reply = kzalloc(sizeof(*reply), GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	dma_fence_work_init(&reply->base, &reply_ops);
	get_fault_info(payload, &reply->info);
	reply->guc = guc;

	reply->gt = guc_to_gt(guc);
	reply->wakeref = intel_gt_pm_get(reply->gt);

	fence = handle_i915_mm_fault(guc, &reply->info, &reply->dump);
	if (IS_ERR(fence)) {
		i915_sw_fence_set_error_once(&reply->base.chain, PTR_ERR(fence));
	} else if (fence) {
		__i915_sw_fence_await_dma_fence(&reply->base.chain, fence, &reply->cb);
		dma_fence_put(fence);
	}

	dma_fence_work_commit_imm_if(&reply->base, !reply->dump);
	return 0;
}
