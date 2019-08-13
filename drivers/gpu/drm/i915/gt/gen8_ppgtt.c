// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include <linux/log2.h>

#include "gem/i915_gem_lmem.h"

#include "gen8_engine_cs.h"
#include "gen8_ppgtt.h"
#include "i915_scatterlist.h"
#include "i915_trace.h"
#include "i915_pvinfo.h"
#include "i915_vgpu.h"
#include "intel_engine_pm.h"
#include "intel_flat_ppgtt_pool.h"
#include "intel_gpu_commands.h"
#include "intel_gt.h"
#include "intel_gtt.h"
#include "intel_gt_pm.h"
#include "intel_lrc.h"

static intel_wakeref_t l4wa_pm_get(struct intel_gt *gt)
{
	if (!i915_is_level4_wa_active(gt))
		return 0;

	return intel_gt_pm_get_if_awake_l4(gt);
}

static void pte_sync(struct i915_request **fp)
{
	struct i915_request *f = fetch_and_zero(fp);

	if (!IS_ERR_OR_NULL(f)) {
		__i915_request_wait(f, 0, MAX_SCHEDULE_TIMEOUT);
		i915_request_put(f);
	}
}

static struct intel_pte_bo *get_next_batch(struct intel_flat_ppgtt_pool *fpp)
{
	struct intel_pte_bo *bo = intel_flat_ppgtt_get_pte_bo(fpp);

	/*
	 * In current implementation of level-4 wa we need two i915 resources
	 * to update ptes 1) i915 request 2) i915 vma (a.k.a batch buffer).
	 *
	 * While we estimate how many i915 requests are needed ahead and allocate them
	 * but batch buffer is still a limited resource, since we have predetermined
	 * number of them available, statically pinned on flat ppgtt during driver load
	 * by directly writing ptes through lmem bar.
	 *
	 * Since we allocate only 1 vma to bind/unbind operation we have to reuse
	 * if we need more, hence the wait here to ensure we are done with previous
	 * operation before we reuse. Here we should to use dma_fence_wait(), but
	 * that is not allowed since we are already holding vm->mutex and dep_map
	 * requirements for gt->reset.mutex.dep_map. so we will be in a tight loop
	 * to check if fence is signaled that will guarantee batch buffer is available
	 * before we reuse.
	 *
	 * This limited number of batch buffer resource should be converted into more
	 * dynamic resource and that we have unlimited supply of them based on demand,
	 * this part is left for future work. At that point below wait will not be needed
	 * and rather we wait only on the last request submitted, so we know bind/unbind
	 * operation is completed and wait should be outside of vm->mutex.
	 */
	pte_sync(&bo->wait);

	return bo;
}

static u32 *fill_cmd_pte(u32 *cmd, u64 start, u32 idx, u64 val)
{
	u64 offset = start + idx * sizeof(gen8_pte_t);

	*cmd++ = MI_STORE_QWORD_IMM_GEN8;
	*cmd++ = lower_32_bits(offset);
	*cmd++ = upper_32_bits(offset);
	*cmd++ = lower_32_bits(val);
	*cmd++ = upper_32_bits(val);
	return cmd;
}

static u32 *
fill_value_blt(struct intel_gt *gt, u32 *cmd,
	       u64 offset, int idx, int count, u64 val)
{
	u32 mocs = 0;
	u32 mem = 0;
	int len;

	/* XY_FAST_COLOR_BLT was added in gen12 */
	drm_WARN_ON(&gt->i915->drm, GRAPHICS_VER(gt->i915) < 12);

	len = 11;
	if (GRAPHICS_VER_FULL(gt->i915) >= IP_VER(12, 50)) {
		mocs = gt->mocs.uc_index << 1;
		mocs = FIELD_PREP(XY_FAST_COLOR_BLT_MOCS_MASK, mocs);
		len = 16;
	}

	if (IS_XEHPSDV_GRAPHICS_STEP(gt->i915, STEP_A0, STEP_B0))
		mem = MEM_TYPE_SYS << 31;

	*cmd++ = GEN9_XY_FAST_COLOR_BLT_CMD |
		XY_FAST_COLOR_BLT_DEPTH_64 |
		(len - 2);
	*cmd++ = mocs | (PAGE_SIZE - 1);
	*cmd++ = idx;
	*cmd++ = (1 << 16) | (idx + count);
	*cmd++ = lower_32_bits(offset);
	*cmd++ = upper_32_bits(offset);
	*cmd++ = mem;
	/* BG7 */
	*cmd++ = lower_32_bits(val);
	*cmd++ = upper_32_bits(val);
	*cmd++ = 0;
	*cmd++ = 0;
	/* BG11 -- MI_NOOP on tgl/dg1 */
	*cmd++ = 0;
	*cmd++ = 0;
	/* BG13 */
	*cmd++ = 0;
	*cmd++ = 0;
	*cmd++ = 0;

	/*
	 * Add flush between XY_FAST_COLOR_BLT and MI_STORE to avoid the
	 * overwriting by cached entries by XY_FAST_COLOR.
	 */
	return __gen8_emit_flush_dw(cmd, 0, LRC_PPHWSP_SCRATCH_ADDR,
				    MI_FLUSH_DW_OP_STOREDW |
				    MI_FLUSH_DW_STORE_INDEX);
}

/*
 * Fills a page with a given value
 */
static u32 *fill_page_blt(struct intel_gt *gt, u32 *cmd, u64 offset, u64 val)
{
	return fill_value_blt(gt, cmd, offset, 0, PAGE_SIZE >> 3, val);
}

static struct i915_request *
__flat_ppgtt_submit(struct i915_vma *batch, struct i915_request *rq)
{
	int err;

	i915_gem_object_flush_map(batch->obj);

	err = rq->engine->emit_bb_start(rq,
					i915_vma_offset(batch),
					i915_vma_size(batch),
					0);
	if (!err)
		i915_request_get(rq);
	else
		i915_request_set_error_once(rq, err);
	i915_request_add(rq);

	return err ? ERR_PTR(err) : rq;
}

static struct i915_request *flat_ppgtt_submit(struct i915_vma *batch)
{
	struct i915_request *rq;

	rq = intel_flat_ppgtt_get_request(&batch->vm->gt->fpp);
	if (IS_ERR(rq))
		return rq;

	return __flat_ppgtt_submit(batch, rq);
}

static bool
release_pd_entry_wa_bcs(struct i915_page_directory * const pd,
			const unsigned short idx,
			struct i915_page_table * const pt,
			const struct drm_i915_gem_object * const scratch,
			u32 **cmd)
{
	bool free = false;

	if (atomic_add_unless(&pt->used, -1, 1))
		return false;

	spin_lock(&pd->lock);
	if (atomic_dec_and_test(&pt->used)) {
		*cmd = fill_cmd_pte(*cmd, px_dma(pd), idx, scratch->encode);
		pd->entry[idx] = NULL;
		atomic_dec(px_used(pd));
		free = true;
	}
	spin_unlock(&pd->lock);

	return free;
}

static u64 gen8_pde_encode(const dma_addr_t addr,
			   const enum i915_cache_level level)
{
	u64 pde = addr | GEN8_PAGE_PRESENT | GEN8_PAGE_RW;

	if (level != I915_CACHE_NONE)
		pde |= PPAT_CACHED_PDE;
	else
		pde |= PPAT_UNCACHED;

	return pde;
}

static u64 gen8_pte_encode(dma_addr_t addr,
			   enum i915_cache_level level,
			   u32 flags)
{
	gen8_pte_t pte = addr | GEN8_PAGE_PRESENT | GEN8_PAGE_RW;

	if (unlikely(flags & PTE_READ_ONLY))
		pte &= ~GEN8_PAGE_RW;

	if (flags & PTE_LM)
		pte |= GEN12_PPGTT_PTE_LM;

	switch (level) {
	case I915_CACHE_NONE:
		pte |= PPAT_UNCACHED;
		break;
	case I915_CACHE_WT:
		pte |= PPAT_DISPLAY_ELLC;
		break;
	default:
		pte |= PPAT_CACHED;
		break;
	}

	return pte;
}

static void gen8_ppgtt_notify_vgt(struct i915_ppgtt *ppgtt, bool create)
{
	struct drm_i915_private *i915 = ppgtt->vm.i915;
	struct intel_uncore *uncore = ppgtt->vm.gt->uncore;
	enum vgt_g2v_type msg;
	int i;

	if (create)
		atomic_inc(px_used(ppgtt->pd)); /* never remove */
	else
		atomic_dec(px_used(ppgtt->pd));

	mutex_lock(&i915->vgpu.lock);

	if (i915_vm_lvl(&ppgtt->vm) >= 4) {
		const u64 daddr = px_dma(ppgtt->pd);

		intel_uncore_write(uncore,
				   vgtif_reg(pdp[0].lo), lower_32_bits(daddr));
		intel_uncore_write(uncore,
				   vgtif_reg(pdp[0].hi), upper_32_bits(daddr));

		msg = create ?
			VGT_G2V_PPGTT_L4_PAGE_TABLE_CREATE :
			VGT_G2V_PPGTT_L4_PAGE_TABLE_DESTROY;
	} else {
		for (i = 0; i < GEN8_3LVL_PDPES; i++) {
			const u64 daddr = i915_page_dir_dma_addr(ppgtt, i);

			intel_uncore_write(uncore,
					   vgtif_reg(pdp[i].lo),
					   lower_32_bits(daddr));
			intel_uncore_write(uncore,
					   vgtif_reg(pdp[i].hi),
					   upper_32_bits(daddr));
		}

		msg = create ?
			VGT_G2V_PPGTT_L3_PAGE_TABLE_CREATE :
			VGT_G2V_PPGTT_L3_PAGE_TABLE_DESTROY;
	}

	/* g2v_notify atomically (via hv trap) consumes the message packet. */
	intel_uncore_write(uncore, vgtif_reg(g2v_notify), msg);

	mutex_unlock(&i915->vgpu.lock);
}

/* Index shifts into the pagetable are offset by GEN8_PTE_SHIFT [12] */
#define GEN8_PAGE_SIZE (SZ_4K) /* page and page-directory sizes are the same */
#define GEN8_PTE_SHIFT (ilog2(GEN8_PAGE_SIZE))
#define GEN8_PDES (GEN8_PAGE_SIZE / sizeof(u64))
#define gen8_pd_shift(lvl) ((lvl) * ilog2(GEN8_PDES))
#define gen8_pd_index(i, lvl) i915_pde_index((i), gen8_pd_shift(lvl))
#define __gen8_pte_shift(lvl) (GEN8_PTE_SHIFT + gen8_pd_shift(lvl))
#define __gen8_pte_index(a, lvl) i915_pde_index((a), __gen8_pte_shift(lvl))

#define as_pd(x) container_of((x), typeof(struct i915_page_directory), pt)

static unsigned int
gen8_pd_range(u64 start, u64 end, int lvl, unsigned int *idx)
{
	const int shift = gen8_pd_shift(lvl);
	const u64 mask = ~0ull << gen8_pd_shift(lvl + 1);

	GEM_BUG_ON(start >= end);
	end += ~mask >> gen8_pd_shift(1);

	*idx = i915_pde_index(start, shift);
	if ((start ^ end) & mask)
		return GEN8_PDES - *idx;
	else
		return i915_pde_index(end, shift) - *idx;
}

static bool gen8_pd_contains(u64 start, u64 end, int lvl)
{
	const u64 mask = ~0ull << gen8_pd_shift(lvl + 1);

	GEM_BUG_ON(start >= end);
	return (start ^ end) & mask && (start & ~mask) == 0;
}

static unsigned int gen8_pt_count(u64 start, u64 end)
{
	GEM_BUG_ON(start >= end);
	if ((start ^ end) >> gen8_pd_shift(1))
		return GEN8_PDES - (start & (GEN8_PDES - 1));
	else
		return end - start;
}

static unsigned int gen8_pd_top_count(const struct i915_address_space *vm)
{
	unsigned int shift = __gen8_pte_shift(vm->top);

	return (vm->total + (1ull << shift) - 1) >> shift;
}

static struct i915_page_directory *
gen8_pdp_for_page_index(struct i915_address_space * const vm, const u64 idx)
{
	struct i915_ppgtt * const ppgtt = i915_vm_to_ppgtt(vm);

	if (vm->top == 2)
		return ppgtt->pd;
	else
		return i915_pd_entry(ppgtt->pd, gen8_pd_index(idx, vm->top));
}

static struct i915_page_directory *
gen8_pdp_for_page_address(struct i915_address_space * const vm, const u64 addr)
{
	return gen8_pdp_for_page_index(vm, addr >> GEN8_PTE_SHIFT);
}

static void __gen8_ppgtt_cleanup(struct i915_address_space *vm,
				 struct i915_page_directory *pd,
				 int count, int lvl)
{
	if (lvl) {
		void **pde = pd->entry;

		do {
			if (!*pde)
				continue;

			__gen8_ppgtt_cleanup(vm, *pde, GEN8_PDES, lvl - 1);
		} while (pde++, --count);
	}

	free_px(vm, &pd->pt, lvl);
}

static void gen8_ppgtt_cleanup(struct i915_address_space *vm)
{
	struct i915_ppgtt *ppgtt = i915_vm_to_ppgtt(vm);

	if (intel_vgpu_active(vm->i915))
		gen8_ppgtt_notify_vgt(ppgtt, false);

	if (ppgtt->pd)
		__gen8_ppgtt_cleanup(vm, ppgtt->pd,
				     gen8_pd_top_count(vm), vm->top);

	free_scratch(vm);
}

static u64 __gen8_ppgtt_clear(struct i915_address_space * const vm,
			      struct i915_page_directory * const pd,
			      u64 start, const u64 end, int lvl,
			      u32 **cmd, int *nptes)
{
	const struct drm_i915_gem_object * const scratch = vm->scratch[lvl];
	unsigned int idx, len;

	GEM_BUG_ON(end > vm->total >> GEN8_PTE_SHIFT);

	len = gen8_pd_range(start, end, lvl--, &idx);
	DBG("%s(%p):{ lvl:%d, start:%llx, end:%llx, idx:%d, len:%d, used:%d }\n",
	    __func__, vm, lvl + 1, start, end,
	    idx, len, atomic_read(px_used(pd)));
	GEM_BUG_ON(!len || len >= atomic_read(px_used(pd)));

	do {
		struct i915_page_table *pt = pd->entry[idx];
		bool freepx;

		if (atomic_fetch_inc(&pt->used) >> gen8_pd_shift(1) &&
		    gen8_pd_contains(start, end, lvl)) {
			DBG("%s(%p):{ lvl:%d, idx:%d, start:%llx, end:%llx } removing pd\n",
			    __func__, vm, lvl + 1, idx, start, end);
			if (!cmd) {
				clear_pd_entry(pd, idx, scratch);
			} else {
				*cmd = fill_cmd_pte(*cmd, px_dma(pd), idx, scratch->encode);
				pd->entry[idx] = NULL;
				atomic_dec(px_used(pd));
				*nptes = *nptes + 1;
			}
			__gen8_ppgtt_cleanup(vm, as_pd(pt), I915_PDES, lvl);
			start += (u64)I915_PDES << gen8_pd_shift(lvl);

			if (cmd && *nptes >= INTEL_FLAT_PPGTT_MAX_FILL_PTE_ENTRIES)
				break;
			continue;
		}

		if (lvl) {
			start = __gen8_ppgtt_clear(vm, as_pd(pt),
						   start, end, lvl, cmd, nptes);
		} else {
			unsigned int count;
			unsigned int pte = gen8_pd_index(start, 0);
			unsigned int num_ptes;
			u64 *vaddr;

			count = gen8_pt_count(start, end);
			DBG("%s(%p):{ lvl:%d, start:%llx, end:%llx, idx:%d, len:%d, used:%d } removing pte\n",
			    __func__, vm, lvl, start, end,
			    gen8_pd_index(start, 0), count,
			    atomic_read(&pt->used));
			GEM_BUG_ON(!count || count >= atomic_read(&pt->used));

			num_ptes = count;
			if (pt->is_compact) {
				GEM_BUG_ON(num_ptes % 16);
				GEM_BUG_ON(pte % 16);
				num_ptes /= 16;
				pte /= 16;
			}

			vaddr = px_vaddr(pt, NULL);
			if (!cmd) {
				memset64(vaddr + pte,
					 vm->scratch[0]->encode,
					 num_ptes);
			} else {

				*cmd = fill_value_blt(vm->gt, *cmd, px_dma(pt),
						      pte, num_ptes,
						      vm->scratch[0]->encode);
				*nptes += 1;
			}

			atomic_sub(count, &pt->used);
			start += count;
		}

		if (!cmd)
			freepx = release_pd_entry(pd, idx, pt, scratch);

		else {
			freepx = release_pd_entry_wa_bcs(pd, idx, pt, scratch, cmd);
			*nptes += 1;
		}
		if (freepx)
			free_px(vm, pt, lvl);

		if (cmd && *nptes >= INTEL_FLAT_PPGTT_MAX_FILL_PTE_ENTRIES)
			break;
	} while (idx++, --len);

	return start;
}

static void gen8_ppgtt_clear(struct i915_address_space *vm,
			     u64 start, u64 length)
{
	GEM_BUG_ON(!IS_ALIGNED(start, BIT_ULL(GEN8_PTE_SHIFT)));
	GEM_BUG_ON(!IS_ALIGNED(length, BIT_ULL(GEN8_PTE_SHIFT)));
	GEM_BUG_ON(range_overflows(start, length, vm->total));

	start >>= GEN8_PTE_SHIFT;
	length >>= GEN8_PTE_SHIFT;
	GEM_BUG_ON(length == 0);

	__gen8_ppgtt_clear(vm, i915_vm_to_ppgtt(vm)->pd,
			   start, start + length, vm->top, NULL, NULL);
}

static void gen8_ppgtt_clear_wa_bcs(struct i915_address_space *vm,
				    u64 start, u64 length)
{
	u64 begin, end, fstart, flength;
	struct intel_gt *gt = vm->gt;
	struct i915_request *f = NULL;
	intel_wakeref_t wakeref;

	wakeref = l4wa_pm_get(gt);
	if (!wakeref) {
		gen8_ppgtt_clear(vm, start, length);
		return;
	}

	GEM_BUG_ON(!IS_ALIGNED(start, BIT_ULL(GEN8_PTE_SHIFT)));
	GEM_BUG_ON(!IS_ALIGNED(length, BIT_ULL(GEN8_PTE_SHIFT)));
	GEM_BUG_ON(range_overflows(start, length, vm->total));

	fstart = start;
	flength = length;
	start >>= GEN8_PTE_SHIFT;
	length >>= GEN8_PTE_SHIFT;
	GEM_BUG_ON(length == 0);
	begin = start;
	end = start + length;

	do {
		struct intel_pte_bo *bo = get_next_batch(&gt->fpp);
		struct i915_request *rq;
		u32 *cmd = bo->cmd;
		int count = 0;

		rq = intel_flat_ppgtt_get_request(&gt->fpp);
		if (IS_ERR(rq)) {
			intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
			break;
		}

		begin = __gen8_ppgtt_clear(vm, i915_vm_to_ppgtt(vm)->pd,
					   begin, end, vm->top, &cmd, &count);
		if (!count) {
			intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
			i915_request_add(rq);
			break;
		}

		GEM_BUG_ON(cmd >= bo->cmd + bo->vma->size / sizeof(*bo->cmd));
		*cmd++ = MI_BATCH_BUFFER_END;

		bo->wait = __flat_ppgtt_submit(bo->vma, rq);
		if (IS_ERR(bo->wait)) {
			intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
			break;
		}

		i915_request_put(f);
		f = i915_request_get(bo->wait);
		intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
	} while (begin < end);

	pte_sync(&f);
	intel_gt_pm_put_async_l4(gt, wakeref);

	if (unlikely(begin < end)) {
		drm_warn(&vm->i915->drm, "flat ppgtt clear pte fallback\n");
		gen8_ppgtt_clear(vm, fstart, flength);
	}
}

static void gen8_ppgtt_clear_wa(struct i915_address_space *vm,
				u64 start, u64 length)
{
	GEM_WARN_ON(i915_gem_idle_engines(vm->i915));

	gen8_ppgtt_clear(vm, start, length);

	GEM_WARN_ON(i915_gem_resume_engines(vm->i915));
}

static int __gen8_ppgtt_alloc(struct i915_address_space * const vm,
			       struct i915_vm_pt_stash *stash,
			       struct i915_page_directory * const pd,
			       u64 * const start, const u64 end, int lvl,
			       u32 **cmd, int *nptes)
{
	unsigned int idx, len;
	int ret = 0;

	GEM_BUG_ON(end > vm->total >> GEN8_PTE_SHIFT);

	len = gen8_pd_range(*start, end, lvl--, &idx);
	DBG("%s(%p):{ lvl:%d, start:%llx, end:%llx, idx:%d, len:%d, used:%d }\n",
	    __func__, vm, lvl + 1, *start, end,
	    idx, len, atomic_read(px_used(pd)));
	GEM_BUG_ON(!len || (idx + len - 1) >> gen8_pd_shift(1));

	spin_lock(&pd->lock);
	GEM_BUG_ON(!atomic_read(px_used(pd))); /* Must be pinned! */
	do {
		struct i915_page_table *pt = pd->entry[idx];

		if (!pt) {
			spin_unlock(&pd->lock);

			DBG("%s(%p):{ lvl:%d, idx:%d } allocating new tree\n",
			    __func__, vm, lvl + 1, idx);

			pt = stash->pt[!!lvl];
			__i915_gem_object_pin_pages(pt->base);

			if (!cmd) {
				fill_px(pt, vm->scratch[lvl]->encode);
			} else {
				*cmd = fill_page_blt(vm->gt, *cmd,
						     px_dma(pt),
						     vm->scratch[lvl]->encode);
				*nptes += 1;
			}
			spin_lock(&pd->lock);
			if (likely(!pd->entry[idx])) {
				stash->pt[!!lvl] = pt->stash;
				atomic_set(&pt->used, 0);
				if (!cmd) {
					set_pd_entry(pd, idx, pt);
				} else {
					pd->entry[idx] = pt;
					atomic_inc(px_used(pd));
					*cmd = fill_cmd_pte(*cmd, px_dma(pd), idx,
							    gen8_pde_encode(px_dma(pt), I915_CACHE_LLC));
					*nptes += 1;
				}
			} else {
				pt = pd->entry[idx];
			}
		}

		if (cmd && *nptes >= INTEL_FLAT_PPGTT_MAX_FILL_PTE_ENTRIES) {
			ret = -EAGAIN;
			break;
		}

		if (lvl) {
			atomic_inc(&pt->used);
			spin_unlock(&pd->lock);

			ret = __gen8_ppgtt_alloc(vm, stash,
					   as_pd(pt), start, end, lvl, cmd, nptes);
			spin_lock(&pd->lock);
			atomic_dec(&pt->used);
			GEM_BUG_ON(!atomic_read(&pt->used));
		} else {
			unsigned int count = gen8_pt_count(*start, end);

			DBG("%s(%p):{ lvl:%d, start:%llx, end:%llx, idx:%d, len:%d, used:%d } inserting pte\n",
			    __func__, vm, lvl, *start, end,
			    gen8_pd_index(*start, 0), count,
			    atomic_read(&pt->used));

			atomic_add(count, &pt->used);
			/* All other pdes may be simultaneously removed */
			GEM_BUG_ON(atomic_read(&pt->used) > NALLOC * I915_PDES);
			*start += count;
		}

		if (cmd && *nptes >= INTEL_FLAT_PPGTT_MAX_FILL_PTE_ENTRIES) {
			/* call again with same idx & updated start */
			ret = -EAGAIN;
			break;
		}
	} while (idx++, --len);
	spin_unlock(&pd->lock);

	return ret;
}

static void gen8_ppgtt_alloc(struct i915_address_space *vm,
			     struct i915_vm_pt_stash *stash,
			     u64 start, u64 length)
{
	GEM_BUG_ON(!IS_ALIGNED(start, BIT_ULL(GEN8_PTE_SHIFT)));
	GEM_BUG_ON(!IS_ALIGNED(length, BIT_ULL(GEN8_PTE_SHIFT)));
	GEM_BUG_ON(range_overflows(start, length, vm->total));

	start >>= GEN8_PTE_SHIFT;
	length >>= GEN8_PTE_SHIFT;
	GEM_BUG_ON(length == 0);

	__gen8_ppgtt_alloc(vm, stash, i915_vm_to_ppgtt(vm)->pd,
			   &start, start + length, vm->top, NULL, NULL);
}

static void __gen8_ppgtt_foreach(struct i915_address_space *vm,
				 struct i915_page_directory *pd,
				 u64 *start, u64 end, int lvl,
				 void (*fn)(struct i915_address_space *vm,
					    struct i915_page_table *pt,
					    void *data),
				 void *data)
{
	unsigned int idx, len;

	len = gen8_pd_range(*start, end, lvl--, &idx);

	spin_lock(&pd->lock);
	do {
		struct i915_page_table *pt = pd->entry[idx];

		atomic_inc(&pt->used);
		spin_unlock(&pd->lock);

		if (lvl) {
			__gen8_ppgtt_foreach(vm, as_pd(pt), start, end, lvl,
					     fn, data);
		} else {
			fn(vm, pt, data);
			*start += gen8_pt_count(*start, end);
		}

		spin_lock(&pd->lock);
		atomic_dec(&pt->used);
	} while (idx++, --len);
	spin_unlock(&pd->lock);
}

static void gen8_ppgtt_foreach(struct i915_address_space *vm,
			       u64 start, u64 length,
			       void (*fn)(struct i915_address_space *vm,
					  struct i915_page_table *pt,
					  void *data),
			       void *data)
{
	start >>= GEN8_PTE_SHIFT;
	length >>= GEN8_PTE_SHIFT;

	__gen8_ppgtt_foreach(vm, i915_vm_to_ppgtt(vm)->pd,
			     &start, start + length, vm->top,
			     fn, data);
}

static void gen8_ppgtt_alloc_wa(struct i915_address_space *vm,
				struct i915_vm_pt_stash *stash,
				u64 start, u64 length)
{
	GEM_WARN_ON(i915_gem_idle_engines(vm->i915));

	gen8_ppgtt_alloc(vm, stash, start, length);

	GEM_WARN_ON(i915_gem_resume_engines(vm->i915));
}

static void gen8_ppgtt_alloc_wa_bcs(struct i915_address_space *vm,
				   struct i915_vm_pt_stash *stash,
				   u64 start, u64 length)
{
	u64 from, begin, end, fstart, flength;
	struct intel_gt *gt = vm->gt;
	struct i915_request *f = NULL;
	intel_wakeref_t wakeref;
	int err;

	wakeref = l4wa_pm_get(gt);
	if (!wakeref)
		return gen8_ppgtt_alloc(vm, stash, start, length);

	fstart = start;
	flength = length;
	GEM_BUG_ON(!IS_ALIGNED(start, BIT_ULL(GEN8_PTE_SHIFT)));
	GEM_BUG_ON(!IS_ALIGNED(length, BIT_ULL(GEN8_PTE_SHIFT)));
	GEM_BUG_ON(range_overflows(start, length, vm->total));

	start >>= GEN8_PTE_SHIFT;
	length >>= GEN8_PTE_SHIFT;
	GEM_BUG_ON(length == 0);
	from = start;
	begin = start;
	end = start + length;

	do {
		struct intel_pte_bo *bo = get_next_batch(&gt->fpp);
		struct i915_request *rq;
		u32 *cmd = bo->cmd;
		int count = 0;

		rq = intel_flat_ppgtt_get_request(&gt->fpp);
		if (IS_ERR(rq)) {
			intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
			err = PTR_ERR(rq);
			break;
		}

		err = __gen8_ppgtt_alloc(vm, stash, i915_vm_to_ppgtt(vm)->pd,
					 &begin, end, vm->top, &cmd, &count);

		/*
		 * -EGAIN indicates the batch buffer was full with blts to update the pte,
		 * since all the submissions for filling scratch pages for the VA range
		 * are completed we can clear this error flag.
		 */
		if (err == -EAGAIN)
			err = 0;
		if (err || !count) {
			intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
			if (err)
				i915_request_set_error_once(rq, err);
			i915_request_add(rq);
			break;
		}

		GEM_BUG_ON(cmd >= bo->cmd + bo->vma->size / sizeof(*bo->cmd));
		*cmd++ = MI_BATCH_BUFFER_END;

		bo->wait = __flat_ppgtt_submit(bo->vma, rq);
		if (IS_ERR(bo->wait)) {
			intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
			err = PTR_ERR(bo->wait);
			break;
		}

		i915_request_put(f);
		f = i915_request_get(bo->wait);
		intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
	} while (begin < end);

	pte_sync(&f);
	intel_gt_pm_put_async_l4(gt, wakeref);

	if (unlikely(err)) {
		drm_warn(&vm->i915->drm, "flat ppgtt pte alloc fallback\n");
		gen8_ppgtt_alloc(vm, stash, fstart, flength);
	}
}

static void xehpsdv_ppgtt_color_adjust(const struct drm_mm_node *node,
				   unsigned long color,
				   u64 *start,
				   u64 *end)
{
	if (i915_node_color_differs(node, color))
		*start = round_up(*start, SZ_2M);

	node = list_next_entry(node, node_list);
	if (i915_node_color_differs(node, color))
		*end = round_down(*end, SZ_2M);
}

static void
xehpsdv_ppgtt_insert_huge(struct i915_vma *vma,
			  struct i915_vm_pt_stash *stash,
			  struct sgt_dma *iter,
			  enum i915_cache_level cache_level,
			  u32 flags, u32 **cmd, int *nptes)
{
	const gen8_pte_t pte_encode = vma->vm->pte_encode(0, cache_level, flags);
	unsigned int rem = min_t(u64, (u64)(iter->max - iter->dma), iter->rem);
	u64 start = i915_vma_offset(vma) + (vma->size - iter->rem);
	dma_addr_t daddr;

	GEM_BUG_ON(i915_vm_lvl(vma->vm) < 4);

	do {
		struct i915_page_directory * const pdp =
			gen8_pdp_for_page_address(vma->vm, start);
		struct i915_page_directory * const pd =
			i915_pd_entry(pdp, __gen8_pte_index(start, 2));
		struct i915_page_table *pt =
			i915_pt_entry(pd, __gen8_pte_index(start, 1));
		gen8_pte_t encode = pte_encode;
		unsigned int page_size;
		gen8_pte_t *vaddr, entry;
		u16 index, max, nent, i;
		bool needs_flush;

		max = I915_PDES;
		nent = 1;

		if (unlikely(vma->page_sizes.sg & I915_GTT_PAGE_SIZE_1G) &&
				IS_ALIGNED(iter->dma, I915_GTT_PAGE_SIZE_1G) &&
				rem >= I915_GTT_PAGE_SIZE_1G &&
				!(__gen8_pte_index(start, 0) | __gen8_pte_index(start, 1))) {
			index = __gen8_pte_index(start, 2);
			encode |= GEN8_PDPE_PS_1G;
			page_size = I915_GTT_PAGE_SIZE_1G;
			vaddr = px_vaddr(pdp, &needs_flush);
			daddr = px_dma(pdp);
		} else if (vma->page_sizes.sg & I915_GTT_PAGE_SIZE_2M &&
		    IS_ALIGNED(iter->dma, I915_GTT_PAGE_SIZE_2M) &&
		    rem >= I915_GTT_PAGE_SIZE_2M &&
		    !__gen8_pte_index(start, 0)) {
			index = __gen8_pte_index(start, 1);
			encode |= GEN8_PDE_PS_2M;
			page_size = I915_GTT_PAGE_SIZE_2M;

			vaddr = px_vaddr(pd, &needs_flush);
			daddr = px_dma(pd);
		} else {
			if (encode & GEN12_PPGTT_PTE_LM) {
				GEM_BUG_ON(__gen8_pte_index(start, 0) % 16);
				GEM_BUG_ON(rem < I915_GTT_PAGE_SIZE_64K);
				GEM_BUG_ON(!IS_ALIGNED(iter->dma,
						       I915_GTT_PAGE_SIZE_64K));

				index = __gen8_pte_index(start, 0) / 16;
				page_size = I915_GTT_PAGE_SIZE_64K;

				max /= 16;

				if (!pt->is_compact) {
					pt->is_compact = true;
					vaddr = px_vaddr(pd, &needs_flush);
					if (!cmd) {
						vaddr[__gen8_pte_index(start, 1)] |= GEN12_PDE_64K;
					} else {
						u64 pde_encode = vma->vm->pte_encode(px_dma(pt), 0, 0) | GEN12_PDE_64K;

						*cmd = fill_cmd_pte(*cmd, px_dma(pd), __gen8_pte_index(start, 1),
								    pde_encode);
						*nptes = *nptes + 1;

						if (*nptes >= INTEL_FLAT_PPGTT_MAX_PTE_ENTRIES)
							break;
					}
				}
			} else {
				GEM_BUG_ON(pt->is_compact);
				index =  __gen8_pte_index(start, 0);

				if (vma->page_sizes.sg & I915_GTT_PAGE_SIZE_64K &&
				    IS_ALIGNED(iter->dma, I915_GTT_PAGE_SIZE_64K) &&
				    rem >= I915_GTT_PAGE_SIZE_64K &&
				    !(index % 16)) {
					encode |= GEN12_PTE_PS64;
					page_size = I915_GTT_PAGE_SIZE_64K;
					nent = 16;
				} else {
					page_size = I915_GTT_PAGE_SIZE;
				}
			}

			vaddr = px_vaddr(pt, &needs_flush);
			daddr = px_dma(pt);
		}

		vma->page_sizes.gtt |= page_size;
		do {
			GEM_BUG_ON(rem < page_size);

			if (cmd && *nptes > INTEL_FLAT_PPGTT_MAX_PTE_ENTRIES - nent)
				return;

			for (i = 0; i < nent; i++) {
				entry = encode |
					(iter->dma + i * I915_GTT_PAGE_SIZE);
				if (!cmd) {
					vaddr[index++] = entry;
				} else {
					*cmd = fill_cmd_pte(*cmd, daddr, index++,
							    entry);
					*nptes = *nptes + 1;
				}
			}

			start += page_size;
			iter->dma += page_size;
			iter->rem -= page_size;
			if (!iter->rem)
				break;

			rem -= page_size;
			if (iter->dma >= iter->max) {
				iter->sg = __sg_next(iter->sg);
				GEM_BUG_ON(!iter->sg);

				rem = min_t(u64, sg_dma_len(iter->sg),
					    iter->rem);
				GEM_BUG_ON(!rem);

				iter->dma = sg_dma_address(iter->sg);
				iter->max = iter->dma + rem;

				if (unlikely(!IS_ALIGNED(iter->dma, page_size)))
					break;
			}
		} while (rem >= page_size && index < max);

		if (needs_flush)
			drm_clflush_virt_range(vaddr, PAGE_SIZE);
	} while (iter->rem);
}

static void xehpsdv_ppgtt_insert(struct i915_address_space *vm,
				 struct i915_vm_pt_stash *stash,
				 struct i915_vma *vma,
				 enum i915_cache_level cache_level,
				 u32 flags)
{
	struct sgt_dma iter = sgt_dma(vma);

	xehpsdv_ppgtt_insert_huge(vma, stash, &iter, cache_level, flags,
				  NULL, NULL);
}

static void gen8_ppgtt_insert_huge(struct i915_vma *vma,
				   struct i915_vm_pt_stash *stash,
				   struct sgt_dma *iter,
				   enum i915_cache_level cache_level,
				   u32 flags)
{
	const gen8_pte_t pte_encode = gen8_pte_encode(0, cache_level, flags);
	unsigned int rem = min_t(u64, sg_dma_len(iter->sg), iter->rem);
	u64 start = i915_vma_offset(vma);

	GEM_BUG_ON(i915_vm_lvl(vma->vm) < 4);

	do {
		struct i915_page_directory * const pdp =
			gen8_pdp_for_page_address(vma->vm, start);
		struct i915_page_directory * const pd =
			i915_pd_entry(pdp, __gen8_pte_index(start, 2));
		gen8_pte_t encode = pte_encode;
		unsigned int maybe_64K = -1;
		unsigned int page_size;
		gen8_pte_t *vaddr;
		bool needs_flush;
		u16 index;

		if (unlikely(vma->page_sizes.sg & I915_GTT_PAGE_SIZE_1G) &&
				IS_ALIGNED(iter->dma, I915_GTT_PAGE_SIZE_1G) &&
				rem >= I915_GTT_PAGE_SIZE_1G &&
				!(__gen8_pte_index(start, 0) | __gen8_pte_index(start, 1))) {
			index = __gen8_pte_index(start, 2);
			encode |= GEN8_PDPE_PS_1G;
			page_size = I915_GTT_PAGE_SIZE_1G;
			vaddr = px_vaddr(pdp, &needs_flush);

		} else if (vma->page_sizes.sg & I915_GTT_PAGE_SIZE_2M &&
		    IS_ALIGNED(iter->dma, I915_GTT_PAGE_SIZE_2M) &&
		    rem >= I915_GTT_PAGE_SIZE_2M &&
		    !__gen8_pte_index(start, 0)) {
			index = __gen8_pte_index(start, 1);
			encode |= GEN8_PDE_PS_2M;
			page_size = I915_GTT_PAGE_SIZE_2M;

			vaddr = px_vaddr(pd, &needs_flush);
		} else {
			struct i915_page_table *pt =
				i915_pt_entry(pd, __gen8_pte_index(start, 1));

			index = __gen8_pte_index(start, 0);
			page_size = I915_GTT_PAGE_SIZE;

			if (!index &&
			    vma->page_sizes.sg & I915_GTT_PAGE_SIZE_64K &&
			    IS_ALIGNED(iter->dma, I915_GTT_PAGE_SIZE_64K) &&
			    (IS_ALIGNED(rem, I915_GTT_PAGE_SIZE_64K) ||
			     rem >= (I915_PDES - index) * I915_GTT_PAGE_SIZE))
				maybe_64K = __gen8_pte_index(start, 1);

			vaddr = px_vaddr(pt, &needs_flush);
		}

		do {
			GEM_BUG_ON(rem < page_size);
			vaddr[index++] = encode | iter->dma;

			start += page_size;
			iter->dma += page_size;
			iter->rem -= page_size;
			if (!iter->rem)
				break;

			rem -= page_size;
			if (iter->dma >= iter->max) {
				iter->sg = __sg_next(iter->sg);
				GEM_BUG_ON(!iter->sg);

				rem = min_t(u64, sg_dma_len(iter->sg),
					    iter->rem);
				GEM_BUG_ON(!rem);
				iter->dma = sg_dma_address(iter->sg);
				iter->max = iter->dma + rem;

				if (maybe_64K != -1 && index < I915_PDES &&
				    !(IS_ALIGNED(iter->dma, I915_GTT_PAGE_SIZE_64K) &&
				      (IS_ALIGNED(rem, I915_GTT_PAGE_SIZE_64K) ||
				       rem >= (I915_PDES - index) * I915_GTT_PAGE_SIZE)))
					maybe_64K = -1;

				if (unlikely(!IS_ALIGNED(iter->dma, page_size)))
					break;
			}
		} while (rem >= page_size && index < I915_PDES);

		if (needs_flush)
			drm_clflush_virt_range(vaddr, PAGE_SIZE);

		/*
		 * Is it safe to mark the 2M block as 64K? -- Either we have
		 * filled whole page-table with 64K entries, or filled part of
		 * it and have reached the end of the sg table and we have
		 * enough padding.
		 */
		if (maybe_64K != -1 &&
		    (index == I915_PDES ||
		     (i915_vm_has_scratch_64K(vma->vm) &&
		      !iter->rem && IS_ALIGNED(i915_vma_offset(vma) +
					       i915_vma_size(vma),
					       I915_GTT_PAGE_SIZE_2M)))) {
			vaddr = px_vaddr(pd, &needs_flush);
			vaddr[maybe_64K] |= GEN8_PDE_IPS_64K;
			if (needs_flush)
				drm_clflush_virt_range(vaddr, PAGE_SIZE);
			page_size = I915_GTT_PAGE_SIZE_64K;

			/*
			 * We write all 4K page entries, even when using 64K
			 * pages. In order to verify that the HW isn't cheating
			 * by using the 4K PTE instead of the 64K PTE, we want
			 * to remove all the surplus entries. If the HW skipped
			 * the 64K PTE, it will read/write into the scratch page
			 * instead - which we detect as missing results during
			 * selftests.
			 */
			if (I915_SELFTEST_ONLY(vma->vm->scrub_64K)) {
				u16 i;

				encode = vma->vm->scratch[0]->encode;
				vaddr = px_vaddr(i915_pt_entry(pd, maybe_64K),
						 &needs_flush);

				for (i = 1; i < index; i += 16)
					memset64(vaddr + i, encode, 15);

				if (needs_flush)
					drm_clflush_virt_range(vaddr, PAGE_SIZE);
			}
		}

		vma->page_sizes.gtt |= page_size;
	} while (iter->rem);
}

static void gen8_ppgtt_insert(struct i915_address_space *vm,
			      struct i915_vm_pt_stash *stash,
			      struct i915_vma *vma,
			      enum i915_cache_level cache_level,
			      u32 flags)
{
	struct sgt_dma iter = sgt_dma(vma);

	gen8_ppgtt_insert_huge(vma, stash, &iter, cache_level, flags);
}

typedef void (*insert_pte_fn)(struct i915_address_space *vm,
			      struct i915_vm_pt_stash *stash,
			      struct i915_vma *vma,
			      enum i915_cache_level cache_level,
			      u32 flags);

static insert_pte_fn get_insert_pte(struct drm_i915_private *i915)
{
	if (GRAPHICS_VER_FULL(i915) >= IP_VER(12, 50))
		return xehpsdv_ppgtt_insert;
	else
		return gen8_ppgtt_insert;
}

static void gen8_ppgtt_insert_entry(struct i915_address_space *vm,
				    dma_addr_t addr,
				    u64 offset,
				    enum i915_cache_level level,
				    u32 flags)
{
	u64 idx = offset >> GEN8_PTE_SHIFT;
	struct i915_page_directory * const pdp =
		gen8_pdp_for_page_index(vm, idx);
	struct i915_page_directory *pd =
		i915_pd_entry(pdp, gen8_pd_index(idx, 2));
	struct i915_page_table *pt = i915_pt_entry(pd, gen8_pd_index(idx, 1));
	bool needs_flush;
	gen8_pte_t *vaddr;

	GEM_BUG_ON(pt->is_compact);

	vaddr = px_vaddr(i915_pt_entry(pd, gen8_pd_index(idx, 1)), &needs_flush);
	vaddr[gen8_pd_index(idx, 0)] = gen8_pte_encode(addr, level, flags);
	if (needs_flush)
		clflush_cache_range(&vaddr[gen8_pd_index(idx, 0)], sizeof(*vaddr));
}

static void __xehpsdv_ppgtt_insert_entry_lm(struct i915_address_space *vm,
					    dma_addr_t addr,
					    u64 offset,
					    enum i915_cache_level level,
					    u32 flags)
{
	u64 idx = offset >> GEN8_PTE_SHIFT;
	struct i915_page_directory * const pdp =
		gen8_pdp_for_page_index(vm, idx);
	struct i915_page_directory *pd =
		i915_pd_entry(pdp, gen8_pd_index(idx, 2));
	struct i915_page_table *pt = i915_pt_entry(pd, gen8_pd_index(idx, 1));
	bool needs_flush;
	gen8_pte_t *vaddr;

	GEM_BUG_ON(!IS_ALIGNED(addr, SZ_64K));
	GEM_BUG_ON(!IS_ALIGNED(offset, SZ_64K));

	if (!pt->is_compact) {
		vaddr = px_vaddr(pd, NULL);
		vaddr[gen8_pd_index(idx, 1)] |= GEN12_PDE_64K;
		pt->is_compact = true;
	}

	vaddr = px_vaddr(pt, &needs_flush);
	vaddr[gen8_pd_index(idx, 0) / 16] = gen8_pte_encode(addr, level, flags);
	if (needs_flush)
		clflush_cache_range(&vaddr[gen8_pd_index(idx, 0)], sizeof(*vaddr));
}

static void xehpsdv_ppgtt_insert_entry(struct i915_address_space *vm,
				       dma_addr_t addr,
				       u64 offset,
				       enum i915_cache_level level,
				       u32 flags)
{
	if (flags & PTE_LM)
		return __xehpsdv_ppgtt_insert_entry_lm(vm, addr, offset,
						       level, flags);

	return gen8_ppgtt_insert_entry(vm, addr, offset, level, flags);
}

static void xehpsdv_ppgtt_insert_huge_wa_bcs(struct i915_vma *vma,
					     struct i915_vm_pt_stash *stash,
					     struct sgt_dma *iter,
					     enum i915_cache_level cache_level,
					     u32 flags)
{
	struct intel_gt *gt = vma->vm->gt;
	struct sgt_dma iterb = sgt_dma(vma);
	struct i915_request *f = NULL;

	do {
		struct intel_pte_bo *bo = get_next_batch(&gt->fpp);
		u32 *cmd = bo->cmd;
		int count = 0;

		xehpsdv_ppgtt_insert_huge(vma, stash, iter, cache_level, flags,
					  &cmd, &count);

		if (!count && iter->rem) {
			drm_err(&gt->i915->drm, "flat ppgtt error no pte to update\n");
			break;
		}

		GEM_BUG_ON(cmd >= bo->cmd + bo->vma->size / sizeof(*bo->cmd));
		*cmd++ = MI_BATCH_BUFFER_END;

		bo->wait = flat_ppgtt_submit(bo->vma);
		if (IS_ERR(bo->wait)) {
			drm_info(&gt->i915->drm,
				 "flat ppgtt huge pte update fallback\n");
			intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
			pte_sync(&f);
			goto fallback;
		}

		i915_request_put(f);
		f = i915_request_get(bo->wait);
		intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
	} while (iter->rem);

	pte_sync(&f);
	return;

fallback:
	xehpsdv_ppgtt_insert_huge(vma, stash, &iterb, cache_level, flags,
				  NULL, NULL);
}

static void gen8_ppgtt_insert_wa_bcs(struct i915_address_space *vm,
				     struct i915_vm_pt_stash *stash,
				     struct i915_vma *vma,
				     enum i915_cache_level cache_level,
				     u32 flags)
{
	struct sgt_dma iter = sgt_dma(vma);
	struct intel_gt *gt = vm->gt;
	intel_wakeref_t wakeref;

	wakeref = l4wa_pm_get(gt);
	if (!wakeref)
		return get_insert_pte(vm->i915)(vm, stash, vma, cache_level, flags);

	if (GRAPHICS_VER_FULL(vm->i915) >= IP_VER(12, 50))
		xehpsdv_ppgtt_insert_huge_wa_bcs(vma, stash, &iter, cache_level, flags);
	else
		gen8_ppgtt_insert_huge(vma, stash, &iter, cache_level, flags);

	intel_gt_pm_put_async_l4(gt, wakeref);
}

static void gen8_ppgtt_insert_wa(struct i915_address_space *vm,
				 struct i915_vm_pt_stash *stash,
			         struct i915_vma *vma,
			         enum i915_cache_level cache_level,
				 u32 flags)
{
	GEM_WARN_ON(i915_gem_idle_engines(vm->i915));

	get_insert_pte(vm->i915)(vm, stash, vma, cache_level, flags);

	GEM_WARN_ON(i915_gem_resume_engines(vm->i915));
}

static int gen8_init_scratch(struct i915_address_space *vm)
{
	struct intel_gt *gt = vm->gt;
	struct intel_pte_bo *bo;
	intel_wakeref_t wakeref;
	u32 *cmd = NULL;
	u32 pte_flags;
	int ret;
	int i;

	/*
	 * If everybody agrees to not to write into the scratch page,
	 * we can reuse it for all vm, keeping contexts and processes separate.
	 */
	if (vm->has_read_only && vm->gt->vm && !i915_is_ggtt(vm->gt->vm)) {
		struct i915_address_space *clone = vm->gt->vm;

		GEM_BUG_ON(!clone->has_read_only);

		vm->scratch_order = clone->scratch_order;
		for (i = 0; i <= vm->top; i++)
			vm->scratch[i] = i915_gem_object_get(clone->scratch[i]);

		vm->poison = clone->poison;
		return 0;
	}

	ret = setup_scratch_page(vm);
	if (ret)
		return ret;

	pte_flags = vm->has_read_only;
	if (i915_gem_object_is_lmem(vm->scratch[0]))
		pte_flags |= PTE_LM;

	vm->scratch[0]->encode =
		gen8_pte_encode(px_dma(vm->scratch[0]),
				I915_CACHE_NONE, pte_flags);
	if (!vm->has_scratch)
		vm->scratch[0]->encode &= ~GEN8_PAGE_PRESENT;

	wakeref = l4wa_pm_get(gt);
	if (wakeref) {
		bo = get_next_batch(&gt->fpp);
		cmd = bo->cmd;
	}
retry:
	for (i = 1; i <= vm->top; i++) {
		struct drm_i915_gem_object *obj;

		obj = vm->alloc_pt_dma(vm, I915_GTT_PAGE_SIZE_4K);
		if (IS_ERR(obj)) {
			ret = PTR_ERR(obj);
			goto free_scratch;
		}

		ret = map_pt_dma(vm, obj);
		if (ret) {
			i915_gem_object_put(obj);
			goto free_scratch;
		}

		if (!cmd)
			fill_px(obj, vm->scratch[i - 1]->encode);
		else
			cmd = fill_page_blt(vm->gt, cmd, px_dma(obj),
					    vm->scratch[i - 1]->encode);

		obj->encode = gen8_pde_encode(px_dma(obj), I915_CACHE_NONE);
		if (!vm->has_scratch)
			obj->encode &= ~GEN8_PAGE_PRESENT;

		vm->scratch[i] = obj;
	}

	if (cmd) {
		GEM_BUG_ON(cmd >= bo->cmd + bo->vma->size + sizeof(*bo->cmd));
		*cmd++ = MI_BATCH_BUFFER_END;

		bo->wait = flat_ppgtt_submit(bo->vma);
		if (IS_ERR(bo->wait))
			cmd = NULL;

		intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
		intel_gt_pm_put_async_l4(gt, wakeref);

		if (!cmd)
			goto retry;
	}

	return 0;

free_scratch:
	while (i--)
		i915_gem_object_put(vm->scratch[i]);
	vm->scratch[0] = NULL;

	if (cmd) {
		intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
		intel_gt_pm_put_async_l4(gt, wakeref);
	}

	return ret;
}

static int gen8_preallocate_top_level_pdp(struct i915_ppgtt *ppgtt)
{
	struct i915_address_space *vm = &ppgtt->vm;
	struct i915_page_directory *pd = ppgtt->pd;
	unsigned int idx;

	GEM_BUG_ON(vm->top != 2);
	GEM_BUG_ON(gen8_pd_top_count(vm) != GEN8_3LVL_PDPES);

	for (idx = 0; idx < GEN8_3LVL_PDPES; idx++) {
		struct i915_page_directory *pde;
		int err;

		pde = alloc_pd(vm);
		if (IS_ERR(pde))
			return PTR_ERR(pde);

		err = map_pt_dma(vm, pde->pt.base);
		if (err) {
			free_pd(vm, pde);
			return err;
		}

		fill_px(pde, vm->scratch[1]->encode);
		set_pd_entry(pd, idx, pde);
		atomic_inc(px_used(pde)); /* keep pinned */
	}
	wmb();

	return 0;
}

static struct i915_page_directory *
gen8_alloc_top_pd(struct i915_address_space *vm)
{
	const unsigned int count = gen8_pd_top_count(vm);
	struct intel_gt *gt = vm->gt;
	struct i915_page_directory *pd;
	intel_wakeref_t wakeref;
	u32 *cmd = NULL;
	int err;

	GEM_BUG_ON(count > I915_PDES);

	pd = __alloc_pd(count);
	if (unlikely(!pd))
		return ERR_PTR(-ENOMEM);

	pd->pt.base = vm->alloc_pt_dma(vm, I915_GTT_PAGE_SIZE_4K);
	if (IS_ERR(pd->pt.base)) {
		err = PTR_ERR(pd->pt.base);
		pd->pt.base = NULL;
		goto err_pd;
	}

	err = map_pt_dma(vm, pd->pt.base);
	if (err)
		goto err_pd;

	wakeref = l4wa_pm_get(gt);
	if (wakeref) {
		struct intel_pte_bo *bo = get_next_batch(&gt->fpp);

		cmd = fill_value_blt(vm->gt, bo->cmd, px_dma(pd), 0, count,
				     vm->scratch[vm->top]->encode);

		GEM_BUG_ON(cmd >= bo->cmd + bo->vma->size / sizeof(*bo->cmd));
		*cmd++ = MI_BATCH_BUFFER_END;

		bo->wait = flat_ppgtt_submit(bo->vma);
		if (IS_ERR(bo->wait))
			cmd = NULL; /* Fallback to legacy way, on err */

		intel_flat_ppgtt_put_pte_bo(&gt->fpp, bo);
		intel_gt_pm_put_async_l4(gt, wakeref);
	}

	if (!cmd)
		fill_page_dma(px_base(pd), vm->scratch[vm->top]->encode, count);

	atomic_inc(px_used(pd)); /* mark as pinned */
	return pd;

err_pd:
	free_pd(vm, pd);
	return ERR_PTR(err);
}

int intel_flat_lmem_ppgtt_init(struct i915_address_space *vm,
			       struct drm_mm_node *node)
{
	struct i915_page_directory *pd = i915_vm_to_ppgtt(vm)->pd;
	unsigned int idx, count;
	u64 start, end, head;
	gen8_pte_t *vaddr;
	gen8_pte_t encode;
	bool needs_flush;
	int lvl;
	int err;

	/*
	 * Map all of LMEM in a kernel internal vm(could be cloned?). This gives
	 * us the useful property where the va == pa, which lets us touch any
	 * part of LMEM, from the gpu without having to dynamically bind
	 * anything. We map the entries as 1G GTT entries, such that we only
	 * need one pdpe for every 1G of LMEM, i.e a single pdp can cover 512G
	 * of LMEM.
	 */
	GEM_BUG_ON(!IS_ALIGNED(node->start | node->size, SZ_1G));
	GEM_BUG_ON(node->size > SZ_1G * GEN8_PDES);

	start = node->start >> GEN8_PTE_SHIFT;
	end = start + (node->size >> GEN8_PTE_SHIFT);
	encode = vm->pte_encode(node->start, 0, PTE_LM) | GEN8_PDPE_PS_1G;

	/* The vm->mm may be hiding the first page already */
	head = vm->mm.head_node.start + vm->mm.head_node.size;
	if (node->start < head) {
		GEM_BUG_ON(node->size < head - node->start);
		node->size -= head - node->start;
		node->start = head;
	}

	err = drm_mm_reserve_node(&vm->mm, node);
	if (err) {
		struct drm_printer p = drm_err_printer(__func__);

		drm_printf(&p,
			   "flat node:[%llx + %llx] already taken\n",
			   node->start, node->size);
		drm_mm_print(&vm->mm, &p);

		return err;
	}

	lvl = vm->top;
	while (lvl >= 3) { /* allocate everything up to and including the pdp */
		struct i915_page_directory *pde;

		/* Check we don't cross into the next page directory */
		GEM_BUG_ON(gen8_pd_range(start, end, lvl, &idx) != 1);

		idx = gen8_pd_index(start, lvl);
		pde = pd->entry[idx];
		if (!pde) {
			pde = alloc_pd(vm);
			if (IS_ERR(pde)) {
				err = PTR_ERR(pde);
				goto err_out;
			}

			err = map_pt_dma(vm, pde->pt.base);
			if (err) {
				free_pd(vm, pde);
				goto err_out;
			}

			fill_px(pde, vm->scratch[lvl]->encode);
		}

		atomic_inc(&pde->pt.used); /* alive until vm is gone */
		set_pd_entry(pd, idx, pde);
		pd = pde;
		lvl--;
	}

	vaddr = px_vaddr(pd, &needs_flush);
	count = gen8_pd_range(start, end, lvl, &idx);
	do {
		vaddr[idx++] = encode;
		encode += SZ_1G;
	} while (--count);

	return 0;

err_out:
	drm_mm_remove_node(node);
	return err;
}

void intel_flat_lmem_ppgtt_fini(struct i915_address_space *vm,
				struct drm_mm_node *node)
{
	if (!drm_mm_node_allocated(node))
		return;

	GEM_BUG_ON(node->mm != &vm->mm);
	drm_mm_remove_node(node);
}

/*
 * GEN8 legacy ppgtt programming is accomplished through a max 4 PDP registers
 * with a net effect resembling a 2-level page table in normal x86 terms. Each
 * PDP represents 1GB of memory 4 * 512 * 512 * 4096 = 4GB legacy 32b address
 * space.
 *
 */
struct i915_ppgtt *gen8_ppgtt_create(struct intel_gt *gt, u32 flags)
{
	struct i915_page_directory *pd;
	struct i915_ppgtt *ppgtt;
	int err;

	ppgtt = kzalloc(sizeof(*ppgtt), GFP_KERNEL);
	if (!ppgtt)
		return ERR_PTR(-ENOMEM);

	err = ppgtt_init(ppgtt, gt);
	if (err) {
		kfree(ppgtt);
		return ERR_PTR(err);
	}

	ppgtt->vm.pd_shift = ilog2(SZ_4K * SZ_4K / sizeof(gen8_pte_t));

	/*
	 * From bdw, there is hw support for read-only pages in the PPGTT.
	 *
	 * Gen11 has HSDES#:1807136187 unresolved. Disable ro support
	 * for now.
	 *
	 * Gen12 has inherited the same read-only fault issue from gen11.
	 */
	ppgtt->vm.has_read_only = !IS_GRAPHICS_VER(gt->i915, 11, 12);

	if (HAS_LMEM(gt->i915))
		ppgtt->vm.alloc_pt_dma = alloc_pt_lmem;
	else
		ppgtt->vm.alloc_pt_dma = alloc_pt_dma;

	/*
	 * On some platforms the hw has dropped support for 4K GTT pages
	 * when dealing with LMEM, and due to the design of 64K GTT
	 * pages in the hw, we can only mark the *entire* page-table as
	 * operating in 64K GTT mode, since the enable bit is still on
	 * the pde, and not the pte. And since we still need to allow
	 * 4K GTT pages for SMEM objects, we can't have a "normal" 4K
	 * page-table with scratch pointing to LMEM, since that's
	 * undefined from the hw pov. The simplest solution is to just
	 * move the 64K scratch page to SMEM on all platforms and call
	 * it a day, since that should work for all configurations.
	 *
	 * Using SMEM instead of LMEM has the additional advantage of
	 * not reserving high performance memory for a "never" used
	 * filler page. It also removes the device access that would
	 * be required to initialise the scratch page, reducing pressure
	 * on an even scarcer resource.
	 */
	ppgtt->vm.alloc_scratch_dma = alloc_pt_dma;

	ppgtt->vm.pte_encode = gen8_pte_encode;

	if (GRAPHICS_VER_FULL(gt->i915) >= IP_VER(12, 50)) {
		ppgtt->vm.insert_entries = xehpsdv_ppgtt_insert;
		ppgtt->vm.insert_page = xehpsdv_ppgtt_insert_entry;
		ppgtt->vm.mm.color_adjust = xehpsdv_ppgtt_color_adjust;
	} else {
		ppgtt->vm.insert_entries = gen8_ppgtt_insert;
		ppgtt->vm.insert_page = gen8_ppgtt_insert_entry;
	}
	ppgtt->vm.allocate_va_range = gen8_ppgtt_alloc;
	ppgtt->vm.clear_range = gen8_ppgtt_clear;
	ppgtt->vm.foreach = gen8_ppgtt_foreach;
	ppgtt->vm.cleanup = gen8_ppgtt_cleanup;

	ppgtt->vm.bind_async_flags = I915_VMA_LOCAL_BIND;
	if (i915_is_mem_wa_enabled(gt->i915, I915_WA_USE_FLAT_PPGTT_UPDATE)) {
		ppgtt->vm.insert_entries = gen8_ppgtt_insert_wa_bcs;
		ppgtt->vm.allocate_va_range = gen8_ppgtt_alloc_wa_bcs;
		ppgtt->vm.clear_range = gen8_ppgtt_clear_wa_bcs;
	} else if (i915_is_mem_wa_enabled(gt->i915, I915_WA_IDLE_GPU_BEFORE_UPDATE)) {
		ppgtt->vm.insert_entries = gen8_ppgtt_insert_wa;
		ppgtt->vm.allocate_va_range = gen8_ppgtt_alloc_wa;
		ppgtt->vm.clear_range = gen8_ppgtt_clear_wa;
	}

	if (flags & PRELIM_I915_VM_CREATE_FLAGS_DISABLE_SCRATCH)
		ppgtt->vm.has_scratch = false;

	err = gen8_init_scratch(&ppgtt->vm);
	if (err)
		goto err_put;

	pd = gen8_alloc_top_pd(&ppgtt->vm);
	if (IS_ERR(pd)) {
		err = PTR_ERR(pd);
		goto err_put;
	}
	ppgtt->pd = pd;

	if (i915_vm_lvl(&ppgtt->vm) == 3) {
		err = gen8_preallocate_top_level_pdp(ppgtt);
		if (err)
			goto err_put;
	}

	if (intel_vgpu_active(gt->i915))
		gen8_ppgtt_notify_vgt(ppgtt, true);

	return ppgtt;

err_put:
	i915_vm_put(&ppgtt->vm);
	return ERR_PTR(err);
}
