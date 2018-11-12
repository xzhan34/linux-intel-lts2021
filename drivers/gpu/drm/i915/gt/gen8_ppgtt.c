// SPDX-License-Identifier: MIT
/*
 * Copyright © 2020 Intel Corporation
 */

#include <linux/log2.h>

#include "gem/i915_gem_lmem.h"

#include "gen8_ppgtt.h"
#include "i915_scatterlist.h"
#include "i915_trace.h"
#include "i915_pvinfo.h"
#include "i915_vgpu.h"
#include "intel_gt.h"
#include "intel_gtt.h"

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

	if (i915_vm_is_4lvl(&ppgtt->vm)) {
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
			      u64 start, const u64 end, int lvl)
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

		if (atomic_fetch_inc(&pt->used) >> gen8_pd_shift(1) &&
		    gen8_pd_contains(start, end, lvl)) {
			DBG("%s(%p):{ lvl:%d, idx:%d, start:%llx, end:%llx } removing pd\n",
			    __func__, vm, lvl + 1, idx, start, end);
			clear_pd_entry(pd, idx, scratch);
			__gen8_ppgtt_cleanup(vm, as_pd(pt), I915_PDES, lvl);
			start += (u64)I915_PDES << gen8_pd_shift(lvl);
			continue;
		}

		if (lvl) {
			start = __gen8_ppgtt_clear(vm, as_pd(pt),
						   start, end, lvl);
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
			memset64(vaddr + pte,
				 vm->scratch[0]->encode,
				 num_ptes);

			atomic_sub(count, &pt->used);
			start += count;
		}

		if (release_pd_entry(pd, idx, pt, scratch))
			free_px(vm, pt, lvl);
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
			   start, start + length, vm->top);
}

static void __gen8_ppgtt_alloc(struct i915_address_space * const vm,
			       struct i915_vm_pt_stash *stash,
			       struct i915_page_directory * const pd,
			       u64 * const start, const u64 end, int lvl)
{
	unsigned int idx, len;

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

			fill_px(pt, vm->scratch[lvl]->encode);

			spin_lock(&pd->lock);
			if (likely(!pd->entry[idx])) {
				stash->pt[!!lvl] = pt->stash;
				atomic_set(&pt->used, 0);
				set_pd_entry(pd, idx, pt);
			} else {
				pt = pd->entry[idx];
			}
		}

		if (lvl) {
			atomic_inc(&pt->used);
			spin_unlock(&pd->lock);

			__gen8_ppgtt_alloc(vm, stash,
					   as_pd(pt), start, end, lvl);

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
	} while (idx++, --len);
	spin_unlock(&pd->lock);
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
			   &start, start + length, vm->top);
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
			  struct sgt_dma *iter,
			  enum i915_cache_level cache_level,
			  u32 flags)
{
	const gen8_pte_t pte_encode = vma->vm->pte_encode(0, cache_level, flags);
	unsigned int rem = sg_dma_len(iter->sg);
	u64 start = vma->node.start;

	GEM_BUG_ON(!i915_vm_is_4lvl(vma->vm));

	do {
		struct i915_page_directory * const pdp =
			gen8_pdp_for_page_address(vma->vm, start);
		struct i915_page_directory * const pd =
			i915_pd_entry(pdp, __gen8_pte_index(start, 2));
		struct i915_page_table *pt =
			i915_pt_entry(pd, __gen8_pte_index(start, 1));
		gen8_pte_t encode = pte_encode;
		unsigned int page_size;
		gen8_pte_t *vaddr;
		bool needs_flush;
		u16 index, max;

		max = I915_PDES;

		if (vma->page_sizes.sg & I915_GTT_PAGE_SIZE_2M &&
		    IS_ALIGNED(iter->dma, I915_GTT_PAGE_SIZE_2M) &&
		    rem >= I915_GTT_PAGE_SIZE_2M &&
		    !__gen8_pte_index(start, 0)) {
			index = __gen8_pte_index(start, 1);
			encode |= GEN8_PDE_PS_2M;
			page_size = I915_GTT_PAGE_SIZE_2M;

			vaddr = px_vaddr(pd, &needs_flush);
		} else {
			if (encode & GEN12_PPGTT_PTE_LM) {
				GEM_BUG_ON(__gen8_pte_index(start, 0) % 16);
				GEM_BUG_ON(rem < I915_GTT_PAGE_SIZE_64K);
				GEM_BUG_ON(!IS_ALIGNED(iter->dma,
						       I915_GTT_PAGE_SIZE_64K));

				index = __gen8_pte_index(start, 0) / 16;
				page_size = I915_GTT_PAGE_SIZE_64K;

				max /= 16;

				vaddr = px_vaddr(pd, &needs_flush);
				vaddr[__gen8_pte_index(start, 1)] |= GEN12_PDE_64K;

				pt->is_compact = true;
			} else {
				GEM_BUG_ON(pt->is_compact);
				index =  __gen8_pte_index(start, 0);
				page_size = I915_GTT_PAGE_SIZE;
			}

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

				if (unlikely(!IS_ALIGNED(iter->dma, page_size)))
					break;
			}
		} while (rem >= page_size && index < max);

		if (needs_flush)
			drm_clflush_virt_range(vaddr, PAGE_SIZE);

		vma->page_sizes.gtt |= page_size;
	} while (iter->rem);
}

static void xehpsdv_ppgtt_insert(struct i915_address_space *vm,
				 struct i915_vm_pt_stash *stash,
				 struct i915_vma *vma,
				 enum i915_cache_level cache_level,
				 u32 flags)
{
	struct sgt_dma iter = sgt_dma(vma);

	xehpsdv_ppgtt_insert_huge(vma, &iter, cache_level, flags);
}

static void gen8_ppgtt_insert_huge(struct i915_vma *vma,
				   struct sgt_dma *iter,
				   enum i915_cache_level cache_level,
				   u32 flags)
{
	const gen8_pte_t pte_encode = gen8_pte_encode(0, cache_level, flags);
	unsigned int rem = min_t(u64, sg_dma_len(iter->sg), iter->rem);
	u64 start = i915_vma_offset(vma);

	GEM_BUG_ON(!i915_vm_is_4lvl(vma->vm));

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

		if (vma->page_sizes.sg & I915_GTT_PAGE_SIZE_2M &&
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

	gen8_ppgtt_insert_huge(vma, &iter, cache_level, flags);
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

static int gen8_init_scratch(struct i915_address_space *vm)
{
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

		fill_px(obj, vm->scratch[i - 1]->encode);
		obj->encode = gen8_pde_encode(px_dma(obj), I915_CACHE_NONE);

		vm->scratch[i] = obj;
	}

	return 0;

free_scratch:
	while (i--)
		i915_gem_object_put(vm->scratch[i]);
	vm->scratch[0] = NULL;
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
	struct i915_page_directory *pd;
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
struct i915_ppgtt *gen8_ppgtt_create(struct intel_gt *gt)
{
	struct i915_page_directory *pd;
	struct i915_ppgtt *ppgtt;
	int err;

	ppgtt = kzalloc(sizeof(*ppgtt), GFP_KERNEL);
	if (!ppgtt)
		return ERR_PTR(-ENOMEM);

	ppgtt_init(ppgtt, gt);
	ppgtt->vm.top = i915_vm_is_4lvl(&ppgtt->vm) ? 3 : 2;
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

	ppgtt->vm.bind_async_flags = I915_VMA_LOCAL_BIND;
	if (HAS_64K_PAGES(gt->i915))
		ppgtt->vm.insert_entries = xehpsdv_ppgtt_insert;
	else
		ppgtt->vm.insert_entries = gen8_ppgtt_insert;
	if (HAS_64K_PAGES(gt->i915))
		ppgtt->vm.insert_page = xehpsdv_ppgtt_insert_entry;
	else
		ppgtt->vm.insert_page = gen8_ppgtt_insert_entry;
	ppgtt->vm.allocate_va_range = gen8_ppgtt_alloc;
	ppgtt->vm.clear_range = gen8_ppgtt_clear;
	ppgtt->vm.foreach = gen8_ppgtt_foreach;
	ppgtt->vm.cleanup = gen8_ppgtt_cleanup;

	if (HAS_64K_PAGES(gt->i915))
		ppgtt->vm.mm.color_adjust = xehpsdv_ppgtt_color_adjust;

	err = gen8_init_scratch(&ppgtt->vm);
	if (err)
		goto err_put;

	pd = gen8_alloc_top_pd(&ppgtt->vm);
	if (IS_ERR(pd)) {
		err = PTR_ERR(pd);
		goto err_put;
	}
	ppgtt->pd = pd;

	if (!i915_vm_is_4lvl(&ppgtt->vm)) {
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
