// SPDX-License-Identifier: MIT
/*
 * Copyright(c) 2022 Intel Corporation. All rights reserved.
 */

#include "gt/intel_gt.h"

struct pte_testcase {
	bool (*test)(struct intel_iov *iov, void __iomem *pte_addr, u64 ggtt_addr, gen8_pte_t *out);
};

static void iov_set_pte(struct intel_iov *iov, void __iomem *addr, gen8_pte_t pte)
{
	gen8_set_pte(addr, pte);
}

static u64 iov_get_pte(struct intel_iov *iov, void __iomem *addr)
{
	return gen8_get_pte(addr);
}

static bool
pte_is_value_modifiable(struct intel_iov *iov, void __iomem *pte_addr, u64 ggtt_addr,
			const u64 mask, gen8_pte_t *out)
{
	gen8_pte_t original_pte;
	bool ret_val = true;
	gen8_pte_t read_pte;
	gen8_pte_t write_pte;

	original_pte = iov->selftest.mmio_get_pte(iov, pte_addr);

	write_pte = original_pte ^ mask;
	iov->selftest.mmio_set_pte(iov, pte_addr, write_pte);
	read_pte = iov->selftest.mmio_get_pte(iov, pte_addr);

	*out = read_pte;

	if ((read_pte & mask) != (write_pte & mask))
		ret_val = false;

	iov->selftest.mmio_set_pte(iov, pte_addr, original_pte);

	return ret_val;
}

static bool
pte_gpa_modifiable(struct intel_iov *iov, void __iomem *pte_addr, u64 ggtt_addr, gen8_pte_t *out)
{
	return pte_is_value_modifiable(iov, pte_addr, ggtt_addr, GEN12_GGTT_PTE_ADDR_MASK, out);
}

static bool
pte_valid_modifiable(struct intel_iov *iov, void __iomem *pte_addr, u64 ggtt_addr, gen8_pte_t *out)
{
	return pte_is_value_modifiable(iov, pte_addr, ggtt_addr, GEN6_PTE_VALID, out);
}

static bool
pte_vfid_modifiable(struct intel_iov *iov, void __iomem *pte_addr, u64 ggtt_addr, gen8_pte_t *out)
{
	return pte_is_value_modifiable(iov, pte_addr, ggtt_addr, TGL_GGTT_PTE_VFID_MASK, out);
}

static bool run_test_on_pte(struct intel_iov *iov, void __iomem *pte_addr, u64 ggtt_addr,
			    const struct pte_testcase *tc, u16 vfid)
{
	gen8_pte_t read_val;

	if (!tc->test(iov, pte_addr, ggtt_addr, &read_val)) {
		IOV_ERROR(iov, "%ps.%u failed at GGTT address %#llx. PTE is: %#llx\n",
			  tc->test, vfid, ggtt_addr, read_val);
		return false;
	}

	return true;
}

#define for_each_pte(pte_addr__, ggtt_addr__, gsm__, ggtt_block__, step__) \
	for ((ggtt_addr__) = ((ggtt_block__)->start), \
	     (pte_addr__) = (gsm__) + (ggtt_addr_to_pte_offset((ggtt_addr__))); \
	     (ggtt_addr__) < ((ggtt_block__)->start + (ggtt_block__)->size); \
	     (ggtt_addr__) += (step__), \
	     (pte_addr__) = (gsm__) + (ggtt_addr_to_pte_offset((ggtt_addr__))))

static bool
run_test_on_ggtt_block(struct intel_iov *iov, void __iomem *gsm, struct drm_mm_node *ggtt_block,
		       const struct pte_testcase *tc, u16 vfid)
{
	void __iomem *pte_addr;
	u64 ggtt_addr;

	GEM_BUG_ON(!IS_ALIGNED(ggtt_block->start, I915_GTT_PAGE_SIZE_4K));

	for_each_pte(pte_addr, ggtt_addr, gsm, ggtt_block, I915_GTT_PAGE_SIZE_4K) {
		if (!run_test_on_pte(iov, pte_addr, ggtt_addr, tc, vfid))
			return false;
		cond_resched();
	}

	return true;
}

#define for_each_pte_test(tc__, testcases__) \
	for ((tc__) = (testcases__); (tc__)->test; (tc__)++)

/*
 * We want to check state of GGTT entries of VF's.
 * PF has the right to modify the GGTT PTE in the whole range,
 * so any problem in writing an entry will be reported as an error
 */
static int igt_pf_iov_ggtt(struct intel_iov *iov)
{
	const u64 size_ggtt_block = SZ_2M;
	struct i915_ggtt *ggtt = iov_to_gt(iov)->ggtt;
	struct drm_mm_node ggtt_block = {};
	static struct pte_testcase pte_testcases[] = {
		{ .test = pte_gpa_modifiable },
		{ .test = pte_vfid_modifiable },
		{ .test = pte_valid_modifiable },
		{ },
	};
	int failed = 0;
	int err;
	u16 vfid;
	struct pte_testcase *tc;

	BUILD_BUG_ON(!IS_ALIGNED(size_ggtt_block, I915_GTT_PAGE_SIZE_4K));
	GEM_BUG_ON(!intel_iov_is_pf(iov));

	mutex_lock(&ggtt->vm.mutex);
	err = i915_gem_gtt_insert(&ggtt->vm, &ggtt_block, size_ggtt_block, 0,
				  I915_COLOR_UNEVICTABLE, 0, U64_MAX, PIN_HIGH);
	mutex_unlock(&ggtt->vm.mutex);

	if (err < 0)
		goto out;

	for (vfid = 1; vfid <= pf_get_totalvfs(iov); vfid++) {
		IOV_DEBUG(iov, "Checking VF%u range [%#llx-%#llx]", vfid, ggtt_block.start,
			  ggtt_block.start + ggtt_block.size);
		i915_ggtt_set_space_owner(ggtt, vfid, &ggtt_block);
		for_each_pte_test(tc, pte_testcases) {
			IOV_DEBUG(iov, "Run '%ps' check\n", tc->test);
			if (!run_test_on_ggtt_block(iov, ggtt->gsm, &ggtt_block, tc, vfid))
				failed++;
		}

		i915_ggtt_set_space_owner(ggtt, 0, &ggtt_block);
	}

	drm_mm_remove_node(&ggtt_block);

	if (failed)
		IOV_ERROR(iov, "%s: Count of failed test cases: %d", __func__, failed);

	return failed ? -EPERM : 0;
out:
	return err;
}

static int igt_pf_ggtt(void *arg)
{
	struct drm_i915_private *i915 = arg;

	GEM_BUG_ON(!IS_SRIOV_PF(i915));

	return igt_pf_iov_ggtt(&to_gt(i915)->iov);
}

static void init_defaults_pte_io(struct intel_iov *iov)
{
	iov->selftest.mmio_set_pte = iov_set_pte;
	iov->selftest.mmio_get_pte = iov_get_pte;
}

int intel_iov_ggtt_live_selftests(struct drm_i915_private *i915)
{
	static const struct i915_subtest pf_tests[] = {
		SUBTEST(igt_pf_ggtt),
	};
	intel_wakeref_t wakeref;
	int ret = 0;

	init_defaults_pte_io(&to_gt(i915)->iov);

	wakeref = intel_runtime_pm_get(&i915->runtime_pm);

	if (IS_SRIOV_PF(i915))
		ret = i915_subtests(pf_tests, i915);

	intel_runtime_pm_put(&i915->runtime_pm, wakeref);

	return ret;
}
