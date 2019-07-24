/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2019 Intel Corporation
 */

#ifndef __I915_SVM_H
#define __I915_SVM_H

#include <linux/hmm.h>

#include "i915_drv.h"

#if defined(CONFIG_DRM_I915_SVM)
struct i915_svm {
	/* i915 address space */
	struct i915_address_space *vm;

	struct mmu_notifier notifier;
	struct mutex mutex; /* protects svm operations */
	/*
	 * XXX: Probably just make use of mmu_notifier's reference
	 * counting (get/put) instead of our own.
	 */
	struct kref ref;
};

int i915_gem_vm_bind_svm_buffer(struct i915_address_space *vm,
				struct prelim_drm_i915_gem_vm_bind *va);
int i915_gem_vm_unbind_svm_buffer(struct i915_address_space *vm,
				  struct prelim_drm_i915_gem_vm_bind *va);
void i915_svm_unbind_mm(struct i915_address_space *vm);
int i915_svm_bind_mm(struct i915_address_space *vm);
static inline bool i915_vm_is_svm_enabled(struct i915_address_space *vm)
{
	return vm->svm;
}

#else

struct i915_svm { };
static inline int i915_gem_vm_bind_svm_buffer(struct i915_address_space *vm,
					      struct prelim_drm_i915_gem_vm_bind *va)
{ return -ENOTSUPP; }
static inline int i915_gem_vm_unbind_svm_buffer(struct i915_address_space *vm,
						struct prelim_drm_i915_gem_vm_bind *va)
{ return -ENOTSUPP; }
static inline void i915_svm_unbind_mm(struct i915_address_space *vm) { }
static inline int i915_svm_bind_mm(struct i915_address_space *vm)
{ return -ENOTSUPP; }
static inline bool i915_vm_is_svm_enabled(struct i915_address_space *vm)
{ return false; }

#endif

#endif /* __I915_SVM_H */
