/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __INTEL_IOV_PROVISIONING_H__
#define __INTEL_IOV_PROVISIONING_H__

#include <linux/types.h>

struct drm_printer;
struct intel_iov;

void intel_iov_provisioning_init_early(struct intel_iov *iov);
void intel_iov_provisioning_release(struct intel_iov *iov);
void intel_iov_provisioning_init(struct intel_iov *iov);
void intel_iov_provisioning_fini(struct intel_iov *iov);

int intel_iov_provisioning_auto(struct intel_iov *iov, unsigned int num_vfs);
int intel_iov_provisioning_verify(struct intel_iov *iov, unsigned int num_vfs);

int intel_iov_provisioning_set_ggtt(struct intel_iov *iov, unsigned int id, u64 size);
u64 intel_iov_provisioning_get_ggtt(struct intel_iov *iov, unsigned int id);
int intel_iov_provisioning_set_spare_ggtt(struct intel_iov *iov, u64 size);
u64 intel_iov_provisioning_get_spare_ggtt(struct intel_iov *iov);
u64 intel_iov_provisioning_query_free_ggtt(struct intel_iov *iov);
u64 intel_iov_provisioning_query_max_ggtt(struct intel_iov *iov);

int intel_iov_provisioning_set_ctxs(struct intel_iov *iov, unsigned int id, u16 num_ctxs);
u16 intel_iov_provisioning_get_ctxs(struct intel_iov *iov, unsigned int id);
int intel_iov_provisioning_set_spare_ctxs(struct intel_iov *iov, u16 spare);
u16 intel_iov_provisioning_get_spare_ctxs(struct intel_iov *iov);
u16 intel_iov_provisioning_query_max_ctxs(struct intel_iov *iov);
u16 intel_iov_provisioning_query_free_ctxs(struct intel_iov *iov);

int intel_iov_provisioning_set_dbs(struct intel_iov *iov, unsigned int id, u16 num_dbs);
u16 intel_iov_provisioning_get_dbs(struct intel_iov *iov, unsigned int id);
int intel_iov_provisioning_set_spare_dbs(struct intel_iov *iov, u16 spare);
u16 intel_iov_provisioning_get_spare_dbs(struct intel_iov *iov);

int intel_iov_provisioning_set_exec_quantum(struct intel_iov *iov, unsigned int id, u32 exec_quantum);
u32 intel_iov_provisioning_get_exec_quantum(struct intel_iov *iov, unsigned int id);

int intel_iov_provisioning_set_preempt_timeout(struct intel_iov *iov, unsigned int id, u32 preempt_timeout);
u32 intel_iov_provisioning_get_preempt_timeout(struct intel_iov *iov, unsigned int id);

int intel_iov_provisioning_print_ggtt(struct intel_iov *iov, struct drm_printer *p);
int intel_iov_provisioning_print_ctxs(struct intel_iov *iov, struct drm_printer *p);
int intel_iov_provisioning_print_dbs(struct intel_iov *iov, struct drm_printer *p);

int intel_iov_provisioning_print_available_ggtt(struct intel_iov *iov, struct drm_printer *p);

#endif /* __INTEL_IOV_PROVISIONING_H__ */
