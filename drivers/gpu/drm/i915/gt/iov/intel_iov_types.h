/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2022 Intel Corporation
 */

#ifndef __INTEL_IOV_TYPES_H__
#define __INTEL_IOV_TYPES_H__

#include <linux/mutex.h>
#include <drm/drm_mm.h>

/**
 * struct intel_iov_config - IOV configuration data.
 * @ggtt_region: GGTT region.
 * @num_ctxs: number of GuC submission contexts.
 * @begin_ctx: start index of GuC contexts.
 * @num_dbs: number of GuC doorbells.
 * @begin_db: start index of GuC doorbells.
 * @exec_quantum: execution-quantum in milliseconds.
 * @preempt_timeout: preemption timeout in microseconds.
 */
struct intel_iov_config {
	struct drm_mm_node ggtt_region;
	u16 num_ctxs;
	u16 begin_ctx;
	u16 num_dbs;
	u16 begin_db;
	u32 exec_quantum;
	u32 preempt_timeout;
};

/**
 * struct intel_iov_spare_config - PF spare configuration data.
 * @ggtt_size: GGTT size.
 * @num_ctxs: number of GuC submission contexts.
 * @num_dbs: number of GuC doorbells.
 */
struct intel_iov_spare_config {
	u64 ggtt_size;
	u16 num_ctxs;
	u16 num_dbs;
};

/**
 * struct intel_iov_sysfs - IOV sysfs data.
 * @entries: array with kobjects that represent PF and VFs.
 */
struct intel_iov_sysfs {
	struct kobject **entries;
};

/**
 * struct intel_iov_policies - IOV policies.
 * @sched_if_idle: controls strict scheduling.
 */
struct intel_iov_policies {
	bool sched_if_idle;
};

/**
 * struct intel_iov_provisioning - IOV provisioning data.
 * @auto_mode: indicates manual or automatic provisioning mode.
 * @policies: provisioning policies.
 * @configs: flexible array with configuration data for PF and VFs.
 * @lock: protects provisionining data
 */
struct intel_iov_provisioning {
	bool auto_mode;
	struct intel_iov_policies policies;
	struct intel_iov_spare_config spare;
	struct intel_iov_config *configs;
	struct mutex lock;
};

#define VFID(n)		(n)
#define PFID		VFID(0)

/**
 * struct intel_iov - I/O Virtualization related data.
 * @pf.sysfs: sysfs data.
 * @pf.provisioning: provisioning data.
 */
struct intel_iov {
	struct {
		struct intel_iov_sysfs sysfs;
		struct intel_iov_provisioning provisioning;
	} pf;
};

#endif /* __INTEL_IOV_TYPES_H__ */
