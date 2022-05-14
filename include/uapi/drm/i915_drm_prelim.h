/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2021 Intel Corporation
 */

#ifndef __I915_DRM_PRELIM_H__
#define __I915_DRM_PRELIM_H__

#include "i915_drm.h"

/*
 * Modifications to structs/values defined here are subject to
 * backwards-compatibility constraints.
 *
 * Internal/downstream declarations must be added here, not to
 * i915_drm.h. The values in i915_drm_prelim.h must also be kept
 * synchronized with values in i915_drm.h.
 */

struct prelim_i915_user_extension {
#define PRELIM_I915_USER_EXT		(1 << 16)
#define PRELIM_I915_USER_EXT_MASK(x)	(x & 0xffff)
};

/* This API has been removed.  On the off chance someone somewhere has
 * attempted to use it, never re-use this extension number.
 */

#define PRELIM_I915_CONTEXT_CREATE_EXT_CLONE	(PRELIM_I915_USER_EXT | 1)

/*
 * PRELIM UAPI VERSION - /sys/<...>/drm/card<n>/prelim_uapi_version
 * MAJOR - to be incremented right after a major public Production branch
 *         release containing PRELIM uAPIs
 *         PROD_DG1_201210.0 released so starting with major = 2, although
 *         it didn't have the proper prelim api infrastructure yet.
 * MINOR - Reset to 0 when MAJOR is bumped.
 *         Bumped as needed when some kind of API incompatibility is identified.
 *         This patch, which introduces this, should be the only patch in
 *         the pile that is changing this number.
 */
#define PRELIM_UAPI_MAJOR	2
#define PRELIM_UAPI_MINOR	1

#define PRELIM_PERF_VERSION	(1000)

/**
 * Returns OA buffer properties to be used with mmap.
 *
 * This ioctl is available in perf revision 1000.
 */
#define PRELIM_I915_PERF_IOCTL_GET_OA_BUFFER_INFO _IOWR('i', 0x80, struct prelim_drm_i915_perf_oa_buffer_info)

/**
 * OA buffer size and offset.
 *
 * OA output buffer
 *   type: 0
 *   flags: mbz
 *
 *   After querying the info, pass (size,offset) to mmap(),
 *
 *   mmap(0, info.size, PROT_READ, MAP_PRIVATE, perf_fd, info.offset).
 *
 *   Note that only a private (not shared between processes, or across fork())
 *   read-only mmapping is allowed.
 *
 *   Userspace must treat the incoming data as tainted, but it conforms to the OA
 *   format as specified by user config. The buffer provides reports that have
 *   OA counters - A, B and C.
 */
struct prelim_drm_i915_perf_oa_buffer_info {
	__u32 type;   /* in */
	__u32 flags;  /* in */
	__u64 size;   /* out */
	__u64 offset; /* out */
	__u64 rsvd;   /* mbz */
};

struct prelim_drm_i915_query_item {
#define PRELIM_DRM_I915_QUERY			(1 << 16)
#define PRELIM_DRM_I915_QUERY_MASK(x)		(x & 0xffff)
/*#define PRELIM_DRM_I915_QUERY_NEW_STUFF	(PRELIM_DRM_I915_QUERY | <id>) */
};

#endif /* __I915_DRM_PRELIM_H__ */
