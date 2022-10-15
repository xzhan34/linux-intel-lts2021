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

/* PRELIM ioctl's */
/* PRELIM ioctl numbers go down from 0x5f */
#define PRELIM_DRM_I915_RESERVED_FOR_VERSION	0x5f
/* 0x5e is free, please use if needed */


#define PRELIM_DRM_IOCTL_I915_GEM_CREATE_EXT		DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_CREATE, struct prelim_drm_i915_gem_create_ext)
/* End PRELIM ioctl's */

struct prelim_drm_i915_gem_create_ext {

	/**
	 * Requested size for the object.
	 *
	 * The (page-aligned) allocated size for the object will be returned.
	 */
	__u64 size;
	/**
	 * Returned handle for the object.
	 *
	 * Object handles are nonzero.
	 */
	__u32 handle;
	__u32 pad;
#define PRELIM_I915_GEM_CREATE_EXT_SETPARAM	(PRELIM_I915_USER_EXT | 1)
#define PRELIM_I915_GEM_CREATE_EXT_PROTECTED_CONTENT   (PRELIM_I915_USER_EXT | 2)
#define PRELIM_I915_GEM_CREATE_EXT_FLAGS_UNKNOWN \
	(~(PRELIM_I915_GEM_CREATE_EXT_SETPARAM | \
	   PRELIM_I915_GEM_CREATE_EXT_PROTECTED_CONTENT))
	__u64 extensions;
};

struct prelim_drm_i915_gem_object_param {
	/* Object handle (0 for I915_GEM_CREATE_EXT_SETPARAM) */
	__u32 handle;

	/* Data pointer size */
	__u32 size;

/*
 * PRELIM_I915_OBJECT_PARAM:
 *
 * Select object namespace for the param.
 */
#define PRELIM_I915_OBJECT_PARAM  (1ull << 48)

	__u64 param;

	/* Data value or pointer */
	__u64 data;
};

struct prelim_drm_i915_gem_create_ext_setparam {
	struct i915_user_extension base;
	struct prelim_drm_i915_gem_object_param param;
};

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

struct prelim_drm_i915_gem_memory_class_instance {
	__u16 memory_class; /* see enum prelim_drm_i915_gem_memory_class */
	__u16 memory_instance;
};

struct prelim_drm_i915_query_item {
#define PRELIM_DRM_I915_QUERY			(1 << 16)
#define PRELIM_DRM_I915_QUERY_MASK(x)		(x & 0xffff)
#define PRELIM_DRM_I915_QUERY_MEMORY_REGIONS	(PRELIM_DRM_I915_QUERY | 4)
};

enum prelim_drm_i915_gem_memory_class {
	PRELIM_I915_MEMORY_CLASS_SYSTEM = 0,
	PRELIM_I915_MEMORY_CLASS_DEVICE,
};

/**
 * struct prelim_drm_i915_memory_region_info
 *
 * Describes one region as known to the driver.
 */
struct prelim_drm_i915_memory_region_info {
	/** class:instance pair encoding */
	struct prelim_drm_i915_gem_memory_class_instance region;

	/** MBZ */
	__u32 rsvd0;

	/** MBZ */
	__u64 caps;

	/** MBZ */
	__u64 flags;

	/** Memory probed by the driver (-1 = unknown) */
	__u64 probed_size;

	/** Estimate of memory remaining (-1 = unknown) */
	__u64 unallocated_size;

	/** MBZ */
	__u64 rsvd1[8];
};

/**
 * struct prelim_drm_i915_query_memory_regions
 *
 * Region info query enumerates all regions known to the driver by filling in
 * an array of struct prelim_drm_i915_memory_region_info structures.
 */
struct prelim_drm_i915_query_memory_regions {
	/** Number of supported regions */
	__u32 num_regions;

	/** MBZ */
	__u32 rsvd[3];

	/* Info about each supported region */
	struct prelim_drm_i915_memory_region_info regions[];
};

#endif /* __I915_DRM_PRELIM_H__ */
