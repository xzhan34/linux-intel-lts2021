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
#define PRELIM_DRM_I915_GEM_VM_BIND		0x5d
#define PRELIM_DRM_I915_GEM_VM_UNBIND		0x5c


#define PRELIM_DRM_IOCTL_I915_GEM_CREATE_EXT		DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_CREATE, struct prelim_drm_i915_gem_create_ext)
#define PRELIM_DRM_IOCTL_I915_GEM_VM_BIND		DRM_IOWR(DRM_COMMAND_BASE + PRELIM_DRM_I915_GEM_VM_BIND, struct prelim_drm_i915_gem_vm_bind)
#define PRELIM_DRM_IOCTL_I915_GEM_VM_UNBIND		DRM_IOWR(DRM_COMMAND_BASE + PRELIM_DRM_I915_GEM_VM_UNBIND, struct prelim_drm_i915_gem_vm_bind)
/* End PRELIM ioctl's */

/* getparam */
#define PRELIM_I915_PARAM               (1 << 16)

/* VM_BIND feature availability */
#define PRELIM_I915_PARAM_HAS_VM_BIND	(PRELIM_I915_PARAM | 6)
/* End getparam */

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

/*
 * PRELIM_I915_PARAM_MEMORY_REGIONS:
 *
 * Set the data pointer with the desired set of placements in priority
 * order(each entry must be unique and supported by the device), as an array of
 * prelim_drm_i915_gem_memory_class_instance, or an equivalent layout of class:instance
 * pair encodings. See PRELIM_DRM_I915_QUERY_MEMORY_REGIONS for how to query the
 * supported regions.
 *
 * Note that this requires the PRELIM_I915_OBJECT_PARAM namespace:
 *	.param = PRELIM_I915_OBJECT_PARAM | PRELIM_I915_PARAM_MEMORY_REGIONS
 */
#define PRELIM_I915_PARAM_MEMORY_REGIONS ((1 << 16) | 0x1)
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

/**
 * struct prelim_drm_i915_gem_vm_bind
 *
 * VA to object/buffer mapping to [un]bind.
 *
 * NOTE:
 * A vm_bind will hold a reference on the BO which is released
 * during corresponding vm_unbind or while closing the VM.
 * Hence closing the BO alone will not ensure BO is released.
 */
struct prelim_drm_i915_gem_vm_bind {
	/** vm to [un]bind **/
	__u32 vm_id;

	/** BO handle **/
	__u32 handle; /* For unbind, it is reserved and must be 0 */

	/** VA start to [un]bind **/
	__u64 start;

	/** Offset in object to [un]bind **/
	__u64 offset;

	/** VA length to [un]bind **/
	__u64 length;

	/** Flags **/
	__u64 flags;
#define PRELIM_I915_GEM_VM_BIND_IMMEDIATE	(1ull << 63)
#define PRELIM_I915_GEM_VM_BIND_READONLY	(1ull << 62)

	/**
	 * Zero-terminated chain of extensions.
	 *
	 * No current extensions defined; mbz.
	 */
	__u64 extensions;
};

struct prelim_drm_i915_gem_vm_control {
#define PRELIM_I915_VM_CREATE_FLAGS_USE_VM_BIND		(1 << 18)
#define PRELIM_I915_VM_CREATE_FLAGS_UNKNOWN		(~(GENMASK(18, 18)))
};

#endif /* __I915_DRM_PRELIM_H__ */
