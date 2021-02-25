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
#define PRELIM_I915_CONTEXT_ENGINES_EXT_PARALLEL2_SUBMIT (PRELIM_I915_USER_EXT | 3)
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
#define PRELIM_DRM_I915_GEM_WAIT_USER_FENCE	0x5a
#define PRELIM_DRM_I915_UUID_REGISTER		0x58
#define PRELIM_DRM_I915_UUID_UNREGISTER		0x57
#define PRELIM_DRM_I915_DEBUGGER_OPEN		0x56


#define PRELIM_DRM_IOCTL_I915_GEM_CREATE_EXT		DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_CREATE, struct prelim_drm_i915_gem_create_ext)
#define PRELIM_DRM_IOCTL_I915_GEM_VM_BIND		DRM_IOWR(DRM_COMMAND_BASE + PRELIM_DRM_I915_GEM_VM_BIND, struct prelim_drm_i915_gem_vm_bind)
#define PRELIM_DRM_IOCTL_I915_GEM_VM_UNBIND		DRM_IOWR(DRM_COMMAND_BASE + PRELIM_DRM_I915_GEM_VM_UNBIND, struct prelim_drm_i915_gem_vm_bind)
#define PRELIM_DRM_IOCTL_I915_GEM_WAIT_USER_FENCE	DRM_IOWR(DRM_COMMAND_BASE + PRELIM_DRM_I915_GEM_WAIT_USER_FENCE, struct prelim_drm_i915_gem_wait_user_fence)
#define PRELIM_DRM_IOCTL_I915_UUID_REGISTER		DRM_IOWR(DRM_COMMAND_BASE + PRELIM_DRM_I915_UUID_REGISTER, struct prelim_drm_i915_uuid_control)
#define PRELIM_DRM_IOCTL_I915_UUID_UNREGISTER		DRM_IOWR(DRM_COMMAND_BASE + PRELIM_DRM_I915_UUID_UNREGISTER, struct prelim_drm_i915_uuid_control)
#define PRELIM_DRM_IOCTL_I915_DEBUGGER_OPEN		DRM_IOWR(DRM_COMMAND_BASE + PRELIM_DRM_I915_DEBUGGER_OPEN, struct prelim_drm_i915_debugger_open_param)
/* End PRELIM ioctl's */

/* getparam */
#define PRELIM_I915_PARAM               (1 << 16)

/* VM_BIND feature availability */
#define PRELIM_I915_PARAM_HAS_VM_BIND	(PRELIM_I915_PARAM | 6)

/* EU Debugger support */
#define PRELIM_I915_PARAM_EU_DEBUGGER_VERSION  (PRELIM_I915_PARAM | 9)

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
#define PRELIM_I915_GEM_CREATE_EXT_VM_PRIVATE	(PRELIM_I915_USER_EXT | 3)
#define PRELIM_I915_GEM_CREATE_EXT_FLAGS_UNKNOWN			\
	(~(PRELIM_I915_GEM_CREATE_EXT_SETPARAM |			\
	   PRELIM_I915_GEM_CREATE_EXT_PROTECTED_CONTENT |		\
	   PRELIM_I915_GEM_CREATE_EXT_VM_PRIVATE))
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

struct prelim_drm_i915_gem_create_ext_vm_private {
	/** @base: Extension link. See struct i915_user_extension. */
	struct i915_user_extension base;
	/** @vm_id: Id of the VM to which Object is private */
	__u32 vm_id;
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
/* Deprecated: HWConfig is now upstream, do not use the prelim version anymore */
#define PRELIM_DRM_I915_QUERY_HWCONFIG_TABLE	(PRELIM_DRM_I915_QUERY | 6)
	/**
	 * Query Geometry Subslices: returns the items found in query_topology info
	 * with a mask for geometry_subslice_mask applied
	 *
	 * @flags:
	 *
	 * bits 0:7 must be a valid engine class and bits 8:15 must be a valid engine
	 * instance.
	 */
#define PRELIM_DRM_I915_QUERY_GEOMETRY_SUBSLICES	(PRELIM_DRM_I915_QUERY | 7)
	/**
	 * Query Compute Subslices: returns the items found in query_topology info
	 * with a mask for compute_subslice_mask applied
	 *
	 * @flags:
	 *
	 * bits 0:7 must be a valid engine class and bits 8:15 must be a valid engine
	 * instance.
	 */
#define PRELIM_DRM_I915_QUERY_COMPUTE_SUBSLICES		(PRELIM_DRM_I915_QUERY | 8)
#define PRELIM_DRM_I915_QUERY_ENGINE_INFO		(PRELIM_DRM_I915_QUERY | 13)
};

/*
 * Indicates the 2k user priority levels are statically mapped into 3 buckets as
 * follows:
 *
 * -1k to -1	Low priority
 * 0		Normal priority
 * 1 to 1k	Highest priority
 */
#define   PRELIM_I915_SCHEDULER_CAP_STATIC_PRIORITY_MAP	(1ul << 31)

enum prelim_drm_i915_gem_engine_class {
#define	PRELIM_I915_ENGINE_CLASS		(1 << 8)
#define	PRELIM_I915_ENGINE_CLASS_MASK(x)	(x & 0xff)

	PRELIM_I915_ENGINE_CLASS_COMPUTE = 4,
};

struct prelim_i915_context_param_engines {
#define PRELIM_I915_CONTEXT_ENGINES_EXT_PARALLEL_SUBMIT (PRELIM_I915_USER_EXT | 2) /* see prelim_i915_context_engines_parallel_submit */
};

struct prelim_drm_i915_gem_context_param {
/*
 * I915_CONTEXT_PARAM_DEBUG_FLAGS
 *
 * Set or clear debug flags associated with this context.
 * The flags works with 32 bit masking to enable/disable individual
 * flags. For example to set debug flag of bit position 0, the
 * value needs to be 0x0000000100000001, and to clear flag of
 * bit position 0, the value needs to be 0x0000000100000000.
 *
 */
#define PRELIM_I915_CONTEXT_PARAM		(1 << 16)
#define PRELIM_I915_CONTEXT_PARAM_DEBUG_FLAGS	(PRELIM_I915_CONTEXT_PARAM | 0xfd)

/*
 * Notify driver that SIP is provided with the pipeline setup.
 * Driver raises exception on hang resolution and waits for pipeline's
 * sip to signal attention before capturing state of user objects
 * associated with the context.
 *
 */
#define PRELIM_I915_CONTEXT_PARAM_DEBUG_FLAG_SIP	(1ull << 0)
};

/*
 * I915_CONTEXT_PARAM_PROTECTED_CONTENT:
 *
 * Mark that the context makes use of protected content, which will result
 * in the context being invalidated when the protected content session is.
 * This flag can only be set at context creation time and, when set to true,
 * must be preceded by an explicit setting of I915_CONTEXT_PARAM_RECOVERABLE
 * to false. This flag can't be set to true in conjunction with setting the
 * I915_CONTEXT_PARAM_BANNABLE flag to false.
 *
 * Given the numerous restriction on this flag, there are several unique
 * failure cases:
 *
 * -ENODEV: feature not available
 * -EPERM: trying to mark a recoverable or not bannable context as protected
 */
#define PRELIM_I915_CONTEXT_PARAM_PROTECTED_CONTENT (PRELIM_I915_CONTEXT_PARAM | 0xe)

/* Downstream PRELIM properties */
enum prelim_drm_i915_perf_property_id {
	PRELIM_DRM_I915_PERF_PROP = (1 << 16),

	/**
	 * Specify a global OA buffer size to be allocated in bytes. The size
	 * specified must be supported by HW (before XEHPSDV supported sizes are
	 * powers of 2 ranging from 128Kb to 16Mb. With XEHPSDV max supported size
	 * is 128Mb).
	 *
	 * This property is available in perf revision 1001.
	 */
	PRELIM_DRM_I915_PERF_PROP_OA_BUFFER_SIZE = (PRELIM_DRM_I915_PERF_PROP | 1),

	PRELIM_DRM_I915_PERF_PROP_LAST,

	PRELIM_DRM_I915_PERF_PROP_MAX = DRM_I915_PERF_PROP_MAX - 1 + \
					(PRELIM_DRM_I915_PERF_PROP_LAST & 0xffff)
};

struct prelim_drm_i915_uuid_control {
	char  uuid[36]; /* String formatted like
			 *      "%08x-%04x-%04x-%04x-%012x"
			 */

	__u32 uuid_class; /* Predefined UUID class or handle to
			   * the previously registered UUID Class
			   */

	__u32 flags;	/* MBZ */

	__u64 ptr;	/* Pointer to CPU memory payload associated
			 * with the UUID Resource.
			 * For uuid_class I915_UUID_CLASS_STRING
			 * it must point to valid string buffer.
			 * Otherwise must point to page aligned buffer
			 * or be NULL.
			 */

	__u64 size;	/* Length of the payload in bytes */

#define PRELIM_I915_UUID_CLASS_STRING	((__u32)-1)
/*
 * d9900de4-be09-56ab-84a5-dfc280f52ee5 =
 *                          sha1(“I915_UUID_CLASS_STRING”)[0..35]
 */
#define PRELIM_I915_UUID_CLASS_MAX_RESERVED ((__u32)-1024)

	__u32 handle; /* Output: Registered handle ID */

	__u64 extensions; /* MBZ */
};

/*
 * struct prelim_drm_i915_vm_bind_ext_uuid
 *
 * Used for registering metadata that will be attached to the vm
 */
struct prelim_drm_i915_vm_bind_ext_uuid {
#define PRELIM_I915_VM_BIND_EXT_UUID	(PRELIM_I915_USER_EXT | 1)
	struct i915_user_extension base;
	__u32 uuid_handle; /* Handle to the registered UUID resource. */
};

/**
 * Do a debug event read for a debugger connection.
 *
 * This ioctl is available in debug version 1.
 */
#define PRELIM_I915_DEBUG_IOCTL_READ_EVENT _IO('j', 0x0)
#define PRELIM_I915_DEBUG_IOCTL_READ_UUID  _IOWR('j', 0x1, struct prelim_drm_i915_debug_read_uuid)

struct prelim_drm_i915_debug_event {
	__u32 type;
#define PRELIM_DRM_I915_DEBUG_EVENT_NONE     0
#define PRELIM_DRM_I915_DEBUG_EVENT_READ     1
#define PRELIM_DRM_I915_DEBUG_EVENT_CLIENT   2
#define PRELIM_DRM_I915_DEBUG_EVENT_CONTEXT  3
#define PRELIM_DRM_I915_DEBUG_EVENT_UUID     4
#define PRELIM_DRM_I915_DEBUG_EVENT_MAX_EVENT PRELIM_DRM_I915_DEBUG_EVENT_UUID

	__u32 flags;
#define PRELIM_DRM_I915_DEBUG_EVENT_CREATE	(1 << 31)
#define PRELIM_DRM_I915_DEBUG_EVENT_DESTROY	(1 << 30)
	__u64 seqno;
	__u64 size;
} __attribute__((packed));

struct prelim_drm_i915_debug_event_client {
	struct prelim_drm_i915_debug_event base; /* .flags = CREATE/DESTROY */

	__u64 handle; /* This is unique per debug connection */
} __attribute__((packed));

struct prelim_drm_i915_debug_event_context {
	struct prelim_drm_i915_debug_event base;

	__u64 client_handle;
	__u64 handle;
} __attribute__((packed));

/*
 * Debugger ABI (ioctl and events) Version History:
 * 0 - No debugger available
 * 1 - Initial version
 */
#define PRELIM_DRM_I915_DEBUG_VERSION 0

struct prelim_drm_i915_debugger_open_param {
	__u64 pid; /* input: Target process ID */
	__u32 flags;
#define PRELIM_DRM_I915_DEBUG_FLAG_FD_NONBLOCK	(1u << 31)

	__u32 version; /* output: current ABI (ioctl / events) version */
	__u64 events;  /* input: event types to subscribe to */
	__u64 extensions; /* MBZ */
};

struct prelim_drm_i915_debug_event_uuid {
	struct prelim_drm_i915_debug_event base;
	__u64 client_handle;

	__u64 handle;
	__u64 class_handle; /* Can be filtered based on pre-defined classes */
	__u64 payload_size;
} __attribute__((packed));

struct prelim_drm_i915_debug_read_uuid {
	__u64 client_handle;
	__u64 handle;
	__u32 flags; /* MBZ */
	char uuid[36]; /* output */
	__u64 payload_ptr;
	__u64 payload_size;
} __attribute__((packed));

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
 * struct prelim_drm_i915_engine_info
 *
 * Describes one engine and it's capabilities as known to the driver.
 */
struct prelim_drm_i915_engine_info {
	/** Engine class and instance. */
	struct i915_engine_class_instance engine;

	/** Reserved field. */
	__u32 rsvd0;

	/** Engine flags. */
	__u64 flags;
#define PRELIM_I915_ENGINE_INFO_HAS_LOGICAL_INSTANCE	(1ull << 62)

	/** Capabilities of this engine. */
	__u64 capabilities;
#define I915_VIDEO_CLASS_CAPABILITY_HEVC		(1 << 0)
#define I915_VIDEO_AND_ENHANCE_CLASS_CAPABILITY_SFC	(1 << 1)

	__u64 rsvd3;

	/** Logical engine instance */
	__u16 logical_instance;

	/** Reserved fields. */
	__u16 rsvd1[3];
	__u64 rsvd2[2];
};

/**
 * struct drm_i915_query_engine_info
 *
 * Engine info query enumerates all engines known to the driver by filling in
 * an array of struct drm_i915_engine_info structures.
 */
struct prelim_drm_i915_query_engine_info {
	/** Number of struct drm_i915_engine_info structs following. */
	__u32 num_engines;

	/** MBZ */
	__u32 rsvd[3];

	/** Marker for drm_i915_engine_info structures. */
	struct prelim_drm_i915_engine_info engines[];
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
#define PRELIM_I915_GEM_VM_BIND_CAPTURE		(1ull << 61)

	__u64 extensions;
};

/**
 * struct prelim_drm_i915_gem_wait_user_fence
 *
 * Wait on user fence. User fence can be woken up either by,
 *    1. GPU context indicated by 'ctx_id', or,
 *    2. Kerrnel driver async worker upon PRELIM_I915_UFENCE_WAIT_SOFT.
 *       'ctx_id' is ignored when this flag is set.
 *
 * Wakeup when below condition is true.
 * (*addr & MASK) OP (VALUE & MASK)
 *
 */
struct prelim_drm_i915_gem_wait_user_fence {
	__u64 extensions;
	__u64 addr;
	__u32 ctx_id;
	__u16 op;
#define PRELIM_I915_UFENCE		(1 << 8)
#define PRELIM_I915_UFENCE_WAIT_EQ	(PRELIM_I915_UFENCE | 0)
#define PRELIM_I915_UFENCE_WAIT_NEQ	(PRELIM_I915_UFENCE | 1)
#define PRELIM_I915_UFENCE_WAIT_GT	(PRELIM_I915_UFENCE | 2)
#define PRELIM_I915_UFENCE_WAIT_GTE	(PRELIM_I915_UFENCE | 3)
#define PRELIM_I915_UFENCE_WAIT_LT	(PRELIM_I915_UFENCE | 4)
#define PRELIM_I915_UFENCE_WAIT_LTE	(PRELIM_I915_UFENCE | 5)
#define PRELIM_I915_UFENCE_WAIT_BEFORE	(PRELIM_I915_UFENCE | 6)
#define PRELIM_I915_UFENCE_WAIT_AFTER	(PRELIM_I915_UFENCE | 7)
	__u16 flags;
#define PRELIM_I915_UFENCE_WAIT_SOFT	(1 << 15)
#define PRELIM_I915_UFENCE_WAIT_ABSTIME	(1 << 14)
	__u64 value;
	__u64 mask;
#define PRELIM_I915_UFENCE_WAIT_U8     0xffu
#define PRELIM_I915_UFENCE_WAIT_U16    0xffffu
#define PRELIM_I915_UFENCE_WAIT_U32    0xfffffffful
#define PRELIM_I915_UFENCE_WAIT_U64    0xffffffffffffffffull
	__s64 timeout;
};

/* Deprecated in favor of prelim_drm_i915_vm_bind_ext_user_fence */
struct prelim_drm_i915_vm_bind_ext_sync_fence {
#define PRELIM_I915_VM_BIND_EXT_SYNC_FENCE     (PRELIM_I915_USER_EXT | 0)
	struct i915_user_extension base;
	__u64 addr;
	__u64 val;
};

struct prelim_drm_i915_vm_bind_ext_user_fence {
#define PRELIM_I915_VM_BIND_EXT_USER_FENCE     (PRELIM_I915_USER_EXT | 3)
	struct i915_user_extension base;
	__u64 addr;
	__u64 val;
	__u64 rsvd;
};

struct prelim_drm_i915_gem_vm_control {
#define PRELIM_I915_VM_CREATE_FLAGS_USE_VM_BIND		(1 << 18)
#define PRELIM_I915_VM_CREATE_FLAGS_UNKNOWN		(~(GENMASK(18, 18)))
};

#endif /* __I915_DRM_PRELIM_H__ */
