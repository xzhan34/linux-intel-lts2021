/* SPDX-License-Identifier: MIT */
/*
 * Copyright © 2021 Intel Corporation
 */

#ifndef __I915_DEBUGGER_TYPES_H__
#define __I915_DEBUGGER_TYPES_H__

#include <linux/mutex.h>
#include <linux/kref.h>
#include <uapi/drm/i915_drm.h>
#include <linux/completion.h>
#include <linux/wait.h>

struct task_struct;
struct drm_i915_private;

struct i915_debug_event {
	u32 type;
	u32 flags;
	u64 seqno;
	u64 size;
	u8 data[0];
} __packed;

struct i915_debug_event_client {
	struct i915_debug_event base;
	u64 handle;
} __packed;

struct i915_debug_event_context {
	struct i915_debug_event base;
	u64 client_handle;
	u64 handle;
} __packed;

struct i915_debugger {
	struct kref ref;
	struct rcu_head rcu;
	struct mutex lock;
	struct drm_i915_private *i915;
	int debug_lvl;
	struct task_struct *target_task;
	wait_queue_head_t write_done;
	struct completion read_done;

	u64 session;
	atomic_long_t event_seqno;

	const struct i915_debug_event *event;
};

#endif /* __I915_DEBUGGER_TYPES_H__ */
