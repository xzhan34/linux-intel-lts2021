// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */

#include <linux/anon_inodes.h>
#include <linux/ptrace.h>

#include "gem/i915_gem_context.h"

#include "i915_debugger.h"
#include "i915_drm_client.h"
#include "i915_drv.h"
#include "i915_gpu_error.h"

#define from_event(T, event) container_of((event), typeof(*(T)), base)
#define to_event(e) (&(e)->base)

static void __i915_debugger_print(const struct i915_debugger * const debugger,
				  const int level,
				  const char * const prefix,
				  const char * const format, ...)
{
	struct drm_printer p;
	struct va_format vaf;
	va_list	args;

	if (level > 2)
		p = drm_debug_printer("i915_debugger");
	else if (level > 1)
		p = drm_info_printer(debugger->i915->drm.dev);
	else
		p = drm_err_printer("i915_debugger");

	va_start(args, format);

	vaf.fmt = format;
	vaf.va = &args;

	drm_printf(&p, "%s(%d/%d:%llu:%d/%d): %pV", prefix,
		   current->pid, task_tgid_nr(current),
		   debugger->session,
		   debugger->target_task->pid,
		   task_tgid_nr(debugger->target_task),
		   &vaf);

	va_end(args);
}

#define i915_debugger_print(debugger, level, prefix, fmt, ...) do { \
		if ((debugger)->debug_lvl >= (level)) {	\
			__i915_debugger_print((debugger), (level), prefix, fmt, ##__VA_ARGS__); \
		} \
	} while (0)

#define __DD(debugger, level, fmt, ...) i915_debugger_print(debugger, level, __func__, fmt, ##__VA_ARGS__)

#define DD_DEBUG_LEVEL_NONE 0
#define DD_DEBUG_LEVEL_ERR  1
#define DD_DEBUG_LEVEL_WARN 2
#define DD_DEBUG_LEVEL_INFO 3
#define DD_DEBUG_LEVEL_VERBOSE 4

/* With verbose raw addresses are seen */
#define I915_DEBUGGER_BUILD_DEBUG_LEVEL DD_DEBUG_LEVEL_VERBOSE

#define DD_INFO(debugger, fmt, ...) __DD(debugger, DD_DEBUG_LEVEL_INFO, fmt, ##__VA_ARGS__)
#define DD_WARN(debugger, fmt, ...) __DD(debugger, DD_DEBUG_LEVEL_WARN, fmt, ##__VA_ARGS__)
#define DD_ERR(debugger, fmt, ...) __DD(debugger, DD_DEBUG_LEVEL_ERR, fmt, ##__VA_ARGS__)

#if I915_DEBUGGER_BUILD_DEBUG_LEVEL >= DD_DEBUG_LEVEL_VERBOSE
#define ND_VERBOSE(i915, fmt, ...) DRM_DEV_DEBUG_DRIVER((i915)->drm.dev, fmt, ##__VA_ARGS__)
#define DD_VERBOSE(debugger, fmt, ...) __DD(debugger, DD_DEBUG_LEVEL_VERBOSE, fmt, ##__VA_ARGS__)
#else
#define ND_VERBOSE(i915, fmt, ...)
#define DD_VERBOSE(debugger, fmt, ...)
#endif

static const char *event_type_to_str(u32 type)
{
	static const char * const type_str[] = {
		"none",
		"read",
		"client",
		"context",
		"uuid",
		"vm",
		"vm-bind",
		"context-param",
		"unknown",
	};

	if (type > ARRAY_SIZE(type_str) - 1)
		type = ARRAY_SIZE(type_str) - 1;

	return type_str[type];
}

static const char *event_flags_to_str(const u32 flags)
{
	if (flags & PRELIM_DRM_I915_DEBUG_EVENT_CREATE)
		return "create";
	else if (flags & PRELIM_DRM_I915_DEBUG_EVENT_DESTROY)
		return "destroy";

	return "unknown";
}

#define EVENT_PRINT_MEMBER(d, p, s, m, fmt, type) do { \
		BUILD_BUG_ON(sizeof(s->m) != sizeof(type)); \
		__i915_debugger_print(d, DD_DEBUG_LEVEL_INFO, p, \
				      "  %s->%s = " fmt, #s, #m, (type)s->m); \
	} while(0)

#define EVENT_PRINT_MEMBER_U64(d, p, s, n) EVENT_PRINT_MEMBER(d, p, s, n, "%llu", u64)
#define EVENT_PRINT_MEMBER_U32(d, p, s, n) EVENT_PRINT_MEMBER(d, p, s, n, "%u", u32)
#define EVENT_PRINT_MEMBER_U16(d, p, s, n) EVENT_PRINT_MEMBER(d, p, s, n, "%hu", u16)
#define EVENT_PRINT_MEMBER_U64X(d, p, s, n) EVENT_PRINT_MEMBER(d, p, s, n, "0x%llx", u64)
#define EVENT_PRINT_MEMBER_U32X(d, p, s, n) EVENT_PRINT_MEMBER(d, p, s, n, "0x%x", u32)
#define EVENT_PRINT_MEMBER_HANDLE(d, p, s, n) EVENT_PRINT_MEMBER_U64(d, p, s, n)

typedef void (*debug_event_printer_t)(const struct i915_debugger * const debugger,
				      const char * const prefix,
				      const struct i915_debug_event * const event);

static void event_printer_client(const struct i915_debugger * const debugger,
				 const char * const prefix,
				 const struct i915_debug_event * const event)
{
	const struct i915_debug_event_client * const client =
		from_event(client, event);

	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, client, handle);
}

static void event_printer_context(const struct i915_debugger * const debugger,
				  const char * const prefix,
				  const struct i915_debug_event * const event)
{
	const struct i915_debug_event_context * const context =
		from_event(context, event);

	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, context, client_handle);
	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, context, handle);
}

static void event_printer_uuid(const struct i915_debugger * const debugger,
			       const char * const prefix,
			       const struct i915_debug_event * const event)
{
	const struct i915_debug_event_uuid * const uuid =
		from_event(uuid, event);

	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, uuid, client_handle);
	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, uuid, handle);
	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, uuid, class_handle);
	EVENT_PRINT_MEMBER_U64(debugger, prefix, uuid, payload_size);
}

static void event_printer_vm(const struct i915_debugger * const debugger,
			     const char * const prefix,
			     const struct i915_debug_event * const event)
{
	const struct i915_debug_event_vm * const vm = from_event(vm, event);

	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, vm, client_handle);
	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, vm, handle);
}

static void event_printer_vma(const struct i915_debugger * const debugger,
			      const char * const prefix,
			      const struct i915_debug_event * const event)
{
	const struct i915_debug_event_vm_bind * const ev = from_event(ev, event);
	unsigned i;

	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, ev, client_handle);
	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, ev, vm_handle);
	EVENT_PRINT_MEMBER_U64X(debugger, prefix, ev, va_start);
	EVENT_PRINT_MEMBER_U64X(debugger, prefix, ev, va_length);
	EVENT_PRINT_MEMBER_U32(debugger, prefix, ev, num_uuids);
	EVENT_PRINT_MEMBER_U32(debugger, prefix, ev, flags);

	for (i = 0; i < ev->num_uuids; i++)
		i915_debugger_print(debugger, DD_DEBUG_LEVEL_INFO, prefix,
				    "  vma->uuids[%u] = %llu",
				    i, ev->uuids[i]);
}

static void event_printer_context_param(const struct i915_debugger * const debugger,
					const char * const prefix,
					const struct i915_debug_event * const event)
{
	const struct i915_debug_event_context_param * const context_param =
		from_event(context_param, event);
	const struct drm_i915_gem_context_param * const context_param_param =
		&context_param->param;

	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, context_param, client_handle);
	EVENT_PRINT_MEMBER_HANDLE(debugger, prefix, context_param, ctx_handle);
	EVENT_PRINT_MEMBER_U32(debugger, prefix, context_param_param, ctx_id);
	EVENT_PRINT_MEMBER_U64(debugger, prefix, context_param_param, param);
	EVENT_PRINT_MEMBER_U64(debugger, prefix, context_param_param, value);
}

static void i915_debugger_print_event(const struct i915_debugger * const debugger,
				      const char * const prefix,
				      const struct i915_debug_event * const event)
{
	static const debug_event_printer_t event_printers[] = {
		NULL,
		NULL,
		event_printer_client,
		event_printer_context,
		event_printer_uuid,
		event_printer_vm,
		event_printer_vma,
		event_printer_context_param,
	};
	debug_event_printer_t event_printer = NULL;

	if (likely(debugger->debug_lvl < DD_DEBUG_LEVEL_INFO))
		return;

	__i915_debugger_print(debugger, DD_DEBUG_LEVEL_INFO, prefix,
			      "%s:%s type=%u, flags=0x%08x, seqno=%llu, size=%llu\n",
			      event_type_to_str(event->type),
			      event_flags_to_str(event->flags),
			      event->type,
			      event->flags,
			      event->seqno,
			      event->size);

	if (event->type < ARRAY_SIZE(event_printers))
		event_printer = event_printers[event->type];

	if (event_printer)
		event_printer(debugger, prefix, event);
	else
		DD_VERBOSE(debugger, "no event printer found for type=%u\n", event->type);
}

static void _i915_debugger_free(struct kref *ref)
{
	struct i915_debugger *debugger = container_of(ref, typeof(*debugger), ref);

	put_task_struct(debugger->target_task);
	xa_destroy(&debugger->resources_xa);
	kfree_rcu(debugger, rcu);
}

static void i915_debugger_put(struct i915_debugger *debugger)
{
	kref_put(&debugger->ref, _i915_debugger_free);
}

static inline bool
__is_debugger_closed(const struct drm_i915_private * const i915,
		     const struct i915_debugger * const debugger)
{
	return debugger != rcu_access_pointer(i915->debug.debugger);
}


static inline bool
is_debugger_closed(const struct i915_debugger * const debugger)
{
	return __is_debugger_closed(debugger->i915, debugger);
}

static void i915_debugger_detach(struct i915_debugger *debugger)
{
	struct drm_i915_private * const i915 = debugger->i915;

	mutex_lock(&i915->debug.mutex);
	if (!__is_debugger_closed(i915, debugger)) {
		rcu_replace_pointer(i915->debug.debugger, NULL, true);
		DD_INFO(debugger, "detached");
	}
	mutex_unlock(&i915->debug.mutex);
}

static inline const struct i915_debug_event *
event_pending(const struct i915_debugger * const debugger)
{
	return READ_ONCE(debugger->event);
}

static inline bool is_client_connected(const struct i915_debugger *debugger,
				       const struct i915_drm_client *client)
{
	return READ_ONCE(client->debugger_session) == debugger->session;
}

static void i915_debugger_close(struct i915_debugger *debugger)
{
	i915_debugger_detach(debugger);

	complete_all(&debugger->discovery);
	wake_up_all(&debugger->write_done);
	complete_all(&debugger->read_done);
}

static __poll_t i915_debugger_poll(struct file *file, poll_table *wait)
{
	struct i915_debugger * const debugger = file->private_data;

	if (is_debugger_closed(debugger))
		return 0;

	poll_wait(file, &debugger->write_done, wait);

	if (event_pending(debugger) && !is_debugger_closed(debugger))
		return EPOLLIN;

	return 0;
}

static ssize_t i915_debugger_read(struct file *file,
				  char __user *buf,
				  size_t count,
				  loff_t *ppos)
{
	return 0;
}

static struct i915_debugger *i915_debugger_get(struct drm_i915_private *i915)
{
	struct i915_debugger *debugger;

	rcu_read_lock();
	debugger = rcu_dereference(i915->debug.debugger);
	if (debugger && !kref_get_unless_zero(&debugger->ref))
		debugger = NULL;
	rcu_read_unlock();

	return debugger;
}

static inline bool client_debugged(const struct i915_drm_client * const client)
{
	struct drm_i915_private * const i915 = client->clients->i915;
	struct i915_debugger *debugger;
	bool debugged;

	if (likely(!READ_ONCE(client->debugger_session)))
		return false;

	rcu_read_lock();
	debugger = rcu_dereference(i915->debug.debugger);
	if (debugger)
		debugged = is_client_connected(debugger, client);
	else
		debugged = false;
	rcu_read_unlock();

	return debugged;
}

static int i915_debugger_send_event(struct i915_debugger * const debugger,
				    const struct i915_debug_event *event)
{
	struct drm_i915_private * const i915 = debugger->i915;
	const unsigned long user_ms = i915->params.debugger_timeout_ms;
	const unsigned long retry_timeout_ms = 100;
	ktime_t disconnect_ts, now;
	unsigned long timeout;
	bool expired;

	/* No need to send base events */
	if (event->size <= sizeof(struct prelim_drm_i915_debug_event) ||
	    !event->type ||
	    event->type == PRELIM_DRM_I915_DEBUG_EVENT_READ) {
		GEM_WARN_ON(event->size <= sizeof(struct prelim_drm_i915_debug_event));
		GEM_WARN_ON(!event->type);
		GEM_WARN_ON(event->type == PRELIM_DRM_I915_DEBUG_EVENT_READ);

		return -EINVAL;
	}

	disconnect_ts = ktime_add_ms(ktime_get_raw(), user_ms);
	mutex_lock(&debugger->lock);

	do {
		const struct i915_debug_event *blocking_event;
		u64 blocking_seqno;

		if (is_debugger_closed(debugger)) {
			DD_INFO(debugger, "disconnect on send: debugger was closed\n");
			goto disconnect;
		}

		blocking_event = event_pending(debugger);
		if (!blocking_event)
			break;

		/*
		 * If we did not get access to event, there might be stuck
		 * reader or other writer have raced us. Take a snapshot
		 * of that event seqno.
		 */
		blocking_seqno = blocking_event->seqno;

		mutex_unlock(&debugger->lock);

		now = ktime_get_raw();
		if (user_ms == 0)
			disconnect_ts = ktime_add_ms(now, retry_timeout_ms);

		if (ktime_sub(disconnect_ts, now) > 0) {
			timeout = min_t(unsigned long,
					retry_timeout_ms,
					ktime_to_ms(ktime_sub(disconnect_ts, now)));

			wait_for_completion_timeout(&debugger->read_done,
						    msecs_to_jiffies(timeout));

			now = ktime_get_raw();
		}

		expired = user_ms ? ktime_after(now, disconnect_ts) : false;

		mutex_lock(&debugger->lock);

		/* Postpone expiration if some other writer made progress */
		blocking_event = is_debugger_closed(debugger) ?
			NULL : event_pending(debugger);
		if (!blocking_event)
			expired = true;
		else if (blocking_event->seqno != blocking_seqno)
			expired = false;
	} while (!expired);

	if (event_pending(debugger) && !is_debugger_closed(debugger)) {
		DD_INFO(debugger, "disconnect: send wait expired");
		goto disconnect;
	}

	reinit_completion(&debugger->read_done);
	debugger->event = event;
	mutex_unlock(&debugger->lock);

	wake_up_all(&debugger->write_done);

	if (event_pending(debugger) != event)
		return 0;

	schedule();
	if (event_pending(debugger) != event)
		return 0;

	mutex_lock(&debugger->lock);
	do {
		if (is_debugger_closed(debugger)) {
			DD_INFO(debugger, "disconnect: debugger closed on waiting read");
			goto disconnect;
		}

		/* If it is not our event, we can safely return */
		if (event_pending(debugger) != event)
			break;

		mutex_unlock(&debugger->lock);

		now = ktime_get_raw();
		if (user_ms == 0)
			disconnect_ts = ktime_add_ms(now, retry_timeout_ms);

		if (ktime_sub(disconnect_ts, now) > 0) {
			timeout = min_t(unsigned long,
					retry_timeout_ms,
					ktime_to_ms(ktime_sub(disconnect_ts, now)));
			wait_for_completion_timeout(&debugger->read_done,
						    msecs_to_jiffies(timeout));
			now = ktime_get_raw();
		}

		expired = user_ms ? ktime_after(now, disconnect_ts) : false;
		mutex_lock(&debugger->lock);
	} while (!expired);

	/* If it is still our event pending, disconnect */
	if (event_pending(debugger) == event) {
		DD_INFO(debugger, "disconnect: timeout waiting for read");
		goto disconnect;
	}

	mutex_unlock(&debugger->lock);
	return 0;

disconnect:
	mutex_unlock(&debugger->lock);
	i915_debugger_close(debugger);

	return -ENODEV;
}

static struct i915_debug_event *
i915_debugger_create_event(struct i915_debugger * const debugger,
			   u32 type, u32 flags, u32 size, gfp_t gfp)
{
	struct i915_debug_event *event;

	GEM_WARN_ON(size <= sizeof(*event));

	event = kzalloc(size, gfp);
	if (!event) {
		DD_ERR(debugger, "unable to create event 0x%08x (ENOMEM), disconnecting", type);
		i915_debugger_close(debugger);
		return NULL;
	}

	event->type = type;
	event->flags = flags;
	event->seqno = atomic_long_inc_return(&debugger->event_seqno);
	event->size = size;

	return event;
}

static long wait_for_write(struct i915_debugger *debugger,
			   const unsigned long timeout_ms)
{
	const long waitjiffs =
		msecs_to_jiffies(timeout_ms);

	if (is_debugger_closed(debugger)) {
		complete(&debugger->read_done);
		return -ENODEV;
	}

	if (event_pending(debugger))
		return waitjiffs;

	return wait_event_interruptible_timeout(debugger->write_done,
						event_pending(debugger),
						waitjiffs);
}

static long i915_debugger_read_event(struct i915_debugger *debugger,
				     const unsigned long arg,
				     const bool nonblock)
{
	struct prelim_drm_i915_debug_event __user * const user_orig =
		(void __user *)(arg);
	struct prelim_drm_i915_debug_event user_event;
	const struct i915_debug_event *event;
	unsigned int waits;
	void *buf;
	long ret;

	if (copy_from_user(&user_event, user_orig, sizeof(user_event)))
		return -EFAULT;

	if (!user_event.type)
		return -EINVAL;

	if (user_event.type > PRELIM_DRM_I915_DEBUG_EVENT_MAX_EVENT)
		return -EINVAL;

	if (user_event.type != PRELIM_DRM_I915_DEBUG_EVENT_READ)
		return -EINVAL;

	if (user_event.size < sizeof(*user_orig))
		return -EINVAL;

	if (user_event.flags)
		return -EINVAL;

	buf = kzalloc(user_event.size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	waits = 0;
	mutex_lock(&debugger->lock);
	do {
		if (is_debugger_closed(debugger)) {
			ret = -ENODEV;
			goto unlock;
		}

		event = event_pending(debugger);
		if (event)
			break;

		mutex_unlock(&debugger->lock);
		if (nonblock) {
			ret = -EAGAIN;
			goto out;
		}

		ret = wait_for_write(debugger, 100);
		if (ret < 0)
			goto out;

		mutex_lock(&debugger->lock);
	} while (waits++ < 10);

	if (!event) {
		ret = -ETIMEDOUT;
		complete(&debugger->read_done);
		goto unlock;
	}

	if (is_debugger_closed(debugger)) {
		ret = -ENODEV;
		goto unlock;
	}

	if (unlikely(user_event.size < event->size)) {
		ret = -EMSGSIZE;
		goto unlock;
	}

	memcpy(&user_event, event, sizeof(user_event));
	memcpy(buf, event->data, event->size - sizeof(*user_orig));

	i915_debugger_print_event(debugger, "read", event);

	debugger->event = NULL;
	complete(&debugger->read_done);
	mutex_unlock(&debugger->lock);
	ret = 0;

	if (copy_to_user(user_orig, &user_event, sizeof(*user_orig))) {
		ret = -EFAULT;
		goto out;
	}

	if (copy_to_user(user_orig + 1, buf,
			 user_event.size - sizeof(*user_orig))) {
		ret = -EFAULT;
		goto out;
	}

out:
	kfree(buf);
	return ret;

unlock:
	mutex_unlock(&debugger->lock);
	goto out;
}

static long i915_debugger_read_uuid_ioctl(struct i915_debugger *debugger,
					  unsigned int cmd,
					  const u64 arg)
{
	struct prelim_drm_i915_debug_read_uuid read_arg;
	struct i915_uuid_resource *uuid;
	struct i915_drm_client *client;
	long ret = 0;

	if (_IOC_SIZE(cmd) < sizeof(read_arg))
		return -EINVAL;

	if (!(_IOC_DIR(cmd) & _IOC_WRITE))
		return -EINVAL;

	if (!(_IOC_DIR(cmd) & _IOC_READ))
		return -EINVAL;

	if (copy_from_user(&read_arg, u64_to_user_ptr(arg), sizeof(read_arg)))
		return -EFAULT;

	if (read_arg.flags)
		return -EINVAL;

	if (!access_ok(u64_to_user_ptr(read_arg.payload_ptr),
		       read_arg.payload_size))
		return -EFAULT;

	DD_INFO(debugger, "read_uuid: client_handle=%llu, handle=%llu, flags=0x%x",
		read_arg.client_handle, read_arg.handle, read_arg.flags);

	uuid = NULL;
	rcu_read_lock();
	client = xa_load(&debugger->i915->clients.xarray,
			 read_arg.client_handle);
	if (client) {
		xa_lock(&client->uuids_xa);
		uuid = xa_load(&client->uuids_xa, read_arg.handle);
		if (uuid)
			i915_uuid_get(uuid);
		xa_unlock(&client->uuids_xa);
	}
	rcu_read_unlock();
	if (!uuid)
		return -ENOENT;

	if (read_arg.payload_size) {
		if (read_arg.payload_size < uuid->size) {
			ret = -EINVAL;
			goto out_uuid;
		}

		/* This limits us to a maximum payload size of 2G */
		if (copy_to_user(u64_to_user_ptr(read_arg.payload_ptr),
				 uuid->ptr, uuid->size)) {
			ret = -EFAULT;
			goto out_uuid;
		}
	}

	read_arg.payload_size = uuid->size;
	memcpy(read_arg.uuid, uuid->uuid, sizeof(read_arg.uuid));

	if (copy_to_user(u64_to_user_ptr(arg), &read_arg, sizeof(read_arg)))
		ret = -EFAULT;

	DD_INFO(debugger, "read_uuid: payload delivery of %llu bytes returned %ld\n", uuid->size, ret);

out_uuid:
	i915_uuid_put(uuid);
	return ret;
}

static long i915_debugger_ioctl(struct file *file,
				unsigned int cmd,
				unsigned long arg)
{
	struct i915_debugger * const debugger = file->private_data;
	long ret;

	if (is_debugger_closed(debugger)) {
		ret = -ENODEV;
		goto out;
	}

	switch(cmd) {
	case PRELIM_I915_DEBUG_IOCTL_READ_EVENT:
		ret = i915_debugger_read_event(debugger, arg,
					       file->f_flags & O_NONBLOCK);
		DD_VERBOSE(debugger, "ioctl cmd=READ_EVENT ret=%ld\n", ret);
		break;
	case PRELIM_I915_DEBUG_IOCTL_READ_UUID:
		ret = i915_debugger_read_uuid_ioctl(debugger, cmd, arg);
		DD_VERBOSE(debugger, "ioctl cmd=READ_UUID ret = %ld\n", ret);
		break;
	default:
		ret = -EINVAL;
		break;
	}

out:
	if (ret < 0)
		DD_INFO(debugger, "ioctl cmd=0x%x arg=0x%lx ret=%ld\n", cmd, arg, ret);

	return ret;
}

static void
i915_debugger_discover_uuids(struct i915_drm_client *client)
{
	unsigned long idx;
	struct i915_uuid_resource *uuid;

	/*
	 * Lock not needed since i915_debugger_wait_in_discovery
	 * prevents from changing the set.
	 */
	xa_for_each(&client->uuids_xa, idx, uuid)
		i915_debugger_uuid_create(client, uuid);
}

static void
__i915_debugger_vm_send_event(struct i915_debugger *debugger,
			      const struct i915_drm_client *client,
			      u32 flags, u64 handle, gfp_t gfp)
{
	struct i915_debug_event_vm *vm_event;
	struct i915_debug_event *event;

	event = i915_debugger_create_event(debugger,
					   PRELIM_DRM_I915_DEBUG_EVENT_VM,
					   flags,
					   sizeof(*vm_event),
					   gfp);
	if (event) {
		vm_event = from_event(vm_event, event);
		vm_event->client_handle = client->id;
		vm_event->handle = handle;

		i915_debugger_send_event(debugger, event);
		kfree(event);
	}
}

static int __i915_debugger_alloc_handle(struct i915_debugger *debugger,
					void *data, u32 *handle)
{
	int ret;

	ret = xa_alloc_cyclic(&debugger->resources_xa, handle, data,
			      xa_limit_32b, &debugger->next_handle,
			      GFP_KERNEL);
	if (ret == 1)
		ret = 0;

	if (ret) {
		DD_ERR(debugger, "xa_alloc_cyclic failed %d, disconnecting\n", ret);
		i915_debugger_close(debugger);
	}

	return ret;
}

static int __i915_debugger_get_handle(struct i915_debugger *debugger,
				      const void *data, u32 *handle)
{
	unsigned long idx;
	int ret = -ENOENT;
	void *entry;

	xa_lock(&debugger->resources_xa);
	xa_for_each(&debugger->resources_xa, idx, entry) {
		if (entry == data) {
			if (handle)
				*handle = idx;
			ret = 0;
			break;
		}
	}
	xa_unlock(&debugger->resources_xa);
	return ret;
}

static inline bool
__i915_debugger_has_resource(struct i915_debugger *debugger, const void *data)
{
	return __i915_debugger_get_handle(debugger, data, NULL) == 0;
}

static int __i915_debugger_del_handle(struct i915_debugger *debugger, u32 id)
{
	return xa_erase(&debugger->resources_xa, id) ? 0 : -ENOENT;
}

static void __i915_debugger_vm_create(struct i915_debugger *debugger,
				      struct i915_drm_client *client,
				      struct i915_address_space *vm)
{
	u32 handle;

	if (__i915_debugger_alloc_handle(debugger, vm, &handle)) {
		DD_ERR(debugger,
		       "unable to allocate vm handle for client %u, disconnecting\n",
		       client->id);
		i915_debugger_close(debugger);
		return;
	}

	__i915_debugger_vm_send_event(debugger, client,
				      PRELIM_DRM_I915_DEBUG_EVENT_CREATE,
				      handle,
				      GFP_KERNEL);
}

static void i915_debugger_discover_vma(struct i915_debugger *debugger,
				       struct i915_address_space *vm)
{
	unsigned long count;
	void *ev = NULL, *__ev;
	u32 vm_handle;
	size_t size;

	if (__i915_debugger_get_handle(debugger, vm, &vm_handle)) {
		DD_WARN(debugger, "discover_vm did not found handle for vm %p\n", vm);
		return;
	}

	size = 0;
	do {
		struct drm_mm_node *node;
		size_t used = 0;

		count = 0;
		__ev = ev;
		mutex_lock(&vm->mutex);
		drm_mm_for_each_node(node, &vm->mm) {
			struct i915_vma *vma = container_of(node, typeof(*vma), node);
			struct i915_debug_event_vm_bind *e = __ev;
			struct i915_vma_metadata *metadata;

			if (!i915_vma_is_persistent(vma))
				continue;

			used += sizeof(*e);
			list_for_each_entry(metadata, &vma->metadata_list, vma_link)
				used += sizeof(e->uuids[0]);

			if (used <= size) {
				e->base.type     = PRELIM_DRM_I915_DEBUG_EVENT_VM_BIND;
				e->base.flags    = PRELIM_DRM_I915_DEBUG_EVENT_CREATE;
				e->base.size     = sizeof(*e);
				e->client_handle = vm->client->id;
				e->vm_handle     = vm_handle;
				e->va_start      = i915_vma_offset(vma);
				e->va_length     = i915_vma_size(vma);
				e->num_uuids	 = 0;
				e->flags         = 0;

				list_for_each_entry(metadata,
						    &vma->metadata_list, vma_link) {
					e->uuids[e->num_uuids++] = metadata->uuid->handle;
					e->base.size += sizeof(e->uuids[0]);
				}

				__ev += e->base.size;
				count++;
			}
		}
		mutex_unlock(&vm->mutex);
		if (size >= used)
			break;

		__ev = krealloc(ev, used, GFP_KERNEL);
		if (!__ev) {
			DD_ERR(debugger, "could not allocate bind event, disconnecting\n");
			goto out;
		}
		ev = __ev;
		size = used;
	} while (1);

	for (__ev = ev; count--; ) {
		struct i915_debug_event_vm_bind *e = __ev;
		e->base.seqno = atomic_long_inc_return(&debugger->event_seqno);
		i915_debugger_send_event(debugger, to_event(e));
		__ev += e->base.size;
	}

out:
	kfree(ev);
}

static void i915_debugger_discover_vm(struct i915_debugger *debugger,
				      struct i915_drm_client *client)
{
	struct i915_address_space *vm;
	unsigned long i;

	if (!client->file) /* protect kernel internals */
		return;

	if (!is_client_connected(debugger, client))
		return;

	xa_for_each(&client->file->vm_xa, i, vm) {
		if (__i915_debugger_has_resource(debugger, vm))
			continue;

		__i915_debugger_vm_create(debugger, client, vm);
		i915_debugger_discover_vma(debugger, vm);
	}
}

static void i915_debugger_ctx_vm_def(struct i915_debugger *debugger,
				     const struct i915_drm_client *client,
				     u32 ctx_id,
				     const struct i915_address_space *vm)
{
	struct i915_debug_event *event;
	struct i915_debug_event_context_param *ep;
	u32 vm_handle;

	if (__i915_debugger_get_handle(debugger, vm, &vm_handle))
		return;

	event = i915_debugger_create_event(debugger,
					   PRELIM_DRM_I915_DEBUG_EVENT_CONTEXT_PARAM,
					   PRELIM_DRM_I915_DEBUG_EVENT_CREATE,
					   sizeof(*ep),
					   GFP_KERNEL);
	if (!event)
		return;

	ep = from_event(ep, event);
	ep->client_handle = client->id;
	ep->ctx_handle = ctx_id;
	ep->param.ctx_id = ctx_id;
	ep->param.param = I915_CONTEXT_PARAM_VM;
	ep->param.value = vm_handle;

	i915_debugger_send_event(debugger, event);

	kfree(event);
}

static void i915_debugger_ctx_vm_create(struct i915_debugger *debugger,
					struct i915_gem_context *ctx)
{
	struct i915_address_space *vm = i915_gem_context_get_eb_vm(ctx);
	bool vm_found;

	vm_found = __i915_debugger_has_resource(debugger, vm);
	if (!vm_found)
		__i915_debugger_vm_create(debugger, ctx->client, vm);

	i915_debugger_ctx_vm_def(debugger, ctx->client, ctx->id, vm);

	if (!vm_found)
		i915_debugger_discover_vma(debugger, vm);

	i915_vm_put(vm);
}

static void
i915_debugger_discover_contexts(struct i915_debugger *debugger,
				struct i915_drm_client *client)
{
	struct i915_gem_context *ctx;

	if (!is_client_connected(debugger, client))
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(ctx, &client->ctx_list, client_link) {
		if (!i915_gem_context_get_rcu(ctx))
			continue;

		if (!i915_gem_context_is_closed(ctx)) {
			rcu_read_unlock();

			i915_debugger_context_create(ctx);
			i915_debugger_ctx_vm_create(debugger, ctx);

			rcu_read_lock();
		}

		i915_gem_context_put(ctx);
	}
	rcu_read_unlock();
}

static bool
i915_debugger_client_task_register(const struct i915_debugger * const debugger,
				   struct i915_drm_client * const client,
				   struct task_struct * const task)
{
	bool registered = false;

	rcu_read_lock();
	if (!READ_ONCE(client->closed) &&
	    !is_debugger_closed(debugger) &&
	    same_thread_group(debugger->target_task, task)) {
		GEM_WARN_ON(client->debugger_session >= debugger->session);
		WRITE_ONCE(client->debugger_session, debugger->session);
		registered = true;
	}
	rcu_read_unlock();

	return registered;
}

static bool
i915_debugger_register_client(const struct i915_debugger * const debugger,
			      struct i915_drm_client * const client)
{
	const struct i915_drm_client_name *name;
	struct task_struct *client_task = NULL;
	bool registered;

	rcu_read_lock();
	name = __i915_drm_client_name(client);
	if (name) {
		client_task = get_pid_task(name->pid, PIDTYPE_PID);
	} else {
		/* XXX: clients->xarray can contain unregistered clients, should we wait or lock? */
		DD_WARN(debugger, "client %d with no pid, will not be found by discovery\n",
			 client->id);
	}
	rcu_read_unlock();

	if (!client_task)
		return false;

	registered = i915_debugger_client_task_register(debugger, client, client_task);
	put_task_struct(client_task);

	return registered;
}

static void
i915_debugger_client_discovery(struct i915_debugger *debugger)
{
	struct i915_drm_client *client;
	unsigned long idx;

	rcu_read_lock();
	xa_for_each(&debugger->i915->clients.xarray, idx, client) {
		if (READ_ONCE(client->closed))
			continue;

		client = i915_drm_client_get_rcu(client);
		if (!client)
			continue;

		rcu_read_unlock();

		if (i915_debugger_register_client(debugger, client)) {
			DD_INFO(debugger, "client %u registered, discovery start", client->id);

			i915_debugger_client_create(client);
			i915_debugger_discover_uuids(client);
			i915_debugger_discover_contexts(debugger, client);
			i915_debugger_discover_vm(debugger, client);

			DD_INFO(debugger, "client %u discovery done", client->id);
		}

		i915_drm_client_put(client);

		rcu_read_lock();
	}

	rcu_read_unlock();
}

static int i915_debugger_discovery_worker(void *data)
{
	struct i915_debugger *debugger = data;

	if (kthread_should_stop())
		goto out;

	if (is_debugger_closed(debugger))
		goto out;

	i915_debugger_client_discovery(debugger);

out:
	complete_all(&debugger->discovery);
	i915_debugger_put(debugger);
	return 0;
}

static int i915_debugger_release(struct inode *inode, struct file *file)
{
	struct i915_debugger *debugger = file->private_data;

	i915_debugger_close(debugger);
	i915_debugger_put(debugger);
	return 0;
}

static const struct file_operations fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.release	= i915_debugger_release,
	.poll		= i915_debugger_poll,
	.read		= i915_debugger_read,
	.unlocked_ioctl	= i915_debugger_ioctl,
};

static struct task_struct *find_get_target(const pid_t nr)
{
	struct task_struct *task;

	rcu_read_lock();
	task = pid_task(find_pid_ns(nr, task_active_pid_ns(current)), PIDTYPE_PID);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	return task;
}

static int discovery_thread_stop(struct task_struct *task)
{
	int ret;

	ret = kthread_stop(task);

	GEM_WARN_ON(ret != -EINTR);
	return ret;
}

static int
i915_debugger_open(struct drm_i915_private * const i915,
		   struct prelim_drm_i915_debugger_open_param * const param)
{
	const u64 known_open_flags = PRELIM_DRM_I915_DEBUG_FLAG_FD_NONBLOCK;
	struct i915_debugger *debugger;
	struct task_struct *discovery_task;
	unsigned long f_flags = 0;
	int debug_fd;
	bool allowed;
	int ret;

	if (!param->pid)
		return -EINVAL;

	if (param->flags & ~known_open_flags)
		return -EINVAL;

	if (param->version && param->version != PRELIM_DRM_I915_DEBUG_VERSION)
		return -EINVAL;

	/* XXX: You get all for now */
	if (param->events)
		return -EINVAL;

	if (param->extensions)
		return -EINVAL;

	debugger = kzalloc(sizeof(*debugger), GFP_KERNEL);
	if (!debugger)
		return -ENOMEM;

	kref_init(&debugger->ref);
	mutex_init(&debugger->lock);
	atomic_long_set(&debugger->event_seqno, 0);
	init_completion(&debugger->read_done);
	init_waitqueue_head(&debugger->write_done);
	init_completion(&debugger->discovery);
	xa_init_flags(&debugger->resources_xa, XA_FLAGS_ALLOC1);

	debugger->target_task = find_get_target(param->pid);
	if (!debugger->target_task) {
		ret = -ENOENT;
		goto err_free;
	}

	allowed = ptrace_may_access(debugger->target_task, PTRACE_MODE_READ_REALCREDS);
	if (!allowed) {
		ret = -EACCES;
		goto err_put_task;
	}

	kref_get(&debugger->ref); /* +1 for worker thread */
	discovery_task = kthread_create(i915_debugger_discovery_worker, debugger,
					"[i915_debugger_discover]");
	if (IS_ERR(discovery_task)) {
		ret = PTR_ERR(discovery_task);
		goto err_put_task;
	}

	if (param->flags & PRELIM_DRM_I915_DEBUG_FLAG_FD_NONBLOCK)
		f_flags |= O_NONBLOCK;

	mutex_lock(&i915->debug.mutex);
	if (i915->debug.debugger) {
		ret = -EBUSY;
		goto err_unlock;
	}

	/* XXX handle the overflow without bailing out */
	if (i915->debug.session_count + 1 == 0) {
		drm_err(&i915->drm, "debugger connections exhausted. (you need module reload)\n");
		ret = -EBUSY;
		goto err_unlock;
	}

	debug_fd = anon_inode_getfd("[i915_debugger]", &fops, debugger, f_flags);
	if (debug_fd < 0) {
		ret = debug_fd;
		goto err_unlock;
	}


	if (i915->params.debugger_log_level < 0)
		debugger->debug_lvl = DD_DEBUG_LEVEL_WARN;
	else
		debugger->debug_lvl = min_t(int, i915->params.debugger_log_level,
					    DD_DEBUG_LEVEL_VERBOSE);

	debugger->i915 = i915;
	debugger->session = ++i915->debug.session_count;
	rcu_assign_pointer(i915->debug.debugger, debugger);
	mutex_unlock(&i915->debug.mutex);

	complete(&debugger->read_done);
	wake_up_process(discovery_task);

	DD_INFO(debugger, "connected, debug level = %d", debugger->debug_lvl);

	if (debugger->debug_lvl >= DD_DEBUG_LEVEL_VERBOSE)
		printk(KERN_WARNING "i915_debugger: verbose debug level exposing raw addresses!\n");

	param->version = PRELIM_DRM_I915_DEBUG_VERSION;

	return debug_fd;

err_unlock:
	mutex_unlock(&i915->debug.mutex);
	discovery_thread_stop(discovery_task);
err_put_task:
	put_task_struct(debugger->target_task);
err_free:
	xa_destroy(&debugger->resources_xa);
	kfree(debugger);

	return ret;
}

static bool i915_debugger_modparms_are_sane(struct drm_i915_private *i915)
{
	const struct i915_params * const p = &i915->params;
	int fails = 0;

	if (p->debug_eu != 1 && ++fails)
		drm_warn(&i915->drm, "i915_debugger: i915.debug_eu=1 not set (is %d)\n",
			 p->debug_eu);

	return fails == 0;
}

int i915_debugger_open_ioctl(struct drm_device *dev,
			     void *data,
			     struct drm_file *file)
{
	struct drm_i915_private *i915 = to_i915(dev);
	struct prelim_drm_i915_debugger_open_param * const param = data;

	if (!i915_debugger_modparms_are_sane(i915))
		return -ENODEV;

	return i915_debugger_open(i915, param);
}

void i915_debugger_init(struct drm_i915_private *i915)
{
	mutex_init(&i915->debug.mutex);
}

void i915_debugger_fini(struct drm_i915_private *i915)
{
	mutex_lock(&i915->debug.mutex);
	rcu_replace_pointer(i915->debug.debugger, NULL, true);
	mutex_unlock(&i915->debug.mutex);
}

void i915_debugger_wait_on_discovery(struct drm_i915_private * const i915)
{
	const unsigned long waitjiffs = msecs_to_jiffies(5000);
	struct i915_debugger *debugger;
	long timeleft;

	debugger = i915_debugger_get(i915);
	if (!debugger)
		return;

	if (is_debugger_closed(debugger))
		goto out;

	if (!same_thread_group(debugger->target_task, current))
		goto out;

	timeleft = wait_for_completion_interruptible_timeout(&debugger->discovery,
							     waitjiffs);
	if (timeleft == -ERESTARTSYS) {
		DD_WARN(debugger,
			"task %d interrupted while waited during debugger discovery process\n",
			task_pid_nr(current));
	} else if (!timeleft) {
		DD_WARN(debugger,
			"task %d waited too long for discovery to complete. Ignoring barrier.\n",
			task_pid_nr(current));
	}
out:
	i915_debugger_put(debugger);
}

void i915_debugger_client_register(struct i915_drm_client *client)
{
	struct i915_debugger *debugger;

	GEM_WARN_ON(client_debugged(client));

	debugger = i915_debugger_get(client->clients->i915);
	if (!debugger)
		return;

	i915_debugger_client_task_register(debugger, client, current);

	i915_debugger_put(debugger);
}

void i915_debugger_client_release(struct i915_drm_client *client)
{
	WRITE_ONCE(client->debugger_session, 0);
}

static struct i915_debugger *
i915_debugger_get_for_client(const struct i915_drm_client *client)
{
	struct i915_debugger *debugger;

	if (!client_debugged(client))
		return NULL;

	debugger = i915_debugger_get(client->clients->i915);
	if (!debugger)
		return NULL;

	if (is_client_connected(debugger, client))
		return debugger;

	i915_debugger_put(debugger);

	return NULL;
}

static void
i915_debugger_send_client_event_ctor(const struct i915_drm_client *client,
				     u32 type, u32 flags, u64 size,
				     void (*constructor)(struct i915_debug_event *,
							 const void *),
				     const void *data,
				     gfp_t gfp)
{
	struct i915_debugger *debugger;
	struct i915_debug_event *event;

	debugger = i915_debugger_get_for_client(client);
	if (!debugger)
		return;

	event = i915_debugger_create_event(debugger, type, flags, size, gfp);
	if (event) {
		constructor(event, data);
		i915_debugger_send_event(debugger, event);
		kfree(event);
	}

	i915_debugger_put(debugger);
}

#define write_member(T_out, ptr, member, value) { \
	BUILD_BUG_ON(sizeof(*ptr) != sizeof(T_out)); \
	BUILD_BUG_ON(offsetof(typeof(*ptr), member) != \
		     offsetof(typeof(T_out), member)); \
	BUILD_BUG_ON(sizeof(ptr->member) != sizeof(value)); \
	BUILD_BUG_ON(sizeof(struct_member(T_out, member)) != sizeof(value)); \
	BUILD_BUG_ON(!typecheck(typeof((ptr)->member), value));	\
	memcpy(&ptr->member, &value, sizeof(ptr->member)); \
}

struct client_event_param {
	u64 handle;
};

static void client_event_ctor(struct i915_debug_event *event, const void *data)
{
	const struct client_event_param *p = data;
	struct i915_debug_event_client *ec = from_event(ec, event);

	write_member(struct prelim_drm_i915_debug_event_client, ec, handle, p->handle);
}

static void send_client_event(const struct i915_drm_client *client, u32 flags)
{
	const struct client_event_param p = {
		.handle = client->id,
	};

	i915_debugger_send_client_event_ctor(client,
					     PRELIM_DRM_I915_DEBUG_EVENT_CLIENT,
					     flags,
					     sizeof(struct prelim_drm_i915_debug_event_client),
					     client_event_ctor, &p,
					     GFP_KERNEL);
}

void i915_debugger_client_create(const struct i915_drm_client *client)
{
	if (!client_debugged(client))
		return;

	send_client_event(client, PRELIM_DRM_I915_DEBUG_EVENT_CREATE);
}

void i915_debugger_client_destroy(struct i915_drm_client *client)
{
	struct i915_uuid_resource *uuid_res;
	unsigned long idx;

	if (!client_debugged(client))
		return;

	xa_for_each(&client->uuids_xa, idx, uuid_res)
		i915_debugger_uuid_destroy(client, uuid_res);

	send_client_event(client, PRELIM_DRM_I915_DEBUG_EVENT_DESTROY);

	i915_debugger_client_release(client);
}

struct ctx_event_param {
	u64 client_handle;
	u64 handle;
};

static void ctx_event_ctor(struct i915_debug_event *event, const void *data)
{
	const struct ctx_event_param *p = data;
	struct i915_debug_event_context *ec = from_event(ec, event);

	write_member(struct prelim_drm_i915_debug_event_context, ec, client_handle, p->client_handle);
	write_member(struct prelim_drm_i915_debug_event_context, ec, handle, p->handle);
}

static void send_context_event(const struct i915_gem_context *ctx, u32 flags)
{
	const struct ctx_event_param p = {
		.client_handle = ctx->client->id,
		.handle = ctx->id
	};

	i915_debugger_send_client_event_ctor(ctx->client,
					     PRELIM_DRM_I915_DEBUG_EVENT_CONTEXT,
					     flags,
					     sizeof(struct prelim_drm_i915_debug_event_context),
					     ctx_event_ctor, &p,
					     GFP_KERNEL);
}

void i915_debugger_context_create(const struct i915_gem_context *ctx)
{
	if (!client_debugged(ctx->client))
		return;

	send_context_event(ctx, PRELIM_DRM_I915_DEBUG_EVENT_CREATE);
}

void i915_debugger_context_destroy(const struct i915_gem_context *ctx)
{
	if (!client_debugged(ctx->client))
		return;

	send_context_event(ctx, PRELIM_DRM_I915_DEBUG_EVENT_DESTROY);
}

struct uuid_event_param {
	u64 client_handle;
	u64 handle;
	u64 class_handle;
	u64 payload_size;
};

static void uuid_event_ctor(struct i915_debug_event *event, const void *data)
{
	const struct uuid_event_param *p = data;
	struct i915_debug_event_uuid *ec = from_event(ec, event);

	write_member(struct prelim_drm_i915_debug_event_uuid, ec, client_handle, p->client_handle);
	write_member(struct prelim_drm_i915_debug_event_uuid, ec, handle, p->handle);
	write_member(struct prelim_drm_i915_debug_event_uuid, ec, class_handle, p->class_handle);
	write_member(struct prelim_drm_i915_debug_event_uuid, ec, payload_size, p->payload_size);
}

static void send_uuid_event(const struct i915_drm_client *client,
			    const struct i915_uuid_resource *uuid,
			    u32 flags)
{
	struct uuid_event_param p = {
		.client_handle = client->id,
		.handle = uuid->handle,
		.class_handle = uuid->uuid_class,
		.payload_size = 0,
	};

	if (flags & PRELIM_DRM_I915_DEBUG_EVENT_CREATE)
		p.payload_size = uuid->size;

	i915_debugger_send_client_event_ctor(client,
					     PRELIM_DRM_I915_DEBUG_EVENT_UUID,
					     flags,
					     sizeof(struct prelim_drm_i915_debug_event_uuid),
					     uuid_event_ctor, &p,
					     GFP_KERNEL);
}

void i915_debugger_uuid_create(const struct i915_drm_client *client,
			       const struct i915_uuid_resource *uuid)
{
	if (!client_debugged(client))
		return;

	send_uuid_event(client, uuid, PRELIM_DRM_I915_DEBUG_EVENT_CREATE);
}

void i915_debugger_uuid_destroy(const struct i915_drm_client *client,
				const struct i915_uuid_resource *uuid)
{
	if (!client_debugged(client))
		return;

	send_uuid_event(client, uuid, PRELIM_DRM_I915_DEBUG_EVENT_DESTROY);
}

static void __i915_debugger_vma_send_event(struct i915_debugger *debugger,
					   struct i915_drm_client *client,
					   struct i915_vma *vma,
					   u32 flags,
					   gfp_t gfp)
{
	struct i915_vma_metadata *metadata;
	struct i915_debug_event_vm_bind *ev;
	struct i915_debug_event *event;
	u32 vm_handle;
	u64 size;

	if (GEM_WARN_ON(!vma))
		return;

	if (__i915_debugger_get_handle(debugger, vma->vm, &vm_handle))
		return;

	size = sizeof(*ev);
	list_for_each_entry(metadata, &vma->metadata_list, vma_link)
		size += sizeof(ev->uuids[0]);

	event = i915_debugger_create_event(debugger,
					   PRELIM_DRM_I915_DEBUG_EVENT_VM_BIND,
					   flags,
					   size,
					   gfp);
	if (!event) {
		DD_ERR(debugger, "debugger: vma: alloc fail, bailing out\n");
		return;
	}

	ev = from_event(ev, event);

	ev->client_handle = client->id;
	ev->vm_handle     = vm_handle;
	ev->va_start      = i915_vma_offset(vma);
	ev->va_length     = i915_vma_size(vma);
	ev->flags         = 0;
	ev->num_uuids     = 0;

	list_for_each_entry(metadata, &vma->metadata_list, vma_link)
		ev->uuids[ev->num_uuids++] = metadata->uuid->handle;

	i915_debugger_send_event(debugger, event);

	kfree(event);
}

void i915_debugger_vma_insert(struct i915_drm_client *client,
			      struct i915_vma *vma)
{
	struct i915_debugger *debugger;

	debugger = i915_debugger_get_for_client(client);
	if (!debugger)
		return;

	if (i915_vma_is_persistent(vma))
		__i915_debugger_vma_send_event(debugger, client, vma,
					       PRELIM_DRM_I915_DEBUG_EVENT_CREATE,
					       GFP_ATOMIC);

	i915_debugger_put(debugger);
}

void i915_debugger_vma_evict(struct i915_drm_client *client,
			     struct i915_vma *vma)
{
	struct i915_debugger *debugger;

	debugger = i915_debugger_get_for_client(client);
	if (!debugger)
		return;

	unmap_mapping_range(vma->vm->inode->i_mapping,
			    vma->node.start, vma->node.size,
			    1);

	if (i915_vma_is_persistent(vma))
		__i915_debugger_vma_send_event(debugger, client, vma,
					       PRELIM_DRM_I915_DEBUG_EVENT_DESTROY,
					       GFP_ATOMIC);

	i915_debugger_put(debugger);
}

void i915_debugger_vm_create(struct i915_drm_client *client,
			     struct i915_address_space *vm)
{
	struct i915_debugger *debugger;

	if (!client)
		return;

	if (GEM_WARN_ON(!vm))
		return;

	debugger = i915_debugger_get_for_client(client);
	if (!debugger)
		return;

	if (!__i915_debugger_has_resource(debugger, vm))
		__i915_debugger_vm_create(debugger, client, vm);

	i915_debugger_put(debugger);
}

void i915_debugger_vm_destroy(struct i915_drm_client *client,
			      struct i915_address_space *vm)
{
	struct i915_debugger *debugger;
	u32 handle;

	if (!client)
		return;

	if (GEM_WARN_ON(!vm))
		return;

	debugger = i915_debugger_get_for_client(client);
	if (!debugger)
		return;

	if (atomic_read(&vm->open) > 1)
		goto out;

	if (__i915_debugger_get_handle(debugger, vm, &handle))
		goto out;

	__i915_debugger_del_handle(debugger, handle);
	__i915_debugger_vm_send_event(debugger, client,
				      PRELIM_DRM_I915_DEBUG_EVENT_DESTROY,
				      handle,
				      GFP_KERNEL);

out:
	i915_debugger_put(debugger);
}

void i915_debugger_context_param_vm(const struct i915_drm_client *client,
				    struct i915_gem_context *ctx,
				    struct i915_address_space *vm)
{
	struct i915_debugger *debugger;

	if (!client)
		return;

	if (!ctx) {
		GEM_WARN_ON(!ctx);
		return;
	}

	if (!vm) {
		GEM_WARN_ON(!vm);
		return;
	}

	debugger = i915_debugger_get_for_client(client);
	if (!debugger)
		return;

	i915_debugger_ctx_vm_def(debugger, client, ctx->id, vm);
	i915_debugger_put(debugger);
}

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftests/i915_debugger.c"
#endif
