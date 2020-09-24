// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Intel Corporation
 */

#include <linux/anon_inodes.h>
#include <linux/ptrace.h>

#include "i915_debugger.h"
#include "i915_drm_client.h"
#include "i915_drv.h"

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

static void i915_debugger_print_event(const struct i915_debugger * const debugger,
				      const char * const prefix,
				      const struct i915_debug_event * const event)
{
	static const debug_event_printer_t event_printers[] = {
		NULL,
		NULL,
		event_printer_client,
		event_printer_context,
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

static void i915_debugger_detach(const struct i915_debugger *debugger)
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
	default:
		ret = -EINVAL;
		break;
	}

out:
	if (ret < 0)
		DD_INFO(debugger, "ioctl cmd=0x%x arg=0x%lx ret=%ld\n", cmd, arg, ret);

	return ret;

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

static int
i915_debugger_open(struct drm_i915_private * const i915,
		   struct prelim_drm_i915_debugger_open_param * const param)
{
	const u64 known_open_flags = PRELIM_DRM_I915_DEBUG_FLAG_FD_NONBLOCK;
	struct i915_debugger *debugger;
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

	DD_INFO(debugger, "connected, debug level = %d", debugger->debug_lvl);

	if (debugger->debug_lvl >= DD_DEBUG_LEVEL_VERBOSE)
		printk(KERN_WARNING "i915_debugger: verbose debug level exposing raw addresses!\n");

	param->version = PRELIM_DRM_I915_DEBUG_VERSION;

	return debug_fd;

err_unlock:
	mutex_unlock(&i915->debug.mutex);
err_put_task:
	put_task_struct(debugger->target_task);
err_free:
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

void i915_debugger_client_register(struct i915_drm_client *client)
{
	struct drm_i915_private * const i915 = client->clients->i915;
	struct i915_debugger *debugger;

	GEM_WARN_ON(client->debugger_session);

	rcu_read_lock();
	debugger = rcu_dereference(i915->debug.debugger);
	if (debugger && same_thread_group(debugger->target_task, current)) {
		GEM_WARN_ON(client->debugger_session >= debugger->session);
		WRITE_ONCE(client->debugger_session, debugger->session);
	}
	rcu_read_unlock();
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

void i915_debugger_client_destroy(const struct i915_drm_client *client)
{
	if (!client_debugged(client))
		return;

	send_client_event(client, PRELIM_DRM_I915_DEBUG_EVENT_DESTROY);
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

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftests/i915_debugger.c"
#endif
