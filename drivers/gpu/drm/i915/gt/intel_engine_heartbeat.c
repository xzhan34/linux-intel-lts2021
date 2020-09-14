// SPDX-License-Identifier: MIT
/*
 * Copyright © 2019 Intel Corporation
 */

#include "i915_drv.h"
#include "i915_request.h"

#include "intel_breadcrumbs.h"
#include "intel_context.h"
#include "intel_engine_heartbeat.h"
#include "intel_engine_pm.h"
#include "intel_engine.h"
#include "intel_gt.h"
#include "intel_reset.h"

/*
 * While the engine is active, we send a periodic pulse along the engine
 * to check on its health and to flush any idle-barriers. If that request
 * is stuck, and we fail to preempt it, we declare the engine hung and
 * issue a reset -- in the hope that restores progress.
 */

static bool next_heartbeat(struct intel_engine_cs *engine)
{
	struct i915_request *rq;
	long delay;

	delay = READ_ONCE(engine->props.heartbeat_interval_ms);

	rq = engine->heartbeat.systole;

	/*
	 * FIXME: The final period extension is disabled if the period has been
	 * modified from the default. This is to prevent issues with certain
	 * selftests which override the value and expect specific behaviour.
	 * Once the selftests have been updated to either cope with variable
	 * heartbeat periods (or to override the pre-emption timeout as well,
	 * or just to add a selftest specific override of the extension), the
	 * generic override can be removed.
	 */
	if (rq && rq->sched.attr.priority >= I915_PRIORITY_BARRIER &&
	    delay == engine->defaults.heartbeat_interval_ms) {
		long longer;

		/*
		 * The final try is at the highest priority possible. Up until now
		 * a pre-emption might not even have been attempted. So make sure
		 * this last attempt allows enough time for a pre-emption to occur.
		 */
		longer = READ_ONCE(engine->props.preempt_timeout_ms) * 2;
		longer = intel_clamp_heartbeat_interval_ms(engine, longer);
		if (longer > delay)
			delay = longer;
	}

	if (!delay)
		return false;

	delay = msecs_to_jiffies_timeout(delay);
	if (delay >= HZ)
		delay = round_jiffies_up_relative(delay);
	mod_delayed_work(system_highpri_wq, &engine->heartbeat.work, delay + 1);

	return true;
}

static struct i915_request *
heartbeat_create(struct intel_context *ce, gfp_t gfp)
{
	struct i915_request *rq;

	intel_context_enter(ce);
	rq = __i915_request_create(ce, gfp);
	intel_context_exit(ce);

	return rq;
}

static void idle_pulse(struct intel_engine_cs *engine, struct i915_request *rq)
{
	engine->wakeref_serial = READ_ONCE(engine->serial) + 1;
	i915_request_add_active_barriers(rq);
}

static void heartbeat_commit(struct i915_request *rq, int prio)
{
	idle_pulse(rq->engine, rq);

	__i915_request_commit(rq);
	__i915_request_queue(rq, prio);
}

static void show_heartbeat(const struct i915_request *rq,
			   struct intel_engine_cs *engine)
{
	struct drm_printer p = drm_debug_printer("heartbeat");

	if (!rq) {
		intel_engine_dump(engine, &p,
				  "%s heartbeat not ticking\n",
				  engine->name);
	} else {
		intel_engine_dump(engine, &p,
				  "%s heartbeat {seqno:%llx:%lld, prio:%d} not ticking\n",
				  engine->name,
				  rq->fence.context,
				  rq->fence.seqno,
				  rq->sched.attr.priority);
	}
}

static void
reset_engine(struct intel_engine_cs *engine, struct i915_request *rq)
{
	if (IS_ENABLED(CONFIG_DRM_I915_DEBUG_GEM))
		show_heartbeat(rq, engine);

	intel_gt_handle_error(engine->gt, engine->mask,
			      I915_ERROR_CAPTURE,
			      "stopped heartbeat on %s",
			      engine->name);
}

static bool check_attn(struct intel_engine_cs *engine)
{
	if (!intel_engine_has_eu_attention(engine))
		return false;

	/* We happily accept non attention without forcewake */
	if (!intel_engine_eu_attention_fw(engine))
		return false;

	intel_gt_handle_error(engine->gt, engine->mask,
			      I915_ERROR_CAPTURE,
			      "eu attention on %s",
			      engine->name);

	return true;
}

static struct i915_request *get_next_heartbeat(struct intel_timeline *tl)
{
	struct i915_request *rq;

	/*
	 * The kernel context may be used for other preemption requests,
	 * any of which may serve to track forward progress along the engine,
	 * so use the next request to be executed along the timeline as
	 * as the engine's heartbeat.
	 */
	rq = to_request(i915_active_fence_get(&tl->last_request));
	if (!rq)
		return NULL;

	rcu_read_lock();
	do {
		struct i915_request *prev;

		/*
		 * Carefully walk backwards along the timeline.
		 * Beware inflight requests may be retired at any time.
		 */
		prev = list_prev_entry(rq, link);
		if (list_is_head(&prev->link, &tl->requests))
			break;

		/* Check that link.prev was still valid */
		if (i915_request_signaled(rq))
			break;

		prev = i915_request_get_rcu(prev);
		if (!prev)
			break;

		/* Check this request is still active on this timeline */
		if (rcu_access_pointer(prev->timeline) != tl ||
		    __i915_request_is_complete(prev)) {
			i915_request_put(prev);
			break;
		}

		i915_request_put(rq);
		rq = prev;
	} while(1);
	rcu_read_unlock();

	rq->emitted_jiffies = jiffies;
	return rq;
}

static unsigned long preempt_timeout(const struct i915_request *rq)
{
	long delay = READ_ONCE(rq->engine->props.preempt_timeout_ms);

	return rq->emitted_jiffies + msecs_to_jiffies_timeout(delay);
}

static void heartbeat(struct work_struct *wrk)
{
	struct intel_engine_cs *engine =
		container_of(wrk, typeof(*engine), heartbeat.work.work);
	struct intel_context *ce = engine->kernel_context;
	int prio = I915_PRIORITY_MIN;
	struct i915_request *rq;
	unsigned long serial;

	/* Just in case everything has gone horribly wrong, give it a kick */
	intel_engine_flush_submission(engine);
	intel_engine_signal_breadcrumbs(engine);

	rq = engine->heartbeat.systole;
	if (rq && i915_request_completed(rq)) {
		i915_request_put(rq);
		engine->heartbeat.systole = NULL;
	}

	if (!intel_engine_pm_get_if_awake(engine))
		return;

	if (intel_gt_is_wedged(engine->gt))
		goto out;

	if (check_attn(engine))
		goto out;

	if (i915_sched_engine_disabled(engine->sched_engine)) {
		reset_engine(engine, engine->heartbeat.systole);
		goto out;
	}

	rq = READ_ONCE(engine->heartbeat.systole);
	if (rq) {
		long delay = READ_ONCE(engine->props.heartbeat_interval_ms);

		if (i915_request_completed(rq))
			goto out;

		/* Safeguard against too-fast worker invocations */
		if (!time_after(jiffies,
				rq->emitted_jiffies + msecs_to_jiffies(delay)))
			goto out;

		if (!i915_sw_fence_signaled(&rq->submit)) {
			/*
			 * Not yet submitted, system is stalled.
			 *
			 * This more often happens for ring submission,
			 * where all contexts are funnelled into a common
			 * ringbuffer. If one context is blocked on an
			 * external fence, not only is it not submitted,
			 * but all other contexts, including the kernel
			 * context are stuck waiting for the signal.
			 */
		} else if (rq->sched.attr.priority < I915_PRIORITY_BARRIER) {
			int prio;

			/*
			 * Gradually raise the priority of the heartbeat to
			 * give high priority work [which presumably desires
			 * low latency and no jitter] the chance to naturally
			 * complete before being preempted.
			 */
			prio = I915_PRIORITY_NORMAL;
			if (rq->sched.attr.priority >= prio)
				prio = I915_PRIORITY_HEARTBEAT;
			if (rq->sched.attr.priority >= prio)
				prio = I915_PRIORITY_BARRIER;

			local_bh_disable();
			i915_request_set_priority(rq, prio);
			local_bh_enable();
		} else if (time_before(jiffies, preempt_timeout(rq))) {
			/*
			 * Give the engine-reset, triggered by a preemption
			 * timeout, a chance to run before we force a full GT
			 * reset.
			 */
			goto out;
		} else {
			reset_engine(engine, rq);
		}

		rq->emitted_jiffies = jiffies;
		goto out;
	}

	/* Reuse the next active pulse on our timeline as the next heartbeat */
	engine->heartbeat.systole = get_next_heartbeat(ce->timeline);
	if (engine->heartbeat.systole)
		goto out;

	serial = READ_ONCE(engine->serial);
	if (engine->wakeref_serial == serial)
		goto out;

	if (!mutex_trylock(&ce->timeline->mutex)) {
		/* Unable to lock the kernel timeline, is the engine stuck? */
		if (xchg(&engine->heartbeat.blocked, serial) == serial)
			intel_gt_handle_error(engine->gt, engine->mask,
					      I915_ERROR_CAPTURE,
					      "no heartbeat on %s",
					      engine->name);
		goto out;
	}

	rq = get_next_heartbeat(ce->timeline);
	if (!rq) {
		rq = heartbeat_create(ce, GFP_NOWAIT | __GFP_NOWARN);
		if (IS_ERR(rq))
			goto unlock;

		i915_request_get(rq);
		heartbeat_commit(rq, prio);
	}
	engine->heartbeat.systole = rq;

unlock:
	mutex_unlock(&ce->timeline->mutex);
out:
	if (!engine->i915->params.enable_hangcheck || !next_heartbeat(engine))
		i915_request_put(fetch_and_zero(&engine->heartbeat.systole));
	intel_engine_pm_put_async(engine);
}

void intel_engine_unpark_heartbeat(struct intel_engine_cs *engine)
{
	if (!CONFIG_DRM_I915_HEARTBEAT_INTERVAL)
		return;

	next_heartbeat(engine);
}

void intel_engine_park_heartbeat(struct intel_engine_cs *engine)
{
	if (cancel_delayed_work(&engine->heartbeat.work))
		i915_request_put(fetch_and_zero(&engine->heartbeat.systole));
}

void intel_gt_unpark_heartbeats(struct intel_gt *gt)
{
	struct intel_engine_cs *engine;
	enum intel_engine_id id;

	for_each_engine(engine, gt, id)
		if (intel_engine_pm_is_awake(engine))
			intel_engine_unpark_heartbeat(engine);
}

void intel_gt_park_heartbeats(struct intel_gt *gt)
{
	struct intel_engine_cs *engine;
	enum intel_engine_id id;

	for_each_engine(engine, gt, id)
		intel_engine_park_heartbeat(engine);
}

void intel_engine_init_heartbeat(struct intel_engine_cs *engine)
{
	INIT_DELAYED_WORK(&engine->heartbeat.work, heartbeat);
}

static int __intel_engine_pulse(struct intel_engine_cs *engine)
{
	struct intel_context *ce = engine->kernel_context;
	int prio = I915_PRIORITY_BARRIER;
	struct i915_request *rq;

	lockdep_assert_held(&ce->timeline->mutex);
	GEM_BUG_ON(!intel_engine_has_preemption(engine));
	GEM_BUG_ON(!intel_engine_pm_is_awake(engine));

	/*
	 * Reuse the last pulse if we know it hasn't already started.
	 *
	 * Before the pulse can start, it must perform the context switch,
	 * forcing the active context away from the engine. As it has not
	 * yet started, we know that we haven't yet flushed any other context,
	 * thus the previously submitted pulse is still viable.
	 */
	rq = to_request(i915_active_fence_get(&ce->timeline->last_request));
	if (rq) {
		if (i915_request_has_sentinel(rq) &&
		    !i915_request_started(rq)) {
			i915_request_set_priority(rq, prio);
			prio = 0;
		}
		i915_request_put(rq);
		if (!prio)
			return 0;
	}

	rq = heartbeat_create(ce, GFP_NOWAIT | __GFP_NOWARN);
	if (IS_ERR(rq))
		return PTR_ERR(rq);

	__set_bit(I915_FENCE_FLAG_SENTINEL, &rq->fence.flags);

	heartbeat_commit(rq, prio);
	GEM_BUG_ON(rq->sched.attr.priority < I915_PRIORITY_BARRIER);

	return 0;
}

static unsigned long set_heartbeat(struct intel_engine_cs *engine,
				   unsigned long delay)
{
	unsigned long old;

	old = xchg(&engine->props.heartbeat_interval_ms, delay);
	if (delay)
		intel_engine_unpark_heartbeat(engine);
	else
		intel_engine_park_heartbeat(engine);

	return old;
}

int intel_engine_set_heartbeat(struct intel_engine_cs *engine,
			       unsigned long delay)
{
	struct intel_context *ce = engine->kernel_context;
	int err = 0;

	if (!delay && !intel_engine_has_preempt_reset(engine))
		return -ENODEV;

	/* FIXME: Remove together with equally marked hack in next_heartbeat. */
	if (delay != engine->defaults.heartbeat_interval_ms &&
	    delay < 2 * engine->props.preempt_timeout_ms) {
		if (intel_engine_uses_guc(engine))
			drm_notice(&engine->i915->drm, "%s heartbeat interval adjusted to a non-default value which may downgrade individual engine resets to full GPU resets!\n",
				   engine->name);
		else
			drm_notice(&engine->i915->drm, "%s heartbeat interval adjusted to a non-default value which may cause engine resets to target innocent contexts!\n",
				   engine->name);
	}

	intel_engine_pm_get(engine);

	err = mutex_lock_interruptible(&ce->timeline->mutex);
	if (err)
		goto out_rpm;

	if (delay != engine->props.heartbeat_interval_ms) {
		unsigned long saved = set_heartbeat(engine, delay);

		/* recheck current execution */
		if (intel_engine_has_preemption(engine)) {
			err = __intel_engine_pulse(engine);
			if (err)
				set_heartbeat(engine, saved);
		}
	}

	mutex_unlock(&ce->timeline->mutex);

out_rpm:
	intel_engine_pm_put(engine);
	return err;
}

int intel_engine_pulse(struct intel_engine_cs *engine)
{
	struct intel_context *ce = engine->kernel_context;
	int err;

	if (!intel_engine_has_preemption(engine))
		return -ENODEV;

	if (!intel_engine_pm_get_if_awake(engine))
		return 0;

	err = -EINTR;
	if (!mutex_lock_interruptible(&ce->timeline->mutex)) {
		err = __intel_engine_pulse(engine);
		mutex_unlock(&ce->timeline->mutex);
	}

	intel_engine_flush_submission(engine);
	intel_engine_pm_put(engine);
	return err;
}

int intel_engine_flush_barriers(struct intel_engine_cs *engine)
{
	struct intel_context *ce = engine->kernel_context;
	int prio = I915_PRIORITY_MIN;
	struct i915_request *rq;
	int err;

	if (list_empty(&engine->barrier_tasks))
		return 0;

	if (!intel_engine_pm_get_if_awake(engine))
		return 0;

	if (mutex_lock_interruptible(&ce->timeline->mutex)) {
		err = -EINTR;
		goto out_rpm;
	}

	rq = heartbeat_create(ce, GFP_KERNEL);
	if (IS_ERR(rq)) {
		err = PTR_ERR(rq);
		goto out_unlock;
	}

	heartbeat_commit(rq, prio);

	err = 0;
out_unlock:
	mutex_unlock(&ce->timeline->mutex);
out_rpm:
	intel_engine_pm_put(engine);
	return err;
}

#if IS_ENABLED(CONFIG_DRM_I915_SELFTEST)
#include "selftest_engine_heartbeat.c"
#endif
