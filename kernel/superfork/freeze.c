// SPDX-License-Identifier: GPL-2.0
/*
 * superfork/freeze.c — cgroup freeze/thaw, source-task cgroup migration,
 * per-task collection, vCPU pt_regs snapshot, and freeze-wait logic.
 */

#include "../cgroup/cgroup-internal.h"
#include <linux/cgroup.h>
#include <linux/cgroup-defs.h>
#include <linux/freezer.h>
#include <linux/kvm_host.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/superfork.h>
#include <asm/ptrace.h>
#include "internal.h"

static bool cgroup_reached_desired_state(struct cgroup *cgrp, bool freeze)
{
	if (freeze)
		return test_bit(CGRP_FROZEN, &cgrp->flags);
	else
		return !test_bit(CGRP_FROZEN, &cgrp->flags);
}

static int cgroup_do_freeze_thaw(struct cgroup *cgrp, bool freeze)
{
	int ret = 0;

	mutex_lock(&cgroup_mutex);

	if (cgrp == &cgrp->root->cgrp) {
		ret = -EINVAL;
		goto out;
	}

	if (cgroup_reached_desired_state(cgrp, freeze))
		goto out;

	cgroup_freeze(cgrp, freeze);

	mutex_unlock(&cgroup_mutex);

	while (!cgroup_reached_desired_state(cgrp, freeze))
		schedule_timeout_uninterruptible(msecs_to_jiffies(1));

	return 0;

out:
	mutex_unlock(&cgroup_mutex);
	return ret;
}

int cgroup_freeze_sync(struct cgroup *cgrp)
{
	return cgroup_do_freeze_thaw(cgrp, true);
}

int cgroup_thaw_sync(struct cgroup *cgrp)
{
	return cgroup_do_freeze_thaw(cgrp, false);
}

#define SUPERFORK_THAW_RETRIES 3

int superfork_thaw_source_cgroup_sync(struct cgroup *src_cgrp,
				      const char *stage)
{
	int attempt;
	int ret = 0;

	if (!src_cgrp)
		return 0;

	for (attempt = 1; attempt <= SUPERFORK_THAW_RETRIES; attempt++) {
		ret = cgroup_thaw_sync(src_cgrp);
		if (!ret)
			return 0;

		pr_warn("superfork: cgroup_thaw_sync failed at stage=%s attempt=%d/%d ret=%d\n",
			stage ? stage : "unknown", attempt,
			SUPERFORK_THAW_RETRIES, ret);
		schedule_timeout_uninterruptible(msecs_to_jiffies(1));
	}

	pr_err("superfork: unable to thaw source cgroup at stage=%s: %d\n",
	       stage ? stage : "unknown", ret);
	return ret;
}

int superfork_restore_source_task_cgroups(struct sf_src_cgroup_move *moves,
					  size_t count)
{
	int ret = 0;
	size_t i;

	if (!moves)
		return 0;

	for (i = 0; i < count; i++) {
		int attach_ret;

		if (!moves[i].moved || !moves[i].leader || !moves[i].orig_cgrp)
			continue;

		attach_ret = cgroup_attach_task(moves[i].orig_cgrp,
						moves[i].leader, true);
		if (attach_ret < 0) {
			pr_err("superfork: failed to restore source tgid=%d to original cgroup: %d\n",
			       moves[i].tgid, attach_ret);
			if (!ret)
				ret = attach_ret;
			continue;
		}

		moves[i].moved = false;
	}

	return ret;
}

void superfork_put_source_task_cgroup_moves(struct sf_src_cgroup_move *moves,
					    size_t count)
{
	size_t i;

	if (!moves)
		return;

	for (i = 0; i < count; i++) {
		if (moves[i].orig_cgrp)
			cgroup_put(moves[i].orig_cgrp);
		if (moves[i].leader)
			put_task_struct(moves[i].leader);
	}
}

int superfork_prepare_source_task_cgroups(struct cgroup *src_cgrp,
					  const pid_t *kpids,
					  size_t count,
					  struct sf_src_cgroup_move *moves)
{
	size_t i;

	if (!src_cgrp || !kpids || !moves)
		return -EINVAL;

	for (i = 0; i < count; i++) {
		struct task_struct *task;
		struct task_struct *leader;
		struct cgroup *orig_cgrp;
		int ret;

		moves[i].tgid = kpids[i];

		rcu_read_lock();
		task = find_task_by_vpid(kpids[i]);
		if (!task) {
			rcu_read_unlock();
			pr_err("superfork: source tgid %d disappeared before cgroup prep\n",
			       kpids[i]);
			return -ESRCH;
		}

		leader = task->group_leader;
		get_task_struct(leader);
		orig_cgrp = task_dfl_cgroup(leader);
		cgroup_get(orig_cgrp);
		rcu_read_unlock();

		moves[i].leader = leader;
		moves[i].orig_cgrp = orig_cgrp;

		if (orig_cgrp == src_cgrp)
			continue;

		ret = cgroup_attach_task(src_cgrp, leader, true);
		if (ret < 0) {
			pr_err("superfork: failed to move source tgid=%d into src cgroup: %d\n",
			       kpids[i], ret);
			return ret;
		}

		moves[i].moved = true;
	}

	return 0;
}

/*
 * vCPU snapshot: called from KVM's kvm_vcpu_block() right before it bails
 * out due to a pending signal. Captures the userspace pt_regs so the clone
 * can re-iret to the ioctl(KVM_RUN) syscall instruction (instead of
 * returning at futex_wait inside pthread_cond_wait, where QEMU masks
 * SIGUSR1 and the guest never gets kicked).
 *
 * We rewrite two fields in the saved frame:
 *   - ip -= 2  : rewind past the 'syscall' instruction so iret re-enters it
 *   - ax = orig_ax : entry_SYSCALL_64 clobbered ax to -ENOSYS, restore the
 *                    syscall number so user rax is correct at re-entry
 *
 * Runs in the vCPU thread's own context; sf_vcpu_snap was pre-allocated by
 * the superfork caller before freezing. No locking needed — only this task
 * reads and writes its own snap, and it only fires once per snap lifecycle
 * (valid guards re-entry).
 */
void superfork_kvm_vcpu_snapshot_entry(void)
{
	struct sf_vcpu_snap *snap = READ_ONCE(current->sf_vcpu_snap);
	struct pt_regs      *regs;

	if (!snap || READ_ONCE(snap->valid))
		return;

	regs = task_pt_regs(current);
	if (!regs || !user_mode(regs))
		return;

	snap->saved_regs      = *regs;
	snap->saved_regs.ip  -= 2;
	snap->saved_regs.ax   = snap->saved_regs.orig_ax;

	/* Publish valid=true only after saved_regs is fully written. */
	smp_wmb();
	WRITE_ONCE(snap->valid, true);
}
EXPORT_SYMBOL_GPL(superfork_kvm_vcpu_snapshot_entry);

/*
 * Detach and free sf_vcpu_snap from every thread in the target tgids.
 * Idempotent: safe to call on error paths even if alloc partially ran.
 */
void superfork_free_vcpu_snaps(pid_t *kpids, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		struct task_struct *leader, *thread;

		rcu_read_lock();
		leader = find_task_by_vpid(kpids[i]);
		if (!leader || leader->tgid != kpids[i]) {
			rcu_read_unlock();
			continue;
		}

		for_each_thread(leader, thread) {
			struct sf_vcpu_snap *snap = xchg(&thread->sf_vcpu_snap, NULL);
			kfree(snap);
		}
		rcu_read_unlock();
	}
}

/*
 * Attach a fresh sf_vcpu_snap to every thread in every target tgid. Called
 * before cgroup_freeze_sync so the snap is in place when KVM's block loop
 * notices the freezer signal. Non-vCPU threads never trigger the snapshot
 * hook and their snap stays valid=false — harmless.
 */
int superfork_alloc_vcpu_snaps(pid_t *kpids, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		struct task_struct *leader, *thread;

		rcu_read_lock();
		leader = find_task_by_vpid(kpids[i]);
		if (!leader || leader->tgid != kpids[i]) {
			rcu_read_unlock();
			pr_warn("superfork: alloc_vcpu_snaps: tgid %d not found\n",
				kpids[i]);
			goto err;
		}

		for_each_thread(leader, thread) {
			struct sf_vcpu_snap *snap;

			if (READ_ONCE(thread->sf_vcpu_snap))
				continue;

			/* GFP_ATOMIC under rcu_read_lock; snap is small (~pt_regs). */
			snap = kzalloc(sizeof(*snap), GFP_ATOMIC);
			if (!snap) {
				rcu_read_unlock();
				pr_err("superfork: alloc_vcpu_snaps: kzalloc OOM\n");
				goto err;
			}

			/*
			 * Publish the pointer. The task isn't frozen yet so it may
			 * observe this on its next KVM block-check; that's fine.
			 */
			WRITE_ONCE(thread->sf_vcpu_snap, snap);
		}
		rcu_read_unlock();
	}

	return 0;

err:
	superfork_free_vcpu_snaps(kpids, count);
	return -ENOMEM;
}

static inline int verify_thread_frozen(struct task_struct *thread)
{
	if (!cgroup_task_frozen(thread) &&
	    !task_is_stopped(thread) &&
	    !task_is_traced(thread)) {
		pr_warn("superfork: task %d is not frozen/stopped (state=0x%x, frozen=%d)\n",
			thread->pid, READ_ONCE(thread->__state),
			thread->frozen);
		return -EBUSY;
	}
	return 0;
}

static inline int thread_user_mode(struct task_struct *thread)
{
	struct pt_regs *regs = task_pt_regs(thread);

	if (!user_mode(regs))
		return -EBUSY;
	return 0;
}

#define SUPERFORK_FREEZE_WAIT_RETRIES 2000
#define SUPERFORK_FREEZE_WAIT_MS      5

/*
 * A thread is ready to clone when it is both frozen/stopped AND its saved
 * register frame points into userspace.  The userspace check is load-bearing:
 * if the saved RIP is inside kernel code, superfork_copy_thread would set up
 * a clone that resumes mid-kernel-function with a stale stack.
 *
 * vhost_tasks (PF_USER_WORKER) satisfy user_mode() after the cgroup freezer
 * kicks them out of kvm_vcpu_block.  Plain PF_KTHREAD tasks are handled
 * separately in superfork_copy_kthread and bypass this check.
 */
static bool thread_ready_for_clone(struct task_struct *thread)
{
	if (!cgroup_task_frozen(thread) &&
	    !task_is_stopped(thread) &&
	    !task_is_traced(thread))
		return false;

	return user_mode(task_pt_regs(thread));
}

static void log_source_freeze_wait_timeout(pid_t *kpids, size_t count)
{
	const int max_logs = 16;
	int logged = 0;
	size_t i;

	rcu_read_lock();
	for (i = 0; i < count && logged < max_logs; i++) {
		struct task_struct *task;
		struct task_struct *leader;
		struct task_struct *thread;

		task = find_task_by_vpid(kpids[i]);
		if (!task) {
			pr_warn("superfork: freeze-wait source tgid %d disappeared\n",
				kpids[i]);
			logged++;
			continue;
		}

		leader = task->group_leader;
		if (!leader || leader->tgid != kpids[i]) {
			pr_warn("superfork: freeze-wait tgid mismatch for source %d (leader=%d)\n",
				kpids[i], leader ? leader->tgid : -1);
			logged++;
			continue;
		}

		for_each_thread(leader, thread) {
			bool frozenish;
			bool user;

			frozenish = cgroup_task_frozen(thread) ||
				    task_is_stopped(thread) ||
				    task_is_traced(thread);
			user = user_mode(task_pt_regs(thread));

			if (frozenish && user)
				continue;

			pr_warn("superfork: freeze-wait not-ready pid=%d tgid=%d state=0x%x frozen=%d stopped=%d traced=%d user_mode=%d\n",
				thread->pid, thread->tgid,
				READ_ONCE(thread->__state), thread->frozen,
				task_is_stopped(thread), task_is_traced(thread), user);
			logged++;
			if (logged >= max_logs)
				break;
		}
	}
	rcu_read_unlock();
}

/*
 * Wait for source thread-groups to reach clone-safe frozen state.
 * This avoids transient races where the cgroup freeze request is set,
 * but target threads have not yet trapped into frozen/stopped state.
 */
int wait_source_tasks_frozen(pid_t *kpids, size_t count)
{
	unsigned int attempt;

	for (attempt = 0; attempt < SUPERFORK_FREEZE_WAIT_RETRIES; attempt++) {
		bool all_ready = true;
		size_t i;

		rcu_read_lock();
		for (i = 0; i < count; i++) {
			struct task_struct *task;
			struct task_struct *leader;
			struct task_struct *thread;

			task = find_task_by_vpid(kpids[i]);
			if (!task) {
				all_ready = false;
				break;
			}

			leader = task->group_leader;
			if (!leader || leader->tgid != kpids[i]) {
				all_ready = false;
				break;
			}

			for_each_thread(leader, thread) {
				if (!thread_ready_for_clone(thread)) {
					all_ready = false;
					break;
				}
			}

			if (!all_ready)
				break;
		}
		rcu_read_unlock();

		if (all_ready)
			return 0;

		schedule_timeout_uninterruptible(
			msecs_to_jiffies(SUPERFORK_FREEZE_WAIT_MS));
	}

	log_source_freeze_wait_timeout(kpids, count);

	return -EBUSY;
}

void release_collected_tasks(struct container_clone_ctx *ctx)
{
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		if (task->old_task) {
			put_task_struct(task->old_task);
			task->old_task = NULL;
		}
	}
	ctx->task_count = 0;
}

int collect_frozen_tasks(struct container_clone_ctx *ctx,
			 pid_t *kpids, size_t count)
{
	struct task_struct *process, *thread;
	size_t i;
	int ret = 0;

	ctx->task_count = 0;
	ctx->tgid_count = 0;
	rcu_read_lock();

	for_each_process(process) {
		for (i = 0; i < count; i++) {
			if (process->tgid == kpids[i]) {
				struct tgid_clone_entry *tgid_entry;
				bool first_thread = true;

				tgid_entry = find_or_create_tgid_entry(ctx, process->tgid);

				if (!tgid_entry)
					goto err_nomem;

				for_each_thread(process, thread) {

					if (ctx->task_count >= MAX_CLONE_TASKS)
						goto err_nomem;

					if (verify_thread_frozen(thread) < 0 || thread_user_mode(thread) < 0) {
						ret = -EBUSY;
						goto err_release;
					}

					ctx->tasks[ctx->task_count].old_task = thread;
					ctx->tasks[ctx->task_count].old_tgid = process->tgid;
					ctx->tasks[ctx->task_count].is_leader = first_thread;
					ctx->tasks[ctx->task_count].new_task = NULL;
					ctx->task_count++;

					get_task_struct(thread);
					first_thread = false;
				}
				break;
			}
		}
	}

	rcu_read_unlock();
	return 0;

err_nomem:
	ret = -ENOMEM;
err_release:
	rcu_read_unlock();
	release_collected_tasks(ctx);
	return ret;
}
