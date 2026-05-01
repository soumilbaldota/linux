// SPDX-License-Identifier: GPL-2.0
/*
 * superfork/attach.c — link cloned tasks into the system.
 *
 * Covers: attach_task (tasklist + pid hashes), attach_tasks (two-pass
 * leader-then-thread), post_fork (sched + perf hooks), cgroup seeding,
 * and wake_tasks.
 */

#include <linux/cgroup.h>
#include <linux/sched/task_stack.h>
#include <linux/perf_event.h>
#include <linux/pid.h>
#include <linux/pid_namespace.h>
#include <linux/preempt.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>
#include <linux/signal.h>
#include <linux/superfork.h>
#include <linux/tty.h>
#include <uapi/linux/wait.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include "internal.h"

static inline void superfork_init_task_pid_links(struct task_struct *task)
{
	enum pid_type type;

	for (type = PIDTYPE_PID; type < PIDTYPE_MAX; ++type)
		INIT_HLIST_NODE(&task->pid_links[type]);
}

static inline void superfork_init_task_pid(struct task_struct *task,
					   enum pid_type type,
					   struct pid *pid)
{
	if (type == PIDTYPE_PID)
		task->thread_pid = pid;
	else
		task->signal->pids[type] = pid;
}

static struct task_struct *find_new_task_by_old(struct container_clone_ctx *ctx,
						struct task_struct *old_task);
static bool is_task_in_clone_set(struct container_clone_ctx *ctx,
				 struct task_struct *task);

static void superfork_remap_wait_syscall_args(struct container_clone_ctx *ctx,
					      struct task_clone_entry *task)
{
	struct task_struct *p;
	struct pt_regs *regs;
	struct pid_namespace *old_ns;
	struct pid_namespace *ns;
	unsigned long args[6];
	pid_t old_pid, new_pid;
	int nr;

	if (!ctx || !task || !task->new_task || !task->old_task)
		return;

	p = task->new_task;
	if (task->old_task->flags & (PF_KTHREAD | PF_USER_WORKER))
		return;

	regs = task_pt_regs(p);
	nr = syscall_get_nr(p, regs);
	if (nr == -1)
		return;

	ns = task_active_pid_ns(p);
	old_ns = task_active_pid_ns(task->old_task);
	if (!ns || !old_ns)
		return;

	syscall_get_arguments(p, regs, args);

	switch (nr) {
	case __NR_wait4:
		old_pid = (pid_t)args[0];
		if (old_pid <= 0)
			return;

		new_pid = superfork_map_old_pid_to_new_nr(ctx, old_pid, old_ns,
							 ns);
		if (!new_pid)
			return;

		args[0] = (unsigned long)new_pid;
		syscall_set_arguments(p, regs, args);
		pr_info("superfork-wait: remap wait4 pid current=%d/%s old=%d new=%d\n",
			p->pid, p->comm, old_pid, new_pid);
		return;

	case __NR_waitid:
		if ((int)args[0] != P_PID)
			return;

		old_pid = (pid_t)args[1];
		if (old_pid <= 0)
			return;

		new_pid = superfork_map_old_pid_to_new_nr(ctx, old_pid, old_ns,
							 ns);
		if (!new_pid)
			return;

		args[1] = (unsigned long)new_pid;
		syscall_set_arguments(p, regs, args);
		pr_info("superfork-wait: remap waitid pid current=%d/%s old=%d new=%d\n",
			p->pid, p->comm, old_pid, new_pid);
		return;
	}
}

/*
 * Rebuild process-group/session membership inside the cloned tree.
 *
 * If the source pgid/sid leader is also being cloned, point the new task at
 * the corresponding cloned leader. Otherwise fall back to @fallback so the new
 * pid namespace remains self-contained instead of referencing an external
 * process-group/session leader.
 */
static struct pid *superfork_map_signal_pid_locked(
				struct container_clone_ctx *ctx,
				struct task_struct *src_task,
				enum pid_type type,
				struct pid *fallback)
{
	struct pid *src_pid;
	struct task_struct *src_leader;
	struct task_struct *new_leader;

	if (!src_task || !src_task->signal)
		return fallback;

	switch (type) {
	case PIDTYPE_PGID:
		src_pid = task_pgrp(src_task);
		break;
	case PIDTYPE_SID:
		src_pid = task_session(src_task);
		break;
	default:
		return fallback;
	}

	if (!src_pid)
		return fallback;

	src_leader = pid_task(src_pid, PIDTYPE_PID);
	if (!src_leader || !is_task_in_clone_set(ctx, src_leader))
		return fallback;

	new_leader = find_new_task_by_old(ctx, src_leader);
	if (!new_leader || !new_leader->thread_pid)
		return fallback;

	return new_leader->thread_pid;
}

/* Find the new task corresponding to an old task. */
static struct task_struct *find_new_task_by_old(struct container_clone_ctx *ctx,
						struct task_struct *old_task)
{
	if (!old_task)
		return NULL;

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		if (task->old_task == old_task)
			return task->new_task;
	}

	return NULL;
}

/* Check if a task_struct is one of the tasks being cloned. */
static bool is_task_in_clone_set(struct container_clone_ctx *ctx,
				 struct task_struct *task)
{
	if (!task)
		return false;

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *ctx_task = get_ctx_task(ctx, i);
		if (ctx_task->old_task == task)
			return true;
	}

	return false;
}

/*
 * Map old parent to new parent, recreating the process tree structure.
 *
 * The cloned container should be an independent process tree:
 * - If old parent was INSIDE the container → use the cloned parent
 * - If old parent was OUTSIDE the container → use 'current' (superfork caller)
 *
 * This ensures the new container is a sibling tree, not a child of the
 * original.
 */
static struct task_struct *superfork_map_parent(struct container_clone_ctx *ctx,
						struct task_struct *old_task)
{
	struct task_struct *old_parent;
	struct task_struct *new_parent;

	if (!old_task)
		return current;

	/* Get the old task's real parent */
	old_parent = old_task->real_parent;

	/*
	 * Keep all threads in the same cloned thread group attached to the
	 * same source parent selection by starting from the source leader's
	 * real parent.
	 */
	if (old_task->group_leader != old_task)
		old_parent = old_task->group_leader->real_parent;

	/*
	 * A source child can be owned by a transient non-leader parent thread
	 * (common with multithreaded runtimes such as Go).  The cloned child
	 * only needs a stable parent process inside the new tree, not the exact
	 * source thread that happened to call fork().  Anchor such children to
	 * the cloned parent leader to avoid reparent/wait churn when that source
	 * worker thread exits.
	 */
	if (old_parent && old_parent->group_leader != old_parent)
		old_parent = old_parent->group_leader;

	/*
	 * Check if the old parent is one of the tasks being cloned.
	 * If yes, find the corresponding new task.
	 * If no, the parent was external to the container - use 'current'.
	 */
	if (!is_task_in_clone_set(ctx, old_parent))
		return current;

	/* Parent is in the clone set - find the new parent */
	new_parent = find_new_task_by_old(ctx, old_parent);
	if (new_parent && new_parent->signal)
		return new_parent;

	/* Fallback - shouldn't happen if parent is in clone set */
	return current;
}

static int superfork_validate_parent_links(struct container_clone_ctx *ctx)
{
	int ret = 0;

	read_lock(&tasklist_lock);
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *leader = task->new_task;
		struct task_struct *thread;
		unsigned int thread_count = 0;

		if (!leader || !task->is_leader || !leader->signal)
			continue;

		for_each_thread(leader, thread) {
			thread_count++;

			if (thread->group_leader != leader || thread->signal != leader->signal) {
				pr_err("superfork: thread-group mismatch leader pid=%d thread pid=%d group_leader=%d signal=%px expected_signal=%px\n",
				       leader->pid, thread->pid,
				       thread->group_leader ? thread->group_leader->pid : -1,
				       thread->signal, leader->signal);
				ret = -EINVAL;
				goto out_unlock;
			}

			if (thread->parent == leader->parent &&
			    thread->real_parent == leader->real_parent)
				continue;

			pr_err("superfork: parent mismatch leader pid=%d tgid=%d comm=%s thread pid=%d tgid=%d comm=%s parent=%d real_parent=%d expected_parent=%d expected_real_parent=%d\n",
			       leader->pid, leader->tgid, leader->comm,
			       thread->pid, thread->tgid, thread->comm,
			       thread->parent ? thread->parent->pid : -1,
			       thread->real_parent ? thread->real_parent->pid : -1,
			       leader->parent ? leader->parent->pid : -1,
			       leader->real_parent ? leader->real_parent->pid : -1);
			ret = -EINVAL;
			goto out_unlock;
		}

		if (leader->signal->nr_threads != thread_count) {
			pr_err("superfork: nr_threads mismatch leader pid=%d signal_nr_threads=%d actual_threads=%u\n",
			       leader->pid, leader->signal->nr_threads, thread_count);
			ret = -EINVAL;
			goto out_unlock;
		}

		if (thread_count > 1 && thread_group_empty(leader)) {
			pr_err("superfork: leader pid=%d appears thread-group-empty with %u threads attached\n",
			       leader->pid, thread_count);
			ret = -EINVAL;
			goto out_unlock;
		}
	}

out_unlock:
	read_unlock(&tasklist_lock);
	return ret;
}

/*
 * superfork_attach_task - Attach a cloned task to the system.
 *
 * Makes the cloned task visible to the rest of the system by attaching it
 * to the tasklist and pid hashes. Mirrors the attachment portion of
 * copy_process().
 */
static void superfork_attach_task(struct container_clone_ctx *ctx,
				  struct task_struct *p,
				  struct task_struct *src_task,
				  struct task_struct *new_parent,
				  bool is_leader)
{
	struct pid *pid = p->thread_pid;
	struct pid *pgid = pid;
	struct pid *sid = pid;

	if (!pid || !p->signal || !p->sighand)
		return;

	superfork_init_task_pid_links(p);

	write_lock_irq(&tasklist_lock);

	superfork_init_task_pid(p, PIDTYPE_PID, pid);
	if (is_leader) {
		pgid = superfork_map_signal_pid_locked(ctx, src_task,
						       PIDTYPE_PGID, pid);
		sid = superfork_map_signal_pid_locked(ctx, src_task,
						      PIDTYPE_SID, pid);
		superfork_init_task_pid(p, PIDTYPE_TGID, pid);
		superfork_init_task_pid(p, PIDTYPE_PGID, pgid);
		superfork_init_task_pid(p, PIDTYPE_SID, sid);
	}

	/* Set parent under tasklist_lock */
	p->real_parent = new_parent;
	p->parent = new_parent;
	p->parent_exec_id = new_parent->self_exec_id;

	/* Initialize ptrace state */
	INIT_LIST_HEAD(&p->ptrace_entry);
	INIT_LIST_HEAD(&p->ptraced);
	p->jobctl = 0;
	p->ptrace = 0;
	p->ptracer_cred = NULL;

	if (is_leader)
		p->exit_signal = src_task->group_leader->exit_signal;
	else
		p->exit_signal = -1;

	if (is_leader) {
		struct task_struct *src_parent = src_task->real_parent;

		pr_info("superfork-attach: leader src_pid=%d src_tgid=%d src_comm=%s src_parent=%d src_exit_signal=%d new_pid=%d new_tgid=%d new_parent=%d new_exit_signal=%d\n",
			src_task->pid, src_task->tgid, src_task->comm,
			src_parent ? src_parent->pid : -1,
			src_task->group_leader->exit_signal,
			p->pid, p->tgid,
			new_parent ? new_parent->pid : -1,
			p->exit_signal);
	}

	spin_lock(&p->sighand->siglock);

	if (!is_leader && p->signal) {
		/* Non-leader: add to thread list */
		refcount_inc(&p->signal->sigcnt);
		task_join_group_stop(p);
		INIT_LIST_HEAD(&p->thread_node);
		list_add_tail_rcu(&p->thread_node, &p->signal->thread_head);
		p->signal->nr_threads++;
		p->signal->quick_threads++;
		atomic_inc(&p->signal->live);
	}

	if (is_leader && p->signal) {
		/*
		 * Preserve source process identity where it is intrinsic to the
		 * task itself, but derive reparenting metadata from the clone's
		 * actual parentage just like upstream fork().
		 */
		p->signal->tty = tty_kref_get(src_task->signal->tty);
		p->signal->has_child_subreaper =
			p->real_parent->signal->has_child_subreaper ||
			p->real_parent->signal->is_child_subreaper;
		p->signal->is_child_subreaper =
			src_task->signal->is_child_subreaper;
		p->signal->group_exit_code = 0;
		p->signal->group_stop_count = 0;
		p->signal->flags &= ~(SIGNAL_GROUP_EXIT | SIGNAL_STOP_STOPPED);

		list_add_tail(&p->sibling, &p->real_parent->children);
		list_add_tail_rcu(&p->tasks, &init_task.tasks);

		attach_pid(p, PIDTYPE_TGID);
		attach_pid(p, PIDTYPE_PGID);
		attach_pid(p, PIDTYPE_SID);

		/* Set child_reaper for PID 1 in namespace */
		if (is_child_reaper(p->thread_pid)) {
			struct pid_namespace *pid_ns = ns_of_pid(p->thread_pid);
			pid_ns->child_reaper = p;
			p->signal->flags |= SIGNAL_UNKILLABLE;
		}
	}

	attach_pid(p, PIDTYPE_PID);
	superfork_account_new_task(is_leader);

	spin_unlock(&p->sighand->siglock);
	write_unlock_irq(&tasklist_lock);
}

/*
 * superfork_attach_tasks - Attach all cloned tasks to the system.
 *
 * Rebuilds the process tree structure by:
 * 1. Setting parent pointers based on the original container's hierarchy
 * 2. Adding leaders to parent's children list
 * 3. Adding threads to their leader's thread group
 *
 * The new tree is INDEPENDENT of the original:
 * - Container root processes get 'current' as parent
 * - Child processes get their corresponding new parent
 */
int superfork_attach_tasks(struct container_clone_ctx *ctx)
{
	int ret;

	/* First pass: attach all leaders (establishes parent-child relationships) */
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *old_task = task->old_task;
		struct task_struct *new_task = task->new_task;
		struct task_struct *new_parent;

		if (!new_task || !task->is_leader)
			continue;

		new_parent = superfork_map_parent(ctx, old_task);
		superfork_attach_task(ctx, new_task, old_task, new_parent, true);
		task->attached = true;
	}

	/* Second pass: attach all non-leader threads */
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *old_task = task->old_task;
		struct task_struct *new_task = task->new_task;
		struct task_struct *new_parent;

		if (!new_task || task->is_leader)
			continue;

		new_parent = superfork_map_parent(ctx, old_task);
		superfork_attach_task(ctx, new_task, old_task, new_parent, false);
		task->attached = true;
	}

	ret = superfork_validate_parent_links(ctx);
	if (ret < 0)
		return ret;

	ret = superfork_reopen_procfs_fds(ctx);
	if (ret < 0)
		return ret;

	ret = superfork_reopen_pidfds(ctx);
	if (ret < 0)
		return ret;

	for_each_task_in_ctx(ctx)
		superfork_remap_wait_syscall_args(ctx, get_ctx_task(ctx, i));

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);

		if (!task->new_task)
			continue;

		ret = superfork_debug_track_task(task->new_task);
		if (ret < 0)
			return ret;
	}

	return 0;
}

void superfork_post_fork(struct container_clone_ctx *ctx)
{
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *new_task = task->new_task;
		if (!new_task)
			continue;
		sched_post_fork(new_task);
		perf_event_fork(new_task);
	}

	ctx->post_fork_done = true;
}

int superfork_seed_cgroup_membership(struct container_clone_ctx *ctx)
{
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		int ret;

		if (!task->new_task || !task->old_task)
			continue;

		ret = superfork_cgroup_attach_task(task->new_task, task->old_task);
		if (ret < 0) {
			pr_err("superfork: failed to seed cgroup membership for pid %d from %d: %d\n",
			       task->new_task->pid, task->old_task->pid, ret);
			return ret;
		}
	}

	return 0;
}

void superfork_wake_tasks(struct container_clone_ctx *ctx)
{
	might_sleep();

	/*
	 * Wake non-leaders first (futex/sleep threads) before the leader.
	 * The leader may be in ppoll and waking it first could cause it to
	 * generate signals to threads before they are ready to receive them.
	 *
	 * After wake_up_new_task() the clone is on a runqueue and may begin
	 * executing immediately.  All cgroup and scheduler setup (post_fork,
	 * seed_cgroup_membership) must be complete before this point.
	 */

	/* Pass 1: non-leader threads */
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *p = task->new_task;

		if (!p || task->is_leader)
			continue;

		if (!p->signal || !p->sighand) {
			pr_err("superfork: task %d has NULL signal/sighand\n", p->pid);
			continue;
		}

		if (!p->real_parent) {
			p->real_parent = current;
			p->parent = current;
		}

		/*
		 * Flush any signals that accumulated between copy_process and
		 * now. The clone starts with a clean signal queue — anything
		 * queued here was not meant for this new task.
		 */
		flush_signals(p);

		init_task_preempt_count(p);

#ifdef CONFIG_ARM64
		{
			struct pt_regs *regs = task_pt_regs(p);
			u64 pstate = regs->pstate;
			bool pstate_ok = ((pstate & PSR_MODE_MASK) == PSR_MODE_EL0t);
			bool sp_ok = (regs->sp < TASK_SIZE);
			bool pc_ok = (regs->pc < TASK_SIZE);

			if (!pstate_ok || !sp_ok || !pc_ok) {
				pr_err("superfork: CORRUPT regs on pid=%d — skipping wake\n",
				       p->pid);
				continue;
			}
		}
#endif /* CONFIG_ARM64 */

		wake_up_new_task(p);
	}

	/* Pass 2: leaders */
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *p = task->new_task;

		if (!p || !task->is_leader)
			continue;

		if (!p->signal || !p->sighand) {
			pr_err("superfork: task %d has NULL signal/sighand\n", p->pid);
			continue;
		}

		if (!p->real_parent) {
			p->real_parent = current;
			p->parent = current;
		}

		flush_signals(p);

		init_task_preempt_count(p);

#ifdef CONFIG_ARM64
		{
			struct pt_regs *regs = task_pt_regs(p);
			u64 pstate = regs->pstate;
			bool pstate_ok = ((pstate & PSR_MODE_MASK) == PSR_MODE_EL0t);
			bool sp_ok = (regs->sp < TASK_SIZE);
			bool pc_ok = (regs->pc < TASK_SIZE);

			if (!pstate_ok || !sp_ok || !pc_ok) {
				pr_err("superfork: CORRUPT regs on pid=%d — skipping wake\n",
				       p->pid);
				continue;
			}
		}
#endif /* CONFIG_ARM64 */

		wake_up_new_task(p);
	}
}
