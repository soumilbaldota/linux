// SPDX-License-Identifier: GPL-2.0
/*
 * superfork/attach.c — link cloned tasks into the system.
 *
 * Covers: attach_task (tasklist + pid hashes), attach_tasks (two-pass
 * leader-then-thread), post_fork (sched + perf hooks), cgroup seeding,
 * and wake_tasks.
 */

#include <linux/cgroup.h>
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

/*
 * Find the new task corresponding to an old task (leaders only for parent
 * mapping).
 */
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

	/* For threads, parent is handled differently - they attach to their leader */
	if (old_task->group_leader != old_task)
		old_parent = old_task->group_leader->real_parent;

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

/*
 * superfork_attach_task - Attach a cloned task to the system.
 *
 * Makes the cloned task visible to the rest of the system by attaching it
 * to the tasklist and pid hashes. Mirrors the attachment portion of
 * copy_process().
 */
static void superfork_attach_task(struct task_struct *p,
				  struct task_struct *src_task,
				  struct task_struct *new_parent,
				  bool is_leader)
{
	struct pid *pid = p->thread_pid;

	if (!pid || !p->signal || !p->sighand)
		return;

	superfork_init_task_pid_links(p);
	superfork_init_task_pid(p, PIDTYPE_PID, pid);

	if (is_leader) {
		superfork_init_task_pid(p, PIDTYPE_TGID, pid);
		superfork_init_task_pid(p, PIDTYPE_PGID, pid);
		superfork_init_task_pid(p, PIDTYPE_SID, pid);
	}

	write_lock_irq(&tasklist_lock);

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

	spin_lock(&p->sighand->siglock);

	if (!is_leader && p->signal) {
		/* Non-leader: add to thread list */
		refcount_inc(&p->signal->sigcnt);
		INIT_LIST_HEAD(&p->thread_node);
		list_add_tail_rcu(&p->thread_node, &p->signal->thread_head);
		p->signal->nr_threads++;
		p->signal->quick_threads++;
		atomic_inc(&p->signal->live);
	}

	if (is_leader && p->signal) {
		/* Leader: inherit tty and clear subreaper flags */
		tty_kref_put(p->signal->tty);
		p->signal->tty = NULL;
		p->signal->has_child_subreaper = false;
		p->signal->is_child_subreaper = false;
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
void superfork_attach_tasks(struct container_clone_ctx *ctx)
{
	/* First pass: attach all leaders (establishes parent-child relationships) */
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *old_task = task->old_task;
		struct task_struct *new_task = task->new_task;
		struct task_struct *new_parent;

		if (!new_task || !task->is_leader)
			continue;

		new_parent = superfork_map_parent(ctx, old_task);
		superfork_attach_task(new_task, old_task, new_parent, true);
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
		superfork_attach_task(new_task, old_task, new_parent, false);
	}
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

			pr_info("superfork: waking thread pid=%d pc=0x%llx sp=0x%llx "
				"pstate=0x%llx fp_type=%d sve=%d "
				"pstate_ok=%d sp_ok=%d pc_ok=%d\n",
				p->pid, regs->pc, regs->sp, pstate,
				p->thread.fp_type,
				test_tsk_thread_flag(p, TIF_SVE) ? 1 : 0,
				pstate_ok, sp_ok, pc_ok);

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

			pr_info("superfork: waking leader pid=%d pc=0x%llx sp=0x%llx "
				"pstate=0x%llx fp_type=%d sve=%d "
				"pstate_ok=%d sp_ok=%d pc_ok=%d\n",
				p->pid, regs->pc, regs->sp, pstate,
				p->thread.fp_type,
				test_tsk_thread_flag(p, TIF_SVE) ? 1 : 0,
				pstate_ok, sp_ok, pc_ok);

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
