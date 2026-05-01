// SPDX-License-Identifier: GPL-2.0
/*
 * superfork/debug.c - generic debug gating for superfork-created tasks.
 *
 * Keep task-specific instrumentation in generic kernel files keyed on clone
 * membership, not workload names.
 */

#include <linux/atomic.h>
#include <linux/sched.h>
#include <linux/superfork.h>
#include <linux/xarray.h>

static DEFINE_XARRAY(superfork_debug_tasks);
static atomic_t superfork_debug_task_count = ATOMIC_INIT(0);

bool superfork_debug_enabled(struct task_struct *task)
{
	bool enabled = false;

	if (!task || !atomic_read(&superfork_debug_task_count))
		return false;

	rcu_read_lock();
	enabled = xa_load(&superfork_debug_tasks, task_pid_nr(task)) == task;
	rcu_read_unlock();

	return enabled;
}

int superfork_debug_track_task(struct task_struct *task)
{
	int ret;

	if (!task)
		return -EINVAL;
	if (superfork_debug_enabled(task))
		return 0;

	get_task_struct(task);
	ret = xa_insert(&superfork_debug_tasks, task_pid_nr(task),
			task, GFP_KERNEL);
	if (ret) {
		put_task_struct(task);
		if (ret == -EBUSY)
			return 0;
		return ret;
	}

	atomic_inc(&superfork_debug_task_count);
	return 0;
}

void superfork_debug_untrack_task(struct task_struct *task)
{
	void *old;

	if (!task || !atomic_read(&superfork_debug_task_count))
		return;

	old = xa_erase(&superfork_debug_tasks, task_pid_nr(task));
	if (!old)
		return;

	atomic_dec(&superfork_debug_task_count);
	put_task_struct(old);
}
