/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM superfork

#if !defined(_TRACE_SUPERFORK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SUPERFORK_H

#include <linux/tracepoint.h>

#ifndef _TRACE_SUPERFORK_PHASE_IDS_H
#define _TRACE_SUPERFORK_PHASE_IDS_H
enum superfork_phase_id {
	SUPERFORK_PHASE_PREPARE_SOURCE_CGROUPS = 1,
	SUPERFORK_PHASE_ALLOC_VCPU_SNAPS,
	SUPERFORK_PHASE_FREEZE_SOURCE_CGROUP,
	SUPERFORK_PHASE_WAIT_SOURCE_FROZEN,
	SUPERFORK_PHASE_BTRFS_SNAPSHOT,
	SUPERFORK_PHASE_COLLECT_FROZEN_TASKS,
	SUPERFORK_PHASE_SETUP_NAMESPACES,
	SUPERFORK_PHASE_CLONE_LEADERS,
	SUPERFORK_PHASE_CLONE_THREADS,
	SUPERFORK_PHASE_VERIFY_FDS,
	SUPERFORK_PHASE_ATTACH_TASKS,
	SUPERFORK_PHASE_CLONE_PROCESSES_FAILED,
	SUPERFORK_PHASE_CLONE_PROCESSES,
	SUPERFORK_PHASE_CONTAINER_CREATED,
	SUPERFORK_PHASE_DESTROY_CONTAINER,
	SUPERFORK_PHASE_CLEANUP_EARLY_FAILURE,
	SUPERFORK_PHASE_CLONE_CONTAINER,
	SUPERFORK_PHASE_THAW_SOURCE_CGROUP,
	SUPERFORK_PHASE_RESTORE_SOURCE_CGROUPS,
	SUPERFORK_PHASE_SEED_CGROUP_MEMBERSHIP,
	SUPERFORK_PHASE_POST_FORK,
	SUPERFORK_PHASE_COPY_NEW_INIT_PID,
	SUPERFORK_PHASE_WAKE_TASKS,
	SUPERFORK_PHASE_THAW_SOURCE_CGROUP_CLEANUP,
};
#endif

TRACE_EVENT(superfork_phase,

	TP_PROTO(int phase, int ret, pid_t pid, unsigned int count),

	TP_ARGS(phase, ret, pid, count),

	TP_STRUCT__entry(
		__field(	int,		phase	)
		__field(	int,		ret	)
		__field(	pid_t,		pid	)
		__field(	unsigned int,	count	)
	),

	TP_fast_assign(
		__entry->phase = phase;
		__entry->ret = ret;
		__entry->pid = pid;
		__entry->count = count;
	),

	TP_printk("phase=%s ret=%d pid=%d count=%u",
		  __print_symbolic(__entry->phase,
				   { SUPERFORK_PHASE_PREPARE_SOURCE_CGROUPS, "prepare_source_cgroups" },
				   { SUPERFORK_PHASE_ALLOC_VCPU_SNAPS, "alloc_vcpu_snaps" },
				   { SUPERFORK_PHASE_FREEZE_SOURCE_CGROUP, "freeze_source_cgroup" },
				   { SUPERFORK_PHASE_WAIT_SOURCE_FROZEN, "wait_source_frozen" },
				   { SUPERFORK_PHASE_BTRFS_SNAPSHOT, "btrfs_snapshot" },
				   { SUPERFORK_PHASE_COLLECT_FROZEN_TASKS, "collect_frozen_tasks" },
				   { SUPERFORK_PHASE_SETUP_NAMESPACES, "setup_namespaces" },
				   { SUPERFORK_PHASE_CLONE_LEADERS, "clone_leaders" },
				   { SUPERFORK_PHASE_CLONE_THREADS, "clone_threads" },
				   { SUPERFORK_PHASE_VERIFY_FDS, "verify_fds" },
				   { SUPERFORK_PHASE_ATTACH_TASKS, "attach_tasks" },
				   { SUPERFORK_PHASE_CLONE_PROCESSES_FAILED, "clone_processes_failed" },
				   { SUPERFORK_PHASE_CLONE_PROCESSES, "clone_processes" },
				   { SUPERFORK_PHASE_CONTAINER_CREATED, "container_created" },
				   { SUPERFORK_PHASE_DESTROY_CONTAINER, "destroy_container" },
				   { SUPERFORK_PHASE_CLEANUP_EARLY_FAILURE, "cleanup_early_failure" },
				   { SUPERFORK_PHASE_CLONE_CONTAINER, "clone_container" },
				   { SUPERFORK_PHASE_THAW_SOURCE_CGROUP, "thaw_source_cgroup" },
				   { SUPERFORK_PHASE_RESTORE_SOURCE_CGROUPS, "restore_source_cgroups" },
				   { SUPERFORK_PHASE_SEED_CGROUP_MEMBERSHIP, "seed_cgroup_membership" },
				   { SUPERFORK_PHASE_POST_FORK, "post_fork" },
				   { SUPERFORK_PHASE_COPY_NEW_INIT_PID, "copy_new_init_pid" },
				   { SUPERFORK_PHASE_WAKE_TASKS, "wake_tasks" },
				   { SUPERFORK_PHASE_THAW_SOURCE_CGROUP_CLEANUP, "thaw_source_cgroup_cleanup" }),
		  __entry->ret, __entry->pid,
		  __entry->count)
);

TRACE_EVENT(superfork_task_clone,

	TP_PROTO(pid_t old_pid, pid_t old_tgid, pid_t new_pid, bool leader),

	TP_ARGS(old_pid, old_tgid, new_pid, leader),

	TP_STRUCT__entry(
		__field(	pid_t,		old_pid		)
		__field(	pid_t,		old_tgid	)
		__field(	pid_t,		new_pid		)
		__field(	bool,		leader		)
	),

	TP_fast_assign(
		__entry->old_pid = old_pid;
		__entry->old_tgid = old_tgid;
		__entry->new_pid = new_pid;
		__entry->leader = leader;
	),

	TP_printk("old_pid=%d old_tgid=%d new_pid=%d leader=%d",
		  __entry->old_pid, __entry->old_tgid, __entry->new_pid,
		  __entry->leader)
);

#endif /* _TRACE_SUPERFORK_H */

#include <trace/define_trace.h>
