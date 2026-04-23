/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM superfork

#if !defined(_TRACE_SUPERFORK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SUPERFORK_H

#include <linux/tracepoint.h>

TRACE_EVENT(superfork_phase,

	TP_PROTO(const char *phase, int ret, pid_t pid, unsigned int count),

	TP_ARGS(phase, ret, pid, count),

	TP_STRUCT__entry(
		__field(	int,		ret	)
		__field(	pid_t,		pid	)
		__field(	unsigned int,	count	)
		__string(	phase,		phase	)
	),

	TP_fast_assign(
		__entry->ret = ret;
		__entry->pid = pid;
		__entry->count = count;
		__assign_str(phase);
	),

	TP_printk("phase=%s ret=%d pid=%d count=%u",
		  __get_str(phase), __entry->ret, __entry->pid,
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
