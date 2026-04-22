// SPDX-License-Identifier: GPL-2.0
/*
 * superfork/process.c — per-task cloning: copy_creds, copy_files, copy_fs,
 * copy_sighand, copy_signal, copy_mm, copy_seccomp, and copy_process.
 *
 * Mirrors the copy_* functions in fork.c but copies from a frozen source
 * task rather than from current.
 */

#include <asm/mmu_context.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/thread_info.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/cgroup.h>
#include <linux/cpumask.h>
#include <linux/cred.h>
#include <linux/delayacct.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/namei.h>
#include <linux/ipc_namespace.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/mempolicy.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/nsproxy.h>
#include <linux/perf_event.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/posix-timers.h>
#include <linux/preempt.h>
#include <linux/psi.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/sched/autogroup.h>
#include <linux/sched/cputime.h>
#include <linux/sched/debug.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/sched/task_stack.h>
#include <linux/sched/task.h>
#include <linux/scs.h>
#include <linux/seccomp.h>
#include <linux/security.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/slab.h>
#include <linux/superfork.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/thread_info.h>
#include <linux/tick.h>
#include <linux/tsacct_kern.h>
#include <linux/uaccess.h>
#include <linux/unwind_deferred.h>
#include <linux/user_namespace.h>
#include <linux/vmalloc.h>
#include "../futex/futex.h"
#include "internal.h"

/* ---- credentials ------------------------------------------------------- */

static int superfork_copy_creds(struct task_struct *p,
				struct task_struct *src_task,
				u64 clone_flags)
{
	const struct cred *src_cred;

	rcu_read_lock();
	src_cred = __task_cred(src_task);
	p->real_cred = get_cred(src_cred);
	p->cred = get_cred(src_cred);
	rcu_read_unlock();

	inc_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
	return 0;
}

/* ---- file descriptors -------------------------------------------------- */

/*
 * superfork_copy_files - Copy file descriptors from source task.
 *
 * For threads (CLONE_FILES), we share the CLONED leader's files,
 * NOT the original task's files - this is critical for isolation.
 */
static int superfork_copy_files(struct task_struct *p,
				struct task_struct *src_task,
				struct tgid_clone_entry *tgid_entry,
				const char *src_bundle_path,
				const char *dst_bundle_path,
				u64 clone_flags)
{
	struct files_struct *oldf = src_task->files;

	if (!oldf) {
		p->files = NULL;
		return 0;
	}

	if (clone_flags & CLONE_FILES) {
		/*
		 * Thread: share the CLONED leader's files, not the original's.
		 * Sharing the original would give the thread access to the source
		 * container's fds, breaking isolation.
		 */
		if (!tgid_entry->shared_files)
			return -EINVAL;
		atomic_inc(&tgid_entry->shared_files->count);
		p->files = tgid_entry->shared_files;
		return 0;
	}

	/* Leader: duplicate and store for threads to share */
	p->files = superfork_dup_files_for_container(oldf, src_bundle_path,
						     dst_bundle_path,
						     p->mm, tgid_entry);
	if (IS_ERR(p->files))
		return PTR_ERR(p->files);

	tgid_entry->shared_files = p->files;
	return 0;
}

/* ---- filesystem root --------------------------------------------------- */

static int superfork_copy_fs(struct task_struct *p,
			     struct task_struct *src_task,
			     const char *new_rootfs_path,
			     u64 clone_flags)
{
	struct fs_struct *fs;
	struct path new_root, old_root, old_pwd;
	int ret;

	fs = copy_fs_struct(src_task->fs);
	if (!fs)
		return -ENOMEM;

	if (new_rootfs_path && new_rootfs_path[0] != '\0') {
		ret = kern_path(new_rootfs_path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				&new_root);
		if (ret) {
			pr_err("superfork: failed to resolve new rootfs path %s: %d\n",
			       new_rootfs_path, ret);
			free_fs_struct(fs);
			return ret;
		}

		write_seqlock(&fs->seq);
		/* Save old paths before overwriting */
		old_root = fs->root;
		old_pwd = fs->pwd;

		/* Update to new rootfs */
		fs->root = new_root;
		fs->pwd = new_root;
		path_get(&fs->root);
		path_get(&fs->pwd);
		write_sequnlock(&fs->seq);

		/* Release old paths */
		path_put(&old_root);
		path_put(&old_pwd);
	}

	p->fs = fs;
	return 0;
}

/* ---- signal handling --------------------------------------------------- */

/*
 * superfork_copy_sighand - Copy signal handlers from source task.
 *
 * For threads (CLONE_SIGHAND), we share the CLONED leader's sighand,
 * NOT the original task's sighand.
 */
static int superfork_copy_sighand(struct task_struct *p,
				  struct task_struct *src_task,
				  struct tgid_clone_entry *tgid_entry,
				  u64 clone_flags)
{
	struct sighand_struct *sig;

	if (clone_flags & CLONE_SIGHAND) {
		/* Thread: share the CLONED leader's sighand */
		if (!tgid_entry->shared_sighand)
			return -EINVAL;
		refcount_inc(&tgid_entry->shared_sighand->count);
		p->sighand = tgid_entry->shared_sighand;
		return 0;
	}

	/* Leader: create new sighand and store for threads */
	sig = kmem_cache_alloc(sighand_cachep, GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	refcount_set(&sig->count, 1);
	spin_lock_irq(&src_task->sighand->siglock);
	memcpy(sig->action, src_task->sighand->action, sizeof(sig->action));
	spin_unlock_irq(&src_task->sighand->siglock);

	RCU_INIT_POINTER(p->sighand, sig);
	tgid_entry->shared_sighand = sig;
	return 0;
}

/*
 * superfork_copy_signal - Copy signal struct from source task.
 *
 * For threads (CLONE_THREAD), we share the CLONED leader's signal_struct.
 */
static int superfork_copy_signal(struct task_struct *p,
				 struct task_struct *src_task,
				 struct tgid_clone_entry *tgid_entry,
				 u64 clone_flags)
{
	struct signal_struct *sig;

	if (clone_flags & CLONE_THREAD) {
		/* Thread: share the CLONED leader's signal struct */
		if (!tgid_entry->shared_signal)
			return -EINVAL;
		p->signal = tgid_entry->shared_signal;
		return 0;
	}

	/* Leader: create new signal struct */
	sig = kmem_cache_zalloc(signal_cachep, GFP_KERNEL);
	if (!sig)
		return -ENOMEM;

	p->signal = sig;
	tgid_entry->shared_signal = sig;

	sig->nr_threads = 1;
	sig->quick_threads = 1;
	atomic_set(&sig->live, 1);
	refcount_set(&sig->sigcnt, 1);

	/* Initialize thread list - leader is first and only thread initially */
	INIT_LIST_HEAD(&sig->thread_head);
	INIT_LIST_HEAD(&p->thread_node);
	list_add_tail(&p->thread_node, &sig->thread_head);

	init_waitqueue_head(&sig->wait_chldexit);
	sig->curr_target = p;
	init_sigpending(&sig->shared_pending);
	INIT_HLIST_HEAD(&sig->multiprocess);
	seqlock_init(&sig->stats_lock);
	prev_cputime_init(&sig->prev_cputime);

#ifdef CONFIG_POSIX_TIMERS
	INIT_HLIST_HEAD(&sig->posix_timers);
	INIT_HLIST_HEAD(&sig->ignored_posix_timers);
	hrtimer_setup(&sig->real_timer, it_real_fn, CLOCK_MONOTONIC, HRTIMER_MODE_REL);
#endif

	/* Copy rlimits from source task */
	task_lock(src_task->group_leader);
	memcpy(sig->rlim, src_task->signal->rlim, sizeof(sig->rlim));
	task_unlock(src_task->group_leader);

	/* Initialize autogroup (required to avoid NULL deref in sched_autogroup_exit) */
	sched_autogroup_fork(sig);

#ifdef CONFIG_CGROUPS
	init_rwsem(&sig->cgroup_threadgroup_rwsem);
#endif

	sig->oom_score_adj = src_task->signal->oom_score_adj;
	sig->oom_score_adj_min = src_task->signal->oom_score_adj_min;

	mutex_init(&sig->cred_guard_mutex);
	init_rwsem(&sig->exec_update_lock);

	return 0;
}

/* ---- memory map -------------------------------------------------------- */

#define SUPERFORK_MM_FORK_FILTER_FLAGS (VM_DONTCOPY | VM_WIPEONFORK)

struct sf_mm_flag_override_entry {
	unsigned long start;
	unsigned long end;
	vm_flags_t flags;
};

struct sf_mm_flag_override_ctx {
	struct sf_mm_flag_override_entry *entries;
	unsigned int count;
};

static void superfork_mm_flag_override_ctx_free(struct sf_mm_flag_override_ctx *ctx)
{
	kvfree(ctx->entries);
	ctx->entries = NULL;
	ctx->count = 0;
}

static int superfork_prepare_mm_exact_clone(struct mm_struct *mm,
					    struct sf_mm_flag_override_ctx *ctx)
{
	struct sf_mm_flag_override_entry *entries;
	struct vm_area_struct *vma;
	unsigned int cap, idx = 0;
	VMA_ITERATOR(vmi, mm, 0);

	memset(ctx, 0, sizeof(*ctx));
	cap = mm->map_count;
	if (!cap)
		return 0;

	entries = kvcalloc(cap, sizeof(*entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	mmap_write_lock(mm);
	for_each_vma(vmi, vma) {
		vm_flags_t clear_mask = vma->vm_flags & SUPERFORK_MM_FORK_FILTER_FLAGS;

		if (!clear_mask)
			continue;

		if (WARN_ON_ONCE(idx >= cap)) {
			unsigned int j;

			for (j = 0; j < idx; j++) {
				struct vm_area_struct *rvma;

				rvma = find_vma(mm, entries[j].start);
				if (!rvma || rvma->vm_start != entries[j].start ||
				    rvma->vm_end != entries[j].end)
					continue;
				vma_start_write(rvma);
				vm_flags_set(rvma, entries[j].flags);
			}
			mmap_write_unlock(mm);
			kvfree(entries);
			return -EOVERFLOW;
		}

		entries[idx].start = vma->vm_start;
		entries[idx].end = vma->vm_end;
		entries[idx].flags = clear_mask;

		vma_start_write(vma);
		vm_flags_clear(vma, clear_mask);
		idx++;
	}
	mmap_write_unlock(mm);

	ctx->entries = entries;
	ctx->count = idx;
	return 0;
}

static void superfork_restore_mm_fork_flags(struct mm_struct *mm,
					   const struct sf_mm_flag_override_ctx *ctx,
					   const char *tag)
{
	unsigned int i;

	if (!ctx->entries || !ctx->count)
		return;

	mmap_write_lock(mm);
	for (i = 0; i < ctx->count; i++) {
		const struct sf_mm_flag_override_entry *e = &ctx->entries[i];
		struct vm_area_struct *vma = find_vma(mm, e->start);

		if (!vma || vma->vm_start != e->start || vma->vm_end != e->end) {
			pr_warn("superfork: %s mm VMA changed while restoring fork flags start=0x%lx end=0x%lx\n",
				tag ? tag : "unknown", e->start, e->end);
			continue;
		}

		vma_start_write(vma);
		vm_flags_set(vma, e->flags);
	}
	mmap_write_unlock(mm);
}

/*
 * superfork_copy_mm - Copy memory from source task.
 * Mirrors copy_mm() but copies from src_task.
 */
static int superfork_copy_mm(struct task_struct *p,
			     struct task_struct *src_task,
			     struct tgid_clone_entry *tgid_entry,
			     u64 clone_flags)
{
	struct mm_struct *mm, *oldmm;

	p->min_flt = p->maj_flt = 0;
	p->nvcsw = p->nivcsw = 0;
#ifdef CONFIG_DETECT_HUNG_TASK
	p->last_switch_count = p->nvcsw + p->nivcsw;
	p->last_switch_time = 0;
#endif

	p->mm = NULL;
	p->active_mm = NULL;

	oldmm = src_task->mm;
	if (!oldmm)
		return 0;

	if (clone_flags & CLONE_VM) {
		/* Thread: share the leader's mm */
		if (!tgid_entry->shared_mm)
			return -EINVAL;
		mmget(tgid_entry->shared_mm);
		p->mm = tgid_entry->shared_mm;
		p->active_mm = tgid_entry->shared_mm;
	} else {
		struct sf_mm_flag_override_ctx mm_override;
		int prep_ret;

		/* Leader: duplicate mm with CoW */
		prep_ret = superfork_prepare_mm_exact_clone(oldmm, &mm_override);
		if (prep_ret)
			return prep_ret;

		mm = dup_mm(p, oldmm);

		superfork_restore_mm_fork_flags(oldmm, &mm_override, "source");

		if (!mm)
			goto out_mm_override_free;

		/* Keep clone VM flags aligned with source after exact clone. */
		superfork_restore_mm_fork_flags(mm, &mm_override, "clone");
		superfork_mm_flag_override_ctx_free(&mm_override);
		p->mm = mm;
		p->active_mm = mm;
		tgid_entry->shared_mm = mm;
		goto out_mm_done;

out_mm_override_free:
		superfork_mm_flag_override_ctx_free(&mm_override);
		return -ENOMEM;
	}

out_mm_done:

	sched_mm_cid_fork(p);
	return 0;
}

/* ---- seccomp ----------------------------------------------------------- */

static void superfork_copy_seccomp(struct task_struct *p,
				   struct task_struct *src_task)
{
#ifdef CONFIG_SECCOMP
	spin_lock_irq(&src_task->sighand->siglock);
	get_seccomp_filter(src_task);
	p->seccomp = src_task->seccomp;
	spin_unlock_irq(&src_task->sighand->siglock);

	if (p->seccomp.mode != SECCOMP_MODE_DISABLED)
		set_task_syscall_work(p, SECCOMP);
#endif
}

/* ---- copy_process ------------------------------------------------------ */

/*
 * superfork_copy_process - Create a new task as a copy of a frozen task.
 *
 * Core function mirroring copy_process() from fork.c. Creates a new
 * task_struct that will resume execution at the same point as the frozen
 * source task.
 */
struct task_struct *superfork_copy_process(
	struct container_clone_ctx *ctx,
	struct task_struct *src_task,
	struct tgid_clone_entry *tgid_entry,
	const char *new_rootfs_path,
	const char *src_bundle_path,
	const char *dst_bundle_path,
	bool is_leader)
{
	int retval;
	struct task_struct *p;
	struct pid *pid;
	u64 clone_flags = 0;
	int node = NUMA_NO_NODE;
	const char *fail_stage = "none";

	/* Set clone flags based on whether this is a leader or thread */
	/*
	 * Threads share the leader's mm/files/sighand via CLONE_VM|FILES|SIGHAND.
	 * The leader's superfork_copy_process call stores these in tgid_entry
	 * so non-leader calls can reference them.
	 */
	if (!is_leader)
		clone_flags = CLONE_THREAD | CLONE_VM |
			      CLONE_FILES | CLONE_SIGHAND;

	pr_debug("superfork: copy_process src_pid=%d is_leader=%d\n",
		 src_task->pid, is_leader);

	/*
	 * Step 1: Duplicate task_struct (mirrors dup_task_struct)
	 */
	p = superfork_dup_task_struct(src_task, node);
	if (!p)
		return ERR_PTR(-ENOMEM);

	/*
	 * The sf_vcpu_snap pointer is owned by the source task (allocated by
	 * superfork_alloc_vcpu_snaps and read in superfork_copy_thread). The
	 * clone must not share it; dup_task_struct shallow-copies the field.
	 */
	p->sf_vcpu_snap = NULL;

	/*
	 * Do NOT clear PF_KTHREAD / PF_USER_WORKER here: those task classes
	 * take the kthread/user-worker resume path in superfork_copy_thread()
	 * which depends on the flag surviving, and the scheduler / signal
	 * code also consults it.  The clone of a kthread is still a kthread;
	 * the clone of a vhost_task is still a vhost_task.
	 */

	/*
	 * Clear the frozen flag. The source task is frozen in its cgroup,
	 * but the cloned task is in a new context and should not be marked
	 * as frozen. If we don't clear this, cgroup_leave_frozen() will
	 * fail when the task wakes up.
	 */
	p->frozen = false;

	/*
	 * Step 1.5: Reset transient thread_info state.
	 *
	 * Do not zero all thread flags: that can drop architecture/runtime bits
	 * that must survive task resume (for example tagged-address policy).
	 * Only clear transient scheduler/freezer/signal-work flags inherited from
	 * the frozen source task.
	 *
	 * We also reset preempt_count here to ensure any code paths before
	 * sched_fork() see a valid value. sched_fork() will later call
	 * init_task_preempt_count() which sets the proper FORK_PREEMPT_COUNT.
	 */
	{
		struct thread_info *ti = task_thread_info(p);

		clear_ti_thread_flag(ti, TIF_SIGPENDING);
		clear_ti_thread_flag(ti, TIF_NEED_RESCHED);
		clear_ti_thread_flag(ti, TIF_NEED_RESCHED_LAZY);
		clear_ti_thread_flag(ti, TIF_NOTIFY_RESUME);
		clear_ti_thread_flag(ti, TIF_NOTIFY_SIGNAL);
#ifdef TIF_FREEZE
		clear_ti_thread_flag(ti, TIF_FREEZE);
#endif
		/*
		 * TIF_RESTORE_SIGMASK only exists on architectures that define
		 * HAVE_TIF_RESTORE_SIGMASK (e.g. arm64).  On x86 and others the
		 * kernel uses task->restore_sigmask instead; clear_tsk_restore_sigmask()
		 * handles both cases portably.
		 */
		clear_tsk_restore_sigmask(p);

		/*
		 * Reset preempt_count using the proper macro.
		 * This ensures the value is correct for the architecture.
		 */
#ifdef CONFIG_ARM64
		pr_debug("superfork: before init_preempt_count, preempt.count=0x%x\n",
			 ti->preempt.count);
#endif
		init_task_preempt_count(p);
#ifdef CONFIG_ARM64
		pr_debug("superfork: after init_preempt_count, preempt.count=0x%x\n",
			 ti->preempt.count);
#endif
	}

	/*
	 * Step 2: Initialize RT mutex state
	 */
	superfork_rt_mutex_init_task(p);

	/*
	 * Step 3: Copy credentials
	 */
	retval = superfork_copy_creds(p, src_task, clone_flags);
	if (retval) {
		fail_stage = "copy_creds";
		goto bad_fork_free;
	}

	/*
	 * Step 4: Initialize task state (mirrors copy_process init section)
	 */
	delayacct_tsk_init(p);
	p->flags &= ~(PF_SUPERPRIV | PF_WQ_WORKER | PF_IDLE | PF_NO_SETAFFINITY);
	p->flags |= PF_FORKNOEXEC;
	INIT_LIST_HEAD(&p->children);
	INIT_LIST_HEAD(&p->sibling);
	superfork_rcu_copy_process(p);
	p->vfork_done = NULL;
	spin_lock_init(&p->alloc_lock);

	init_sigpending(&p->pending);

	p->utime = p->stime = p->gtime = 0;
#ifdef CONFIG_ARCH_HAS_SCALED_CPUTIME
	p->utimescaled = p->stimescaled = 0;
#endif
	prev_cputime_init(&p->prev_cputime);

#ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
	seqcount_init(&p->vtime.seqcount);
	p->vtime.starttime = 0;
	p->vtime.state = VTIME_INACTIVE;
#endif

#ifdef CONFIG_IO_URING
	p->io_uring = NULL;
#endif

	p->default_timer_slack_ns = src_task->timer_slack_ns;

#ifdef CONFIG_PSI
	p->psi_flags = 0;
#endif

	task_io_accounting_init(&p->ioac);
	acct_clear_integrals(p);

	posix_cputimers_init(&p->posix_cputimers);
	tick_dep_init_task(p);

	p->io_context = NULL;
	audit_set_context(p, NULL);
	cgroup_fork(p);

#ifdef CONFIG_NUMA
	p->mempolicy = mpol_dup(src_task->mempolicy);
	if (IS_ERR(p->mempolicy)) {
		retval = PTR_ERR(p->mempolicy);
		p->mempolicy = NULL;
		fail_stage = "mpol_dup";
		goto bad_fork_cleanup_delayacct;
	}
#endif

#ifdef CONFIG_CPUSETS
	p->cpuset_mem_spread_rotor = NUMA_NO_NODE;
	seqcount_spinlock_init(&p->mems_allowed_seq, &p->alloc_lock);
#endif

#ifdef CONFIG_TRACE_IRQFLAGS
	memset(&p->irqtrace, 0, sizeof(p->irqtrace));
	p->irqtrace.hardirq_disable_ip	= _THIS_IP_;
	p->irqtrace.softirq_enable_ip	= _THIS_IP_;
	p->softirqs_enabled		= 1;
	p->softirq_context		= 0;
#endif

	p->pagefault_disabled = 0;
	lockdep_init_task(p);
	p->blocked_on = NULL;

#ifdef CONFIG_BCACHE
	p->sequential_io	= 0;
	p->sequential_io_avg	= 0;
#endif

#ifdef CONFIG_BPF_SYSCALL
	RCU_INIT_POINTER(p->bpf_storage, NULL);
	p->bpf_ctx = NULL;
#endif

	unwind_task_init(p);

	/*
	 * Step 5: Scheduler setup
	 */
	retval = sched_fork(clone_flags, p);
	if (retval) {
		fail_stage = "sched_fork";
		goto bad_fork_cleanup_policy;
	}

#ifdef CONFIG_ARM64
	/* Debug: check preempt_count after sched_fork */
	{
		struct thread_info *ti = task_thread_info(p);
		pr_debug("superfork: after sched_fork, preempt.count=0x%x\n",
			 ti->preempt.count);
	}
#endif

	retval = perf_event_init_task(p, clone_flags);
	if (retval) {
		fail_stage = "perf_event_init_task";
		goto bad_fork_sched_cancel_fork;
	}

	retval = audit_alloc(p);
	if (retval) {
		fail_stage = "audit_alloc";
		goto bad_fork_cleanup_perf;
	}

	/*
	 * Step 6: Copy process information
	 */
	shm_init_task(p);

	retval = security_task_alloc(p, clone_flags);
	if (retval) {
		fail_stage = "security_task_alloc";
		goto bad_fork_cleanup_audit;
	}

	retval = copy_semundo(clone_flags, p);
	if (retval) {
		fail_stage = "copy_semundo";
		goto bad_fork_cleanup_security;
	}

	/*
	 * Phase 3 (Option B): clone mm before files so KVM VM creation can
	 * later bind to the already-cloned mm in a cleaner flow.
	 */
	retval = superfork_copy_mm(p, src_task, tgid_entry, clone_flags);
	if (retval) {
		fail_stage = "copy_mm";
		goto bad_fork_cleanup_semundo;
	}

	retval = superfork_copy_files(p, src_task, tgid_entry,
				     src_bundle_path, dst_bundle_path,
				     clone_flags);
	if (retval) {
		fail_stage = "copy_files";
		goto bad_fork_cleanup_mm_only;
	}

	retval = superfork_copy_fs(p, src_task, new_rootfs_path, clone_flags);
	if (retval) {
		fail_stage = "copy_fs";
		goto bad_fork_cleanup_files_mm;
	}

	retval = superfork_copy_sighand(p, src_task, tgid_entry, clone_flags);
	if (retval) {
		fail_stage = "copy_sighand";
		goto bad_fork_cleanup_fs_mm;
	}

	retval = superfork_copy_signal(p, src_task, tgid_entry, clone_flags);
	if (retval) {
		fail_stage = "copy_signal";
		goto bad_fork_cleanup_sighand_mm;
	}

	// /*
	// * If the source task was frozen while inside a signal handler,
	// * it will try to rt_sigreturn when it resumes. Clear any pending
	// * signals that were directed at the source — they should not be
	// * delivered to the clone. The clone starts fresh signal-wise.
	// *
	// * We don't touch the stack (the signal frame is in userspace memory
	// * which was CoW-duplicated), but we clear the kernel-side pending
	// * signal tracking so the clone doesn't get double-delivered signals.
	// */
	flush_signals(p);

	/*
	 * Step 7: Set up namespaces
	 */
	if (!ctx->new_nsproxy) {
		pr_err("superfork: nsproxy not initialized\n");
		retval = -EINVAL;
		fail_stage = "nsproxy_not_initialized";
		goto bad_fork_cleanup_mm;
	}

	if (!ctx->new_pid_ns) {
		pr_err("superfork: PID namespace not initialized\n");
		retval = -EINVAL;
		fail_stage = "pid_ns_not_initialized";
		goto bad_fork_cleanup_mm;
	}

	/*
	 * Install prepared nsproxy directly.
	 * p->nsproxy is copied by dup_task_struct() but that copied pointer
	 * doesn't carry an owned ref for this new task.
	 */
	task_lock(p);
	get_nsproxy(ctx->new_nsproxy);
	p->nsproxy = ctx->new_nsproxy;
	task_unlock(p);

	/*
	 * Step 8: Copy thread state
	 */
	retval = superfork_copy_thread(p, src_task, clone_flags);
	if (retval) {
		fail_stage = "copy_thread";
		goto bad_fork_cleanup_namespaces;
	}

#ifdef CONFIG_ARM64
	/* Debug: check preempt_count after copy_thread */
	{
		struct thread_info *ti = task_thread_info(p);
		pr_debug("superfork: after copy_thread, preempt.count=0x%x\n",
			 ti->preempt.count);
	}
#endif

	/*
	 * Step 9: Allocate PID
	 */
	pid = alloc_pid(ctx->new_pid_ns, NULL, 0);
	if (IS_ERR(pid)) {
		retval = PTR_ERR(pid);
		fail_stage = "alloc_pid";
		goto bad_fork_cleanup_thread;
	}

	p->thread_pid = pid;
	p->pid = pid_nr(pid);

	if (is_leader) {
		p->tgid = p->pid;
		p->group_leader = p;
		tgid_entry->new_leader = p;
	} else {
		p->tgid = tgid_entry->new_leader->tgid;
		p->group_leader = tgid_entry->new_leader;
	}

	/*
	 * Resume semantics: preserve robust-list state exactly as captured.
	 * Rewriting robust futex owner words from the kernel side can corrupt
	 * user memory when list_op_pending points at transient userspace state.
	 */

	/*
	 * Step 10: Initialize remaining fields
	 */
	p->nr_dirtied = 0;
	p->nr_dirtied_pause = 128 >> (PAGE_SHIFT - 10);
	p->dirty_paused_when = 0;

	p->pdeath_signal = 0;
	p->task_works = NULL;
	clear_posix_cputimers_work(p);

	futex_init_task(p);

	user_disable_single_step(p);
	clear_task_syscall_work(p, SYSCALL_TRACE);
#if defined(CONFIG_GENERIC_ENTRY) || defined(TIF_SYSCALL_EMU)
	clear_task_syscall_work(p, SYSCALL_EMU);
#endif
	clear_tsk_latency_tracing(p);

	/* Copy seccomp state */
	superfork_copy_seccomp(p, src_task);

	/*
	 * Step 11: Initialize scheduler/task state
	 */
	p->on_cpu = 0;
	p->on_rq = 0;
	p->__state = TASK_NEW;
	p->ptrace = 0;

	p->nr_cpus_allowed = src_task->nr_cpus_allowed;
	p->cpus_ptr = &p->cpus_mask;
	cpumask_copy(&p->cpus_mask, &src_task->cpus_mask);

	/* Set safe parent pointers (will be fixed in attach phase) */
	p->real_parent = current;
	p->parent = current;

	/* Initialize list heads */
	INIT_LIST_HEAD(&p->tasks);
	INIT_LIST_HEAD(&p->ptrace_entry);
	INIT_LIST_HEAD(&p->ptraced);

	/* Reference counts */
	refcount_set(&p->rcu_users, 2);
	refcount_set(&p->usage, 1);

	p->start_time = ktime_get_ns();
	p->start_boottime = ktime_get_boottime_ns();

	pr_debug("superfork: copy_process done, new_pid=%d\n", p->pid);

	return p;

	/* Error cleanup - mirrors copy_process cleanup */
bad_fork_cleanup_thread:
	exit_thread(p);
bad_fork_cleanup_namespaces:
	exit_task_namespaces(p);
bad_fork_cleanup_sighand_mm:
	__cleanup_sighand(p->sighand);
bad_fork_cleanup_fs_mm:
	exit_fs(p);
bad_fork_cleanup_files_mm:
	exit_files(p);
bad_fork_cleanup_mm_only:
	if (p->mm) {
		mmput(p->mm);
		p->mm = NULL;
		p->active_mm = NULL;
	}
	goto bad_fork_cleanup_semundo;
bad_fork_cleanup_mm:
	if (p->mm)
		mmput(p->mm);
	goto bad_fork_cleanup_semundo;
bad_fork_cleanup_semundo:
	exit_sem(p);
bad_fork_cleanup_security:
	security_task_free(p);
bad_fork_cleanup_audit:
	audit_free(p);
bad_fork_cleanup_perf:
	perf_event_free_task(p);
bad_fork_sched_cancel_fork:
	sched_cancel_fork(p);
bad_fork_cleanup_policy:
	lockdep_free_task(p);
#ifdef CONFIG_NUMA
	mpol_put(p->mempolicy);
#endif
bad_fork_cleanup_delayacct:
	delayacct_tsk_free(p);
bad_fork_free:
	pr_err("superfork: copy_process failed at stage=%s src_pid=%d err=%d\n",
	       fail_stage, src_task->pid, retval);
	dec_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);
	WRITE_ONCE(p->__state, TASK_DEAD);
	exit_creds(p);
	superfork_free_task_struct(p);
	return ERR_PTR(retval);
}
