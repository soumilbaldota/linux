// SPDX-License-Identifier: GPL-2.0
/*
 * superfork/superfork.c — syscall entry point and container orchestration.
 *
 * Contains the SYSCALL_DEFINE4(superfork) handler, clone_container (the
 * phase sequencer), superfork_clone_processes (per-task copy loop),
 * superfork_destroy_container (error rollback), btrfs snapshot helper, and
 * namespace setup.
 */

#include "../cgroup/cgroup-internal.h"
#include <asm/mmu_context.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/thread_info.h>
#include <linux/audit.h>
#include <linux/btrfs.h>
#include <linux/capability.h>
#include <linux/cgroup-defs.h>
#include <linux/cgroup.h>
#include <linux/cpumask.h>
#include <linux/cred.h>
#include <linux/user_namespace.h>
#include <linux/delayacct.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/freezer.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/ipc_namespace.h>
#include <linux/kernel.h>
#include <linux/kvm_host.h>
#include <linux/list.h>
#include <linux/lockdep.h>
#include <linux/major.h>
#include <linux/mempolicy.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/mnt_namespace.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/ns_common.h>
#include <linux/nsproxy.h>
#include <linux/perf_event.h>
#include <linux/pid_namespace.h>
#include <linux/pid.h>
#include <linux/plist.h>
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
#include <linux/syscalls.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/thread_info.h>
#include <linux/tick.h>
#include <linux/tsacct_kern.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <linux/unwind_deferred.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/net_namespace.h>
#include <net/af_unix.h>
#include <uapi/linux/un.h>
#include <linux/eventfd.h>
#include <linux/signalfd.h>
#include "internal.h"

/* ---- utilities used only within this file ------------------------------ */

static struct nsproxy *superfork_get_task_nsproxy(struct task_struct *task)
{
	struct nsproxy *nsproxy;

	task_lock(task);
	nsproxy = task->nsproxy;
	if (nsproxy)
		get_nsproxy(nsproxy);
	task_unlock(task);

	return nsproxy;
}

/* ---- tgid entry map ---------------------------------------------------- */

struct tgid_clone_entry *find_or_create_tgid_entry(
	struct container_clone_ctx *ctx, pid_t old_tgid)
{
	int i;

	for (i = 0; i < ctx->tgid_count; i++) {
		if (ctx->tgids[i].old_tgid == old_tgid)
			return &ctx->tgids[i];
	}

	if (ctx->tgid_count >= MAX_CLONE_TGIDS)
		return NULL;

	ctx->tgids[ctx->tgid_count].old_tgid = old_tgid;
	ctx->tgids[ctx->tgid_count].new_leader = NULL;
	ctx->tgids[ctx->tgid_count].shared_mm = NULL;
	ctx->tgids[ctx->tgid_count].shared_signal = NULL;
	ctx->tgids[ctx->tgid_count].shared_sighand = NULL;
	ctx->tgids[ctx->tgid_count].shared_files = NULL;
	ctx->tgids[ctx->tgid_count].shared_fs = NULL;

	return &ctx->tgids[ctx->tgid_count++];
}

/* ---- namespace setup --------------------------------------------------- */

static int superfork_setup_container_namespaces(struct container_clone_ctx *ctx,
						struct task_struct *first_task)
{
	struct user_namespace *user_ns;
	const struct cred *cred;
	unsigned long ns_flags;
	int ret;
	struct pid_namespace *parent_ns;
	struct nsproxy *src_nsproxy;

	/* Validate input */
	if (!first_task) {
		pr_err("superfork: invalid source task\n");
		return -EINVAL;
	}

	/*
	 * Take a stable reference instead of reading first_task->nsproxy
	 * directly while other threads may switch namespaces.
	 */
	src_nsproxy = superfork_get_task_nsproxy(first_task);
	if (!src_nsproxy || !src_nsproxy->pid_ns_for_children) {
		if (src_nsproxy)
			put_nsproxy(src_nsproxy);
		pr_err("superfork: source task has no usable namespaces\n");
		return -EINVAL;
	}

	/* Save source namespace references */
	ctx->src_nsproxy = src_nsproxy;
	ctx->src_pid_ns = src_nsproxy->pid_ns_for_children;
	get_pid_ns(ctx->src_pid_ns);

	pr_debug("superfork: source nsproxy=%p, pid_ns=%p\n",
		 ctx->src_nsproxy, ctx->src_pid_ns);

	/* Get user namespace for PID namespace creation */
	cred = get_task_cred(first_task);
	user_ns = get_user_ns(cred->user_ns);
	put_cred(cred);

	/* Create new PID namespace as SIBLING of source, not child. */
	parent_ns = ctx->src_pid_ns->parent;
	if (!parent_ns) {
		/* Source is the init PID namespace - use it as parent */
		parent_ns = ctx->src_pid_ns;
	}

	ctx->new_pid_ns = create_pid_namespace(user_ns, parent_ns);

	if (IS_ERR(ctx->new_pid_ns)) {
		ret = PTR_ERR(ctx->new_pid_ns);
		ctx->new_pid_ns = NULL;
		put_user_ns(user_ns);
		pr_err("superfork: failed to create PID namespace: %d\n", ret);
		return ret;
	}

	pr_debug("superfork: created PID namespace %p\n", ctx->new_pid_ns);

	/*
	 * Always isolate mount/ipc/uts/cgroup and PID namespaces.
	 * Net namespace isolation may be disabled if source tasks hold sockets.
	 */
	ns_flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS |
		   CLONE_NEWCGROUP;
	if (ctx->isolate_netns)
		ns_flags |= CLONE_NEWNET;

	ctx->new_nsproxy = create_new_namespaces(ns_flags, first_task,
						 user_ns, first_task->fs);

	put_user_ns(user_ns);

	if (IS_ERR(ctx->new_nsproxy)) {
		ret = PTR_ERR(ctx->new_nsproxy);
		ctx->new_nsproxy = NULL;
		pr_err("superfork: failed to create nsproxy (flags=0x%lx): %d\n",
		       ns_flags, ret);
		put_pid_ns(ctx->new_pid_ns);
		ctx->new_pid_ns = NULL;
		return ret;
	}

	pr_debug("superfork: created nsproxy %p -> %p (flags=0x%lx)\n",
		 ctx->src_nsproxy, ctx->new_nsproxy, ns_flags);

	/*
	 * Replace pid_ns_for_children with the dedicated PID namespace.
	 */
	put_pid_ns(ctx->new_nsproxy->pid_ns_for_children);
	ctx->new_nsproxy->pid_ns_for_children = get_pid_ns(ctx->new_pid_ns);

	pr_debug("  Namespaces in new container:\n");
	pr_debug("    PID ns:   %p (NEW)\n", ctx->new_nsproxy->pid_ns_for_children);
	pr_debug("    Mount ns: %p (NEW)\n", ctx->new_nsproxy->mnt_ns);
	pr_debug("    IPC ns:   %p (NEW)\n", ctx->new_nsproxy->ipc_ns);
	pr_debug("    UTS ns:   %p (NEW)\n", ctx->new_nsproxy->uts_ns);
	if (ctx->isolate_netns)
		pr_debug("    Net ns:   %p (NEW)\n", ctx->new_nsproxy->net_ns);
	else
		pr_debug("    Net ns:   %p (inherited - sockets detected)\n",
			 ctx->new_nsproxy->net_ns);

	return 0;
}

/* ---- process clone loop ------------------------------------------------ */

static int superfork_clone_processes(struct container_clone_ctx *ctx,
				     const char *new_rootfs_path,
				     const char *src_bundle_path,
				     const char *dst_bundle_path)
{
	int ret = 0;
	pid_t new_init_pid = 0;

	if (ctx->task_count == 0) {
		ret = -ESRCH;
		goto out;
	}

	/*
	 * Two-pass clone: leaders first, then threads.
	 *
	 * superfork_copy_process for a leader allocates the shared mm, files,
	 * signal, and sighand structs and stores them in tgid_entry.  The
	 * thread pass then references those via CLONE_VM|FILES|SIGHAND|THREAD
	 * instead of duplicating them again.  Reversing the order would leave
	 * tgid_entry->shared_* NULL when threads look them up.
	 */

	/* Phase 2: Clone thread group leaders */
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *new_task;
		struct tgid_clone_entry *tgid_entry;

		if (!task->is_leader)
			continue;

		tgid_entry = find_or_create_tgid_entry(ctx, task->old_tgid);
		if (!tgid_entry) {
			ret = -ENOMEM;
			goto cleanup_after_leaders;
		}

		new_task = superfork_copy_process(ctx, task->old_task,
					  tgid_entry, new_rootfs_path,
					  src_bundle_path, dst_bundle_path,
					  true);
		if (IS_ERR(new_task)) {
			ret = PTR_ERR(new_task);
			goto cleanup_after_leaders;
		}

		task->new_task = new_task;

		if (new_init_pid == 0)
			new_init_pid = new_task->pid;
	}

	/* Phase 3: Clone non-leader threads */
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *new_task;
		struct tgid_clone_entry *tgid_entry;

		if (task->is_leader)
			continue;

		tgid_entry = find_or_create_tgid_entry(ctx, task->old_tgid);
		if (!tgid_entry || !tgid_entry->new_leader) {
			ret = -EINVAL;
			goto cleanup_after_leaders;
		}

		new_task = superfork_copy_process(ctx, task->old_task,
					  tgid_entry, new_rootfs_path,
					  src_bundle_path, dst_bundle_path,
					  false);
		if (IS_ERR(new_task)) {
			ret = PTR_ERR(new_task);
			goto cleanup_after_leaders;
		}

		task->new_task = new_task;
	}

	ret = superfork_verify_cloned_fds(ctx);
	if (ret < 0) {
		pr_err("superfork: fd verification failed: %d\n", ret);
		goto cleanup_after_leaders;
	}
	/* Phase 4: Attach tasks */
	superfork_attach_tasks(ctx);

	/*
	 * Cgroup seeding and post-fork setup are deferred to the caller so
	 * they run after the source cgroup has been thawed. Seeding clones
	 * into a frozen src_cgrp would leave __cgroup_task_count >
	 * nr_frozen_tasks, flip CGRP_FROZEN off prematurely, short-circuit
	 * cgroup_thaw_sync, and leave the source tasks' JOBCTL_TRAP_FREEZE
	 * set. See superfork_do_clone() for the post-thaw call sites.
	 */
	return new_init_pid;

cleanup_after_leaders:
	write_lock_irq(&tasklist_lock);
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *p = task->new_task;
		if (!p)
			continue;

		if (!list_empty(&p->tasks))
			list_del_init(&p->tasks);
		if (!list_empty(&p->sibling))
			list_del_init(&p->sibling);
	}
	write_unlock_irq(&tasklist_lock);

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		if (task->new_task) {
			struct task_struct *p = task->new_task;
			if (p->thread_pid)
				free_pid(p->thread_pid);
			put_task_struct(p);
			task->new_task = NULL;
		}
	}
out:
	return ret;
}

/* ---- error rollback ---------------------------------------------------- */

/*
 * superfork_destroy_container - Destroy a partially created container.
 *
 * Kills all cloned tasks and cleans up resources.
 */
static void superfork_destroy_container(struct container_clone_ctx *ctx)
{
	pr_warn("superfork: destroying partially created container\n");

	/* Kill all cloned tasks */
	write_lock_irq(&tasklist_lock);
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *p = task->new_task;
		if (!p)
			continue;

		/* Remove from task lists */
		if (!list_empty(&p->tasks))
			list_del_init(&p->tasks);

		if (!list_empty(&p->sibling))
			list_del_init(&p->sibling);

		/* Send SIGKILL */
		if (!(p->flags & PF_KTHREAD))
			do_send_sig_info(SIGKILL, SEND_SIG_PRIV, p, PIDTYPE_PID);
	}
	write_unlock_irq(&tasklist_lock);

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		if (task->new_task) {
			struct task_struct *p = task->new_task;

			if (p->thread_pid)
				free_pid(p->thread_pid);
			put_task_struct(p);
			task->new_task = NULL;
		}
	}

	release_collected_tasks(ctx);
	if (ctx->new_nsproxy) {
		put_nsproxy(ctx->new_nsproxy);
		ctx->new_nsproxy = NULL;
	}
	if (ctx->new_pid_ns) {
		put_pid_ns(ctx->new_pid_ns);
		ctx->new_pid_ns = NULL;
	}
	if (ctx->src_nsproxy) {
		put_nsproxy(ctx->src_nsproxy);
		ctx->src_nsproxy = NULL;
	}
	if (ctx->src_pid_ns) {
		put_pid_ns(ctx->src_pid_ns);
		ctx->src_pid_ns = NULL;
	}
}

/* ---- container phase sequencer ----------------------------------------- */

static inline struct task_struct *get_first_ftask(struct container_clone_ctx *ctx)
{
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		if (task->old_task && task->is_leader) {
			pr_debug("superfork: using task %d as namespace reference\n",
				 task->old_task->pid);
			return task->old_task;
		}
	}
	pr_err("superfork: no leader task found\n");
	return NULL;
}

static void superfork_adjust_netns_isolation(struct container_clone_ctx *ctx)
{
	ctx->isolate_netns = true;
}

static int clone_container(struct container_clone_ctx *ctx,
			   pid_t *kpids, size_t count,
			   struct container_config *config,
			   pid_t *new_init_pid)
{
	int ret;
	pid_t init_pid = 0;
	struct task_struct *first_frozen_task = NULL;

	pr_debug("superfork: Phase 0 - collecting frozen tasks\n");

	ret = collect_frozen_tasks(ctx, kpids, count);

	if (ret < 0) {
		pr_err("superfork: failed to collect frozen tasks: %d\n", ret);
		return ret;
	}

	if (ctx->task_count == 0) {
		pr_err("superfork: no tasks collected\n");
		ret = -ESRCH;
		goto cleanup_final;
	}

	superfork_adjust_netns_isolation(ctx);

	first_frozen_task = get_first_ftask(ctx);
	if (!first_frozen_task) {
		ret = -ENOENT;
		goto cleanup_final;
	}

	ret = superfork_setup_container_namespaces(ctx, first_frozen_task);
	if (ret < 0) {
		pr_err("superfork: namespace setup failed: %d\n", ret);
		goto cleanup_final;
	}

	pr_info("superfork: using rootfs path: '%s'\n", config->new_rootfs_path);

	init_pid = superfork_clone_processes(ctx, config->new_rootfs_path,
					    config->src_bundle_path,
					    config->dst_bundle_path);
	if (init_pid < 0) {
		ret = init_pid;
		goto cleanup_destroy;
	}

	*new_init_pid = init_pid;

	pr_info("superfork: container created successfully, init=%d\n", init_pid);

	/*
	 * Note: We don't release ctx resources here because the caller
	 * (syscall handler) needs to do final cleanup and wake tasks.
	 */
	return 0;

cleanup_destroy:
	pr_warn("superfork: destroying partially created container\n");
	superfork_destroy_container(ctx);
	return ret;

cleanup_final:
	pr_warn("superfork: cleaning up after early failure\n");

	release_collected_tasks(ctx);

	if (ctx->new_nsproxy) {
		put_nsproxy(ctx->new_nsproxy);
		ctx->new_nsproxy = NULL;
	}
	if (ctx->new_pid_ns) {
		put_pid_ns(ctx->new_pid_ns);
		ctx->new_pid_ns = NULL;
	}
	if (ctx->src_nsproxy) {
		put_nsproxy(ctx->src_nsproxy);
		ctx->src_nsproxy = NULL;
	}
	if (ctx->src_pid_ns) {
		put_pid_ns(ctx->src_pid_ns);
		ctx->src_pid_ns = NULL;
	}

	return ret;
}

/* ---- btrfs snapshot ---------------------------------------------------- */

static int vfs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int error = -ENOTTY;

	if (!filp->f_op->unlocked_ioctl)
		goto out;

	error = filp->f_op->unlocked_ioctl(filp, cmd, arg);
	if (error == -ENOIOCTLCMD)
		error = -ENOTTY;
out:
	return error;
}

static int btrfs_snapshot(struct container_config __user *user_config,
			  const char *dst)
{
	struct file *src_file = NULL, *dst_dir_file = NULL;
	char *kdst, *dst_name;
	int src_fd = -1;
	int ret = 0;

	/* open src_bundle_path — we need an fd for the source subvolume */
	{
		char src[4096];
		if (copy_from_user(src, user_config->src_bundle_path, sizeof(src)))
			return -EFAULT;
		src_file = filp_open(src, O_RDONLY | O_DIRECTORY, 0);
	}
	if (IS_ERR(src_file)) {
		ret = PTR_ERR(src_file);
		src_file = NULL;
		goto out;
	}

	kdst = kstrdup(dst, GFP_KERNEL);
	if (!kdst) {
		ret = -ENOMEM;
		goto out_close_src;
	}

	dst_name = kbasename(kdst);
	if (dst_name == kdst) {
		ret = -EINVAL;
		goto out_free_dst;
	}
	*(dst_name - 1) = '\0';

	dst_dir_file = filp_open(kdst, O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(dst_dir_file)) {
		ret = PTR_ERR(dst_dir_file);
		dst_dir_file = NULL;
		goto out_free_dst;
	}

	src_fd = get_unused_fd_flags(O_CLOEXEC);
	if (src_fd < 0) {
		ret = src_fd;
		goto out_close_dst;
	}
	fd_install(src_fd, get_file(src_file));

	/* Write src_fd into the btrfs_args field in the original userspace buffer.
	 * user_config is the original __user pointer — valid userspace memory,
	 * access_ok passes, no vm_mmap or vmalloc needed. */
	if (put_user((__s64)src_fd, &user_config->btrfs_args.fd)) {
		ret = -EFAULT;
		goto out_close_fd;
	}

	/* dst_name is already written by Go into btrfs_args.name,
	 * but overwrite it here from the kernel-split dst path to be safe */
	if (copy_to_user(user_config->btrfs_args.name, dst_name,
			 strlen(dst_name) + 1)) {
		ret = -EFAULT;
		goto out_close_fd;
	}

	ret = vfs_ioctl(dst_dir_file, BTRFS_IOC_SNAP_CREATE_V2,
			(unsigned long)&user_config->btrfs_args);

out_close_fd:
	close_fd(src_fd);
out_close_dst:
	filp_close(dst_dir_file, NULL);
out_free_dst:
	kfree(kdst);
out_close_src:
	filp_close(src_file, NULL);
out:
	return ret;
}

/* ---- syscall entry ----------------------------------------------------- */

SYSCALL_DEFINE4(superfork,
		pid_t __user *, pids,
		size_t, count,
		struct container_config __user *, user_config,
		pid_t __user *, user_new_init_pid)
{
	struct container_clone_ctx *ctx;
	struct container_config *config;
	struct cgroup *src_cgrp = NULL;
	struct sf_src_cgroup_move *src_moves = NULL;
	pid_t *kpids;
	pid_t new_init_pid = 0;
	bool src_cgrp_frozen = false;
	int thaw_ret;
	int restore_ret;
	int ret = 0;

	if (count == 0 || count > MAX_CLONE_TGIDS)
		return -EINVAL;

	config = kzalloc(sizeof(*config), GFP_KERNEL);
	if (!config)
		return -ENOMEM;

	if (copy_from_user(config, user_config, sizeof(*config))) {
		pr_err("superfork: copy_from_user config failed\n");
		ret = -EFAULT;
		goto out_free_config;
	}
	ctx = kvzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		ret = -ENOMEM;
		goto out_free_config;
	}

	kpids = kmalloc_array(count, sizeof(pid_t), GFP_KERNEL);
	if (!kpids) {
		ret = -ENOMEM;
		goto out_free_ctx;
	}

	src_moves = kcalloc(count, sizeof(*src_moves), GFP_KERNEL);
	if (!src_moves) {
		ret = -ENOMEM;
		goto out_free_kpids;
	}

	if (copy_from_user(kpids, pids, count * sizeof(pid_t))) {
		pr_err("superfork: copy_from_user pids failed\n");
		ret = -EFAULT;
		goto out_cleanup;
	}
	/*
	 * Resolve the scratch/destination cgroup that will be frozen. The
	 * source tasks are migrated into this cgroup before freezing so the
	 * freeze affects only the tasks being cloned, not whatever cgroup
	 * the caller happened to live in (e.g. a shared user session scope).
	 *
	 * src_cgrp is also the *destination* cgroup for the clones — they
	 * stay here after the sources are moved back to their originals.
	 */
	src_cgrp = cgroup_get_from_path(config->src_cgroup_path);
	if (IS_ERR(src_cgrp)) {
		pr_err("superfork: cgroup_get_from_path('%s') failed: %ld\n",
		       config->src_cgroup_path, PTR_ERR(src_cgrp));
		ret = PTR_ERR(src_cgrp);
		src_cgrp = NULL;
		goto out_cleanup;
	}
	pr_info("superfork: got src_cgrp for '%s'\n", config->src_cgroup_path);

	/*
	 * Record each source leader's current cgroup and migrate it into
	 * src_cgrp. Original membership is restored on exit so the source
	 * container keeps its original cgroup placement.
	 */
	ret = superfork_prepare_source_task_cgroups(src_cgrp, kpids, count,
						     src_moves);
	if (ret < 0)
		goto out_cleanup;

	/*
	 * Pre-allocate per-thread pt_regs snapshot slots before freezing so
	 * KVM's block loop can capture the vCPU's userspace frame when the
	 * freezer signal arrives. See superfork_kvm_vcpu_snapshot_entry().
	 */
	ret = superfork_alloc_vcpu_snaps(kpids, count);
	if (ret < 0) {
		pr_err("superfork: alloc_vcpu_snaps failed: %d\n", ret);
		goto out_cleanup;
	}

	ret = cgroup_freeze_sync(src_cgrp);
	if (ret < 0) {
		pr_err("superfork: cgroup_freeze_sync failed: %d\n", ret);
		goto out_cleanup;
	}
	src_cgrp_frozen = true;
	pr_info("superfork: src cgroup frozen\n");

	ret = wait_source_tasks_frozen(kpids, count);
	if (ret < 0) {
		pr_err("superfork: timed out waiting for source tasks to freeze\n");
		goto out_cleanup;
	}

	ret = btrfs_snapshot(user_config, config->dst_bundle_path);
	if (ret < 0) {
		pr_err("superfork: btrfs_snapshot('%s' -> '%s') failed: %d\n",
		       config->src_bundle_path, config->dst_bundle_path, ret);
		goto out_cleanup;
	}
	pr_info("superfork: snapshot created '%s' -> '%s'\n",
		config->src_bundle_path, config->dst_bundle_path);

	ret = clone_container(ctx, kpids, count, config, &new_init_pid);
	if (ret < 0) {
		pr_err("superfork: clone_container failed: %d\n", ret);
		goto out_cleanup;
	}
	pr_info("superfork: clone_container done, new_init_pid=%d\n", new_init_pid);

	/*
	 * Thaw the source cgroup before waking cloned tasks so the source
	 * VM resumes cleanly once clone_container() completes.
	 *
	 * ORDER MATTERS for the next four calls:
	 *   thaw → restore sources → seed clones → post_fork → wake
	 *
	 * Seeding clones while src_cgrp is still frozen would flip CGRP_FROZEN
	 * off prematurely (bumping __cgroup_task_count without nr_frozen_tasks),
	 * causing cgroup_thaw_sync to short-circuit and leaving source threads
	 * trapped with JOBCTL_TRAP_FREEZE.  See the freezer invariant note in
	 * docs/superfork-code-flow.md for the full analysis.
	 */
	ret = superfork_thaw_source_cgroup_sync(src_cgrp, "post-clone");
	if (ret < 0)
		goto out_destroy_container;
	src_cgrp_frozen = false;

	restore_ret = superfork_restore_source_task_cgroups(src_moves, count);
	if (restore_ret < 0) {
		ret = restore_ret;
		goto out_destroy_container;
	}

	/*
	 * Seed cloned tasks into their destination css_set now that src_cgrp
	 * is thawed. Doing this while src_cgrp was frozen would bump
	 * __cgroup_task_count without bumping nr_frozen_tasks, breaking the
	 * freezer invariant and causing cgroup_leave_frozen() underflows on
	 * both the source and the clones.
	 */
	ret = superfork_seed_cgroup_membership(ctx);
	if (ret < 0) {
		pr_err("superfork: seed_cgroup_membership failed: %d\n", ret);
		goto out_destroy_container;
	}

	/* Phase 5: Post-fork setup (must run after cgroup seeding). */
	superfork_post_fork(ctx);

	if (copy_to_user(user_new_init_pid, &new_init_pid, sizeof(pid_t))) {
		pr_err("superfork: copy_to_user new_init_pid failed\n");
		ret = -EFAULT;
		goto out_destroy_container;
	}
	pr_info("superfork: userspace pid copied; waking cloned tasks\n");

	pr_info("superfork: Phase 4 - waking tasks\n");
	superfork_wake_tasks(ctx);

	ret = 0;
	goto out_cleanup;

out_destroy_container:
	superfork_destroy_container(ctx);

out_cleanup:
	if (src_cgrp_frozen) {
		thaw_ret = superfork_thaw_source_cgroup_sync(src_cgrp, "cleanup");
		if (!ret && thaw_ret < 0)
			ret = thaw_ret;
		src_cgrp_frozen = false;
	}

	/*
	 * Free per-thread pt_regs snapshot slots. Idempotent: safe even if
	 * alloc failed or never ran. Must run after source tasks are thawed
	 * so they don't observe a stale pointer if they re-enter KVM_RUN.
	 */
	superfork_free_vcpu_snaps(kpids, count);

	restore_ret = superfork_restore_source_task_cgroups(src_moves, count);
	if (!ret && restore_ret < 0)
		ret = restore_ret;

	release_collected_tasks(ctx);
	if (ctx->new_nsproxy)
		put_nsproxy(ctx->new_nsproxy);
	if (ctx->new_pid_ns)
		put_pid_ns(ctx->new_pid_ns);
	if (ctx->src_nsproxy)
		put_nsproxy(ctx->src_nsproxy);
	if (ctx->src_pid_ns)
		put_pid_ns(ctx->src_pid_ns);

	if (src_cgrp)
		cgroup_put(src_cgrp);

	superfork_put_source_task_cgroup_moves(src_moves, count);
	kfree(src_moves);
	src_moves = NULL;

out_free_kpids:
	kfree(kpids);

out_free_ctx:
	kvfree(ctx);

out_free_config:
	kfree(config);
	return ret;
}
