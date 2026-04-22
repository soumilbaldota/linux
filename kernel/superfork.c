#include "cgroup/cgroup-internal.h"
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
#include <net/af_unix.h>
#include <uapi/linux/un.h>
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
#include <linux/user_namespace.h>
#include <linux/utsname.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <net/net_namespace.h>
#include <linux/eventfd.h>
#include <linux/signalfd.h>
#include "futex/futex.h"

static inline struct task_clone_entry* get_ctx_task(struct container_clone_ctx *ctx, int i) {
	return &ctx->tasks[i];
}


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


static bool cgroup_reached_desired_state(struct cgroup *cgrp, bool freeze)
{
	if (freeze)
		/* Wait for achieved state, not just requested freeze. */
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

static int cgroup_freeze_sync(struct cgroup *cgrp)
{
	return cgroup_do_freeze_thaw(cgrp, true);
}

static int cgroup_thaw_sync(struct cgroup *cgrp)
{
	return cgroup_do_freeze_thaw(cgrp, false);
}

#define SUPERFORK_THAW_RETRIES 3

struct sf_src_cgroup_move {
	pid_t tgid;
	struct task_struct *leader;
	struct cgroup *orig_cgrp;
	bool moved;
};

static int superfork_thaw_source_cgroup_sync(struct cgroup *src_cgrp,
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

static int superfork_restore_source_task_cgroups(struct sf_src_cgroup_move *moves,
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

static void superfork_put_source_task_cgroup_moves(struct sf_src_cgroup_move *moves,
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

static int superfork_prepare_source_task_cgroups(struct cgroup *src_cgrp,
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


static struct tgid_clone_entry *find_or_create_tgid_entry(
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


static int superfork_setup_container_namespaces(struct container_clone_ctx *ctx,
						struct task_struct *first_task)
{
	struct user_namespace *user_ns;
	const struct cred *cred;
	unsigned long ns_flags;
	int ret;
	struct pid_namespace *parent_ns;
	struct nsproxy *src_nsproxy;

	pr_info("superfork: setting up container namespaces\n");

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

	pr_info("superfork: namespace setup complete\n");
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


/*
 * Find the new task corresponding to an old task (leaders only for parent mapping)
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

/*
 * Check if a task_struct is one of the tasks being cloned
 */
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
 * This ensures the new container is a sibling tree, not a child of the original.
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

/* ========== Copy Functions (mirroring fork.c copy_* functions) ========== */

/*
 * superfork_copy_creds - Copy credentials from source task
 * Mirrors copy_creds() but copies from src_task instead of current
 */
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

static struct files_struct *superfork_dup_files_for_container(
	struct files_struct *oldf,
	const char *src_bundle_path,
	const char *dst_bundle_path,
	struct mm_struct *new_mm,
	struct tgid_clone_entry *tgid_entry
);

/*
 * superfork_copy_files - Copy file descriptors from source task
 * Mirrors copy_files() but copies from src_task
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
		/* Thread: share the CLONED leader's files, not the original's */
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

static bool superfork_is_tty_dev(const struct inode *inode)
{
	unsigned int major;

	if (!inode || !S_ISCHR(inode->i_mode))
		return false;

	major = imajor(inode);

	if (major == TTY_MAJOR || major == TTYAUX_MAJOR ||
	    major == PTY_MASTER_MAJOR || major == PTY_SLAVE_MAJOR)
		return true;

	if (major >= UNIX98_PTY_MASTER_MAJOR &&
	    major < UNIX98_PTY_MASTER_MAJOR + (2 * UNIX98_PTY_MAJOR_COUNT))
		return true;

	return false;
}

static int superfork_replace_file_at(struct files_struct *files, unsigned int fd,
				     struct file *replacement)
{
	struct fdtable *fdt;
	struct file *tofree;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd >= fdt->max_fds || !test_bit(fd, fdt->open_fds)) {
		spin_unlock(&files->file_lock);
		return -EBADF;
	}

	tofree = rcu_dereference_raw(fdt->fd[fd]);
	if (!tofree) {
		spin_unlock(&files->file_lock);
		return -EBADF;
	}

	get_file(replacement);
	rcu_assign_pointer(fdt->fd[fd], replacement);
	spin_unlock(&files->file_lock);

	filp_close(tofree, files);
	return 0;
}

static struct file *superfork_get_file_at(struct files_struct *files, unsigned int fd)
{
	struct fdtable *fdt;
	struct file *file = NULL;

	spin_lock(&files->file_lock);
	fdt = files_fdtable(files);
	if (fd < fdt->max_fds && test_bit(fd, fdt->open_fds)) {
		file = rcu_dereference_raw(fdt->fd[fd]);
		if (file)
			get_file(file);
	}
	spin_unlock(&files->file_lock);

	return file;
}

enum fd_action_type {
	FD_ACT_NONE,
	FD_ACT_UNSUPPORTED,
	FD_ACT_CLONE,
	FD_ACT_EVENTFD_NEW,
	FD_ACT_SIGNALFD_NEW,
	FD_ACT_KVM_VM,
	FD_ACT_KVM_VCPU,
	FD_ACT_KVM_VM_STATS,
	FD_ACT_KVM_VCPU_STATS,
	FD_ACT_UNIX_SOCK_SERVER
};

struct fd_action {
	enum fd_action_type type;
	unsigned int fd;
	struct file *file; /* extra ref held when type != NONE */
	const char *hint;
};

static bool superfork_is_kvm_vm_file(struct file *file)
{
#ifdef CONFIG_KVM
	return file_is_kvm(file);
#else
	return false;
#endif
}

static bool superfork_is_kvm_vcpu_file(struct file *file)
{
#ifdef CONFIG_KVM
	return file_is_kvm_vcpu(file);
#else
	return false;
#endif
}

static bool superfork_is_kvm_vm_stats_file(struct file *file)
{
#ifdef CONFIG_KVM
	return file_is_kvm_vm_stats(file);
#else
	return false;
#endif
}

static bool superfork_is_kvm_vcpu_stats_file(struct file *file)
{
#ifdef CONFIG_KVM
	return file_is_kvm_vcpu_stats(file);
#else
	return false;
#endif
}

static bool superfork_is_kvm_device_file(struct file *file)
{
#ifdef CONFIG_KVM
	return file_is_kvm_device(file);
#else
	return false;
#endif
}

static bool superfork_is_kvm_gmem_file(struct file *file)
{
#ifdef CONFIG_KVM
	return file_is_kvm_gmem(file);
#else
	return false;
#endif
}

static int superfork_collect_fd_action(const void *arg, struct file *file,
				       unsigned int fd)
{
	struct fd_action *act = (struct fd_action *)arg;
	struct inode *inode = file_inode(file);

	/* Classify KVM anon-inode fds before generic clone/unsupported paths. */
	if (superfork_is_kvm_vm_file(file)) {
		act->fd = fd;
		act->type = FD_ACT_KVM_VM;
		act->file = get_file(file);
		act->hint = "kvm_vm";
		return fd + 1;
	}

	if (superfork_is_kvm_vm_stats_file(file)) {
		act->fd = fd;
		act->type = FD_ACT_KVM_VM_STATS;
		act->file = get_file(file);
		act->hint = "kvm_vm_stats";
		return fd + 1;
	}

	if (superfork_is_kvm_vcpu_stats_file(file)) {
		act->fd = fd;
		act->type = FD_ACT_KVM_VCPU_STATS;
		act->file = get_file(file);
		act->hint = "kvm_vcpu_stats";
		return fd + 1;
	}

	if (superfork_is_kvm_device_file(file)) {
		act->fd = fd;
		act->type = FD_ACT_UNSUPPORTED;
		act->file = get_file(file);
		act->hint = "kvm_device";
		return fd + 1;
	}

	if (superfork_is_kvm_gmem_file(file)) {
		act->fd = fd;
		act->type = FD_ACT_UNSUPPORTED;
		act->file = get_file(file);
		act->hint = "kvm_gmem";
		return fd + 1;
	}

	if (superfork_is_kvm_vcpu_file(file)) {
		act->fd = fd;
		act->type = FD_ACT_KVM_VCPU;
		act->file = get_file(file);
		act->hint = "kvm_vcpu";
		return fd + 1;
	}

	if (sock_from_file(file)) {
		struct unix_sock *u = unix_get_socket(file);

		if (u && u->sk.sk_state == TCP_LISTEN && u->addr &&
		    u->addr->name[0].sun_family == AF_UNIX &&
		    u->addr->name[0].sun_path[0] != '\0') {
			/* Path-bound Unix domain listening socket — we can
			 * recreate it at the remapped bundle path in the clone.
			 */
			act->fd = fd;
			act->type = FD_ACT_UNIX_SOCK_SERVER;
			act->file = get_file(file);
			act->hint = "unix_sock_server";
			return fd + 1;
		}

		act->fd = fd;
		act->type = FD_ACT_UNSUPPORTED;
		act->file = get_file(file);
		act->hint = "socket";
		return fd + 1;
	}

	if (inode && S_ISFIFO(inode->i_mode)) {
		act->fd = fd;
		act->type = FD_ACT_UNSUPPORTED;
		act->file = get_file(file);
		act->hint = "fifo";
		return fd + 1;
	}

	if (inode && superfork_is_tty_dev(inode)) {
		act->fd = fd;
		act->type = FD_ACT_CLONE;
		act->file = get_file(file);
		act->hint = "tty_path_backed";
		return fd + 1;
	}

	if (inode && (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
		      S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode))) {
		act->fd = fd;
		act->type = FD_ACT_CLONE;
		act->file = get_file(file);
		act->hint = "path_backed";
		return fd + 1;
	}

	{
		struct eventfd_ctx *efd = eventfd_ctx_fileget(file);
		if (!IS_ERR(efd)) {
			eventfd_ctx_put(efd);
			act->fd = fd;
			act->type = FD_ACT_EVENTFD_NEW;
			act->file = get_file(file);
			act->hint = "eventfd";
			return fd + 1;
		}
	}

	if (signalfd_file_is_signalfd(file)) {
		act->fd = fd;
		act->type = FD_ACT_SIGNALFD_NEW;
		act->file = get_file(file);
		act->hint = "signalfd";
		return fd + 1;
	}

	act->fd = fd;
	act->type = FD_ACT_UNSUPPORTED;
	act->file = get_file(file);
	act->hint = inode ? "inode_other" : "anon_or_special";
	return fd + 1;
}

static bool superfork_path_matches_root_prefix(const char *path, const char *root)
{
	size_t root_len;

	if (!path || !root || !root[0])
		return false;

	root_len = strlen(root);
	if (!root_len || strncmp(path, root, root_len))
		return false;

	if (path[root_len] == '\0')
		return true;

	if (root[root_len - 1] == '/')
		return true;

	return path[root_len] == '/';
}

static char *superfork_remap_snapshot_path(const char *src_path,
					 const char *src_bundle_path,
					 const char *dst_bundle_path)
{
	const char *suffix;
	size_t src_len;
	size_t dst_len;
	bool dst_has_slash;
	bool suffix_has_slash;

	if (!src_path)
		return NULL;

	if (!dst_bundle_path || !dst_bundle_path[0] ||
	    !superfork_path_matches_root_prefix(src_path, src_bundle_path))
		return kstrdup(src_path, GFP_KERNEL);

	src_len = strlen(src_bundle_path);
	suffix = src_path + src_len;
	dst_len = strlen(dst_bundle_path);

	if (!suffix[0])
		return kstrdup(dst_bundle_path, GFP_KERNEL);

	dst_has_slash = dst_len && dst_bundle_path[dst_len - 1] == '/';
	suffix_has_slash = suffix[0] == '/';

	if (dst_has_slash && suffix_has_slash)
		return kasprintf(GFP_KERNEL, "%s%s", dst_bundle_path, suffix + 1);

	if (!dst_has_slash && !suffix_has_slash)
		return kasprintf(GFP_KERNEL, "%s/%s", dst_bundle_path, suffix);

	return kasprintf(GFP_KERNEL, "%s%s", dst_bundle_path, suffix);
}

static struct file *superfork_open_path_backed_clone(unsigned int fd,
					      struct file *src_file,
					      const char *src_bundle_path,
					      const char *dst_bundle_path)
{
	char *path_buf = NULL;
	char *src_path = NULL;
	char *dst_path = NULL;
	char *resolved = NULL;
	struct file *clone = NULL;
	loff_t src_pos;
	int open_flags;
	int ret;

	path_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!path_buf)
		return ERR_PTR(-ENOMEM);

	resolved = d_path(&src_file->f_path, path_buf, PAGE_SIZE);
	if (IS_ERR(resolved)) {
		ret = PTR_ERR(resolved);
		pr_err("superfork: failed to resolve path for fd %u: %d\n", fd, ret);
		goto out_err;
	}

	src_path = kstrdup(resolved, GFP_KERNEL);
	if (!src_path) {
		ret = -ENOMEM;
		goto out_err;
	}

	dst_path = superfork_remap_snapshot_path(src_path, src_bundle_path,
						 dst_bundle_path);
	if (!dst_path) {
		ret = -ENOMEM;
		goto out_err;
	}

	open_flags = src_file->f_flags &
		~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_TMPFILE);

	clone = filp_open(dst_path, open_flags, 0);
	if (IS_ERR(clone)) {
		ret = PTR_ERR(clone);
		pr_err("superfork: failed to reopen fd %u from '%s' to '%s': %d\n",
		       fd, src_path, dst_path, ret);
		clone = NULL;
		goto out_err;
	}

	spin_lock(&src_file->f_lock);
	src_pos = src_file->f_pos;
	spin_unlock(&src_file->f_lock);

	spin_lock(&clone->f_lock);
	clone->f_pos = src_pos;
	spin_unlock(&clone->f_lock);

	kfree(dst_path);
	kfree(src_path);
	kfree(path_buf);
	return clone;

out_err:
	kfree(dst_path);
	kfree(src_path);
	kfree(path_buf);
	return ERR_PTR(ret);
}

/*
 * superfork_create_unix_server - create a new listening Unix socket at a
 * remapped path for the clone.
 *
 * The source socket is a path-bound, listening Unix domain socket (SOCK_STREAM
 * or SOCK_SEQPACKET).  We cannot dup it because that would share the same
 * underlying socket and accept queue with the source VM.  Instead we create a
 * fresh socket, bind it to the destination bundle path, and start listening —
 * giving the clone its own independent endpoint.
 *
 * The caller is responsible for installing the returned file into the clone's
 * fd table.
 */
static struct file *superfork_create_unix_server(struct file *src_file,
						  const char *src_bundle_path,
						  const char *dst_bundle_path)
{
	struct unix_sock *u = unix_get_socket(src_file);
	struct socket *sock = src_file->private_data;
	struct socket *new_sock = NULL;
	struct sockaddr_un addr = {};
	char *src_path = NULL;
	char *dst_path = NULL;
	struct file *new_file = NULL;
	int sock_type;
	int backlog;
	int ret;

	if (!u || !u->addr)
		return ERR_PTR(-EINVAL);

	/* Get the socket type (SOCK_STREAM or SOCK_SEQPACKET) */
	sock_type = sock ? sock->type : SOCK_STREAM;

	src_path = kstrndup(u->addr->name[0].sun_path,
			    sizeof(u->addr->name[0].sun_path), GFP_KERNEL);
	if (!src_path) {
		ret = -ENOMEM;
		goto out_err;
	}

	dst_path = superfork_remap_snapshot_path(src_path, src_bundle_path,
						  dst_bundle_path);
	if (!dst_path) {
		ret = -ENOMEM;
		goto out_err;
	}

	if (strlen(dst_path) >= UNIX_PATH_MAX) {
		pr_err("superfork: remapped unix socket path too long: %s\n", dst_path);
		ret = -ENAMETOOLONG;
		goto out_err;
	}

	/*
	 * The btrfs snapshot copies the source socket inode into the clone
	 * directory.  Remove it so bind() can create a fresh one.
	 */
	{
		struct path stale;

		if (kern_path(dst_path, 0, &stale) == 0) {
			inode_lock(d_inode(stale.dentry->d_parent));
			vfs_unlink(mnt_idmap(stale.mnt),
				   d_inode(stale.dentry->d_parent),
				   stale.dentry, NULL);
			inode_unlock(d_inode(stale.dentry->d_parent));
			path_put(&stale);
		}
	}

	ret = sock_create_kern(&init_net, AF_UNIX, sock_type, 0, &new_sock);
	if (ret < 0) {
		pr_err("superfork: failed to create unix socket: %d\n", ret);
		goto out_err;
	}

	addr.sun_family = AF_UNIX;
	strscpy(addr.sun_path, dst_path, sizeof(addr.sun_path));

	ret = kernel_bind(new_sock,
			  (struct sockaddr *)&addr,
			  sizeof(sa_family_t) + strlen(addr.sun_path) + 1);
	if (ret < 0) {
		pr_err("superfork: failed to bind unix socket to %s: %d\n",
		       dst_path, ret);
		goto out_err;
	}

	/* Use the same backlog as a typical QEMU chardev server (128) */
	backlog = 128;
	ret = kernel_listen(new_sock, backlog);
	if (ret < 0) {
		pr_err("superfork: failed to listen on unix socket %s: %d\n",
		       dst_path, ret);
		goto out_err;
	}

	/*
	 * sock_alloc_file() hands off ownership of new_sock to the returned
	 * file; new_sock must not be released separately after this point.
	 */
	new_file = sock_alloc_file(new_sock,
				   src_file->f_flags & ~(O_CREAT | O_EXCL | O_TRUNC),
				   NULL);
	if (IS_ERR(new_file)) {
		ret = PTR_ERR(new_file);
		pr_err("superfork: sock_alloc_file failed for unix socket: %d\n", ret);
		new_sock = NULL; /* sock_alloc_file already called sock_release on error */
		new_file = NULL;
		goto out_err;
	}

	kfree(dst_path);
	kfree(src_path);
	return new_file;

out_err:
	if (new_sock)
		sock_release(new_sock);
	kfree(dst_path);
	kfree(src_path);
	return ERR_PTR(ret);
}

#ifdef CONFIG_KVM
static int superfork_clone_kvm_memslots(struct kvm *src_kvm, struct kvm *dst_kvm)
{
	int as_id;
	int ret = 0;

	if (!src_kvm || !dst_kvm)
		return -EINVAL;

	mutex_lock(&src_kvm->slots_lock);
	for (as_id = 0; as_id < kvm_arch_nr_memslot_as_ids(src_kvm); as_id++) {
		struct kvm_memslots *slots = __kvm_memslots(src_kvm, as_id);
		struct kvm_memory_slot *slot;
		int bkt;

		kvm_for_each_memslot(slot, bkt, slots) {
			struct kvm_userspace_memory_region2 region;

			if (!slot->npages)
				continue;

			if (slot->flags & KVM_MEM_GUEST_MEMFD) {
				ret = -EOPNOTSUPP;
				goto out_unlock;
			}

			memset(&region, 0, sizeof(region));
			region.slot = ((u32)as_id << 16) | (u16)slot->id;
			region.flags = slot->flags;
			region.guest_phys_addr = (u64)slot->base_gfn << PAGE_SHIFT;
			region.memory_size = (u64)slot->npages << PAGE_SHIFT;
			region.userspace_addr = slot->userspace_addr;

			ret = kvm_superfork_set_memslot(dst_kvm, &region);
			if (ret)
				goto out_unlock;
		}
	}

out_unlock:
	mutex_unlock(&src_kvm->slots_lock);
	return ret;
}

static int superfork_clone_kvm_vm_fd(struct files_struct *files,
				      unsigned int fd,
				      struct file *src_file,
				      struct mm_struct *new_mm,
				      struct tgid_clone_entry *tgid_entry)
{
	struct file *new_vm_file = NULL;
	struct kvm *src_kvm;
	struct kvm *new_kvm = NULL;
	unsigned long vm_type;
	int ret;

	if (!new_mm)
		return -EINVAL;

	src_kvm = src_file->private_data;
	if (!src_kvm)
		return -EINVAL;

	vm_type = kvm_superfork_get_vm_type(src_kvm);

	ret = kvm_superfork_create_vm_for_mm(new_mm, vm_type,
					     &new_vm_file, &new_kvm);
	if (ret)
		return ret;

	ret = superfork_clone_kvm_memslots(src_kvm, new_kvm);
	if (ret)
		goto out_put_new_vm;

	ret = kvm_superfork_prepare_vm(new_kvm, src_kvm);
	if (ret)
		goto out_put_new_vm;

	ret = superfork_replace_file_at(files, fd, new_vm_file);
	if (ret)
		goto out_put_new_vm;

	if (tgid_entry && tgid_entry->kvm_vm_count < SF_MAX_KVM_VMS_PER_PROC) {
		int idx = tgid_entry->kvm_vm_count++;
		tgid_entry->kvm_vms[idx].src_fd = fd;
		tgid_entry->kvm_vms[idx].src_vm_file = NULL;
		tgid_entry->kvm_vms[idx].new_vm_file = NULL;
		tgid_entry->kvm_vms[idx].src_kvm = src_kvm;
		tgid_entry->kvm_vms[idx].new_kvm = new_kvm;
	}

	/* Drop the temporary reference held by wrapper call sites. */
	fput(new_vm_file);
	return 0;

out_put_new_vm:
	fput(new_vm_file);
	return ret;
}

static struct sf_kvm_vm_map *superfork_find_kvm_vm_map(struct tgid_clone_entry *tgid_entry,
							struct kvm *src_kvm)
{
	int i;

	if (!tgid_entry || !src_kvm)
		return NULL;

	for (i = 0; i < tgid_entry->kvm_vm_count; i++) {
		if (tgid_entry->kvm_vms[i].src_kvm == src_kvm)
			return &tgid_entry->kvm_vms[i];
	}

	return NULL;
}

static void superfork_remap_kvm_vcpu_vma(struct mm_struct *new_mm,
					  struct file *src_file,
					  struct file *new_vcpu_file)
{
	VMA_ITERATOR(vmi, new_mm, 0);
	struct vm_area_struct *vma;
	int found = 0;

	int scanned = 0;

	mmap_write_lock(new_mm);
	for_each_vma(vmi, vma) {
		scanned++;
		if (vma->vm_file == src_file) {
			vma_set_file(vma, new_vcpu_file);
			zap_vma_pages(vma);
			found++;
		}
	}
	mmap_write_unlock(new_mm);

	pr_info("superfork: kvm_run VMA remap: scanned=%d found=%d (src=%p new=%p)\n",
		scanned, found, src_file, new_vcpu_file);
	if (!found)
		pr_warn("superfork: kvm_run VMA not found for vcpu fd remap\n");
}

static int superfork_clone_kvm_vcpu_fd(struct files_struct *files,
					unsigned int fd,
					struct file *src_file,
					struct mm_struct *new_mm,
					struct tgid_clone_entry *tgid_entry)
{
	struct kvm_vcpu *src_vcpu;
	struct sf_kvm_vm_map *vm_map;
	struct file *new_vcpu_file = NULL;
	struct kvm_vcpu *new_vcpu = NULL;
	int ret;

	if (!tgid_entry)
		return -EINVAL;

	src_vcpu = src_file->private_data;
	if (!src_vcpu || !src_vcpu->kvm)
		return -EINVAL;

	vm_map = superfork_find_kvm_vm_map(tgid_entry, src_vcpu->kvm);
	if (!vm_map || !vm_map->new_kvm)
		return -ENOENT;

	ret = kvm_superfork_create_vcpu(vm_map->new_kvm, src_vcpu->vcpu_id,
					&new_vcpu_file, &new_vcpu);
	if (ret)
		return ret;

	/* Tell QEMU the ioctl was interrupted by a signal so it loops back
	 * and re-issues KVM_RUN rather than treating exit_reason=0 as an
	 * unknown hardware exit and stopping the VM. */
	new_vcpu->run->exit_reason = KVM_EXIT_INTR;

	ret = kvm_superfork_copy_vcpu_state(new_vcpu, src_vcpu);
	if (ret)
		goto out_put_new_vcpu;

	ret = superfork_replace_file_at(files, fd, new_vcpu_file);
	if (ret)
		goto out_put_new_vcpu;

	pr_info("superfork: vcpu fd %u clone done, new_mm=%p src_file=%p new_vcpu_file=%p\n",
		fd, new_mm, src_file, new_vcpu_file);
	if (new_mm)
		superfork_remap_kvm_vcpu_vma(new_mm, src_file, new_vcpu_file);
	else
		pr_warn("superfork: skipping VMA remap: new_mm is NULL\n");

	if (vm_map->vcpu_count < SF_MAX_KVM_VCPUS_PER_VM) {
		int idx = vm_map->vcpu_count++;
		vm_map->vcpus[idx].src_fd = fd;
		vm_map->vcpus[idx].vcpu_id = src_vcpu->vcpu_id;
		vm_map->vcpus[idx].new_file = NULL;
		vm_map->vcpus[idx].new_vcpu = new_vcpu;
	}

	fput(new_vcpu_file);
	return 0;

out_put_new_vcpu:
	fput(new_vcpu_file);
	return ret;
}
#endif /* CONFIG_KVM */

struct sf_fd_alias_entry {
	struct file *src_file;
	struct file *new_file;
};

struct sf_fd_alias_map {
	struct sf_fd_alias_entry *entries;
	unsigned int count;
	unsigned int capacity;
};

static int superfork_fd_alias_count_cb(const void *arg, struct file *file,
					      unsigned int fd)
{
	unsigned int *count = (unsigned int *)arg;

	(void)file;
	(*count)++;
	return fd + 1;
}

static int superfork_fd_alias_map_init(struct files_struct *files,
				       struct sf_fd_alias_map *map)
{
	unsigned int start = 0;
	unsigned int count = 0;
	int ret;

	memset(map, 0, sizeof(*map));

	for (;;) {
		ret = iterate_fd(files, start, superfork_fd_alias_count_cb, &count);
		if (ret == 0)
			break;
		start = ret;
	}

	if (!count)
		return 0;

	map->entries = kcalloc(count, sizeof(*map->entries), GFP_KERNEL);
	if (!map->entries)
		return -ENOMEM;

	map->capacity = count;
	return 0;
}

static void superfork_fd_alias_map_release(struct sf_fd_alias_map *map)
{
	unsigned int i;

	for (i = 0; i < map->count; i++)
		fput(map->entries[i].new_file);

	kfree(map->entries);
	map->entries = NULL;
	map->count = 0;
	map->capacity = 0;
}

static struct file *superfork_fd_alias_map_find(const struct sf_fd_alias_map *map,
						 const struct file *src_file)
{
	unsigned int i;

	for (i = 0; i < map->count; i++) {
		if (map->entries[i].src_file == src_file)
			return get_file(map->entries[i].new_file);
	}

	return NULL;
}

#ifdef CONFIG_KVM
/*
 * Stats fds (KVM_GET_STATS_FD) share ->private_data with their parent VM or
 * vCPU file. Recover the cloned parent by matching private_data against the
 * already-populated alias map. Relies on the fact that iterate_fd() visits
 * slots in ascending order and qemu always creates the parent fd before its
 * stats fd; if that invariant is ever broken the caller will see -ENOENT and
 * refuse to clone rather than corrupt state.
 */
static struct file *superfork_fd_alias_map_find_kvm_parent(
					const struct sf_fd_alias_map *map,
					void *private_data,
					bool want_vm)
{
	unsigned int i;

	for (i = 0; i < map->count; i++) {
		struct file *src = map->entries[i].src_file;

		if (!src || src->private_data != private_data)
			continue;
		if (want_vm && !file_is_kvm(src))
			continue;
		if (!want_vm && !file_is_kvm_vcpu(src))
			continue;
		return get_file(map->entries[i].new_file);
	}

	return NULL;
}
#endif /* CONFIG_KVM */

static int superfork_fd_alias_map_add(struct sf_fd_alias_map *map,
				      struct file *src_file,
				      struct file *new_file)
{
	if (map->count >= map->capacity)
		return -E2BIG;

	map->entries[map->count].src_file = src_file;
	map->entries[map->count].new_file = get_file(new_file);
	map->count++;
	return 0;
}

static int superfork_sanitize_inherited_fds(struct files_struct *files,
					    const char *src_bundle_path,
					    const char *dst_bundle_path,
					    struct mm_struct *new_mm,
					    struct tgid_clone_entry *tgid_entry)
{
	struct sf_fd_alias_map alias_map;
	unsigned int start = 0;
	int ret = 0;
	bool warned_kvm_phase4 = false;

	ret = superfork_fd_alias_map_init(files, &alias_map);
	if (ret < 0)
		return ret;

	for (;;) {
		struct fd_action action = { .type = FD_ACT_NONE };
		struct file *replacement = NULL;
		bool replacement_needs_install = false;
		bool replacement_should_track = false;
		bool replacement_from_map = false;

		ret = iterate_fd(files, start, superfork_collect_fd_action, &action);
		if (ret == 0)
			break;

		if (action.type == FD_ACT_NONE) {
			start = ret;
			continue;
		}

		if (action.type != FD_ACT_UNSUPPORTED) {
			replacement = superfork_fd_alias_map_find(&alias_map, action.file);
			if (replacement) {
				replacement_needs_install = true;
				replacement_from_map = true;
				pr_info("superfork: fd %u type=%d hit alias map, skipping clone\n",
					action.fd, action.type);
			}
		}

		if (!replacement_from_map) {
			switch (action.type) {
			case FD_ACT_UNSUPPORTED:
				pr_err("superfork: unsupported fd type at slot %u (%s)\n",
				       action.fd, action.hint ? action.hint : "unknown");
				ret = -EOPNOTSUPP;
				fput(action.file);
				goto out;
#ifdef CONFIG_KVM
			case FD_ACT_KVM_VM: {
				int rc = superfork_clone_kvm_vm_fd(files, action.fd, action.file,
							       new_mm, tgid_entry);
				if (rc < 0) {
					pr_err("superfork: failed to clone KVM VM fd %u: %d\n",
					       action.fd, rc);
					ret = rc;
					fput(action.file);
					goto out;
				}

				replacement = superfork_get_file_at(files, action.fd);
				if (!replacement) {
					ret = -EBADF;
					pr_err("superfork: cannot read back KVM VM clone at fd %u\n",
					       action.fd);
					fput(action.file);
					goto out;
				}
				replacement_should_track = true;
				break;
			}
			case FD_ACT_KVM_VCPU: {
				int rc;
				pr_info("superfork: processing KVM_VCPU fd %u file=%p new_mm=%p\n",
					action.fd, action.file, new_mm);
				rc = superfork_clone_kvm_vcpu_fd(files, action.fd, action.file,
								 new_mm, tgid_entry);
				if (rc < 0) {
					pr_err("superfork: failed to clone KVM vCPU fd %u: %d\n",
					       action.fd, rc);
					ret = rc;
					fput(action.file);
					goto out;
				}

				replacement = superfork_get_file_at(files, action.fd);
				if (!replacement) {
					ret = -EBADF;
					pr_err("superfork: cannot read back KVM vCPU clone at fd %u\n",
					       action.fd);
					fput(action.file);
					goto out;
				}
				replacement_should_track = true;

				if (!warned_kvm_phase4) {
					pr_info("superfork: KVM VM/vCPU fd cloning is enabled (phase 5)\n");
					warned_kvm_phase4 = true;
				}
				break;
			}
			case FD_ACT_KVM_VM_STATS: {
				struct file *parent_new;
				struct kvm *new_kvm;
				struct file *new_file;

				parent_new = superfork_fd_alias_map_find_kvm_parent(
					&alias_map, action.file->private_data, true);
				if (!parent_new) {
					pr_err("superfork: kvm_vm_stats fd %u has no cloned parent VM\n",
					       action.fd);
					ret = -ENOENT;
					fput(action.file);
					goto out;
				}

				new_kvm = parent_new->private_data;
				new_file = kvm_vm_stats_file_create(new_kvm);
				fput(parent_new);
				if (IS_ERR(new_file)) {
					ret = PTR_ERR(new_file);
					pr_err("superfork: kvm_vm_stats clone failed at fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement = new_file;
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
			case FD_ACT_KVM_VCPU_STATS: {
				struct file *parent_new;
				struct kvm_vcpu *new_vcpu;
				struct file *new_file;

				parent_new = superfork_fd_alias_map_find_kvm_parent(
					&alias_map, action.file->private_data, false);
				if (!parent_new) {
					pr_err("superfork: kvm_vcpu_stats fd %u has no cloned parent vCPU\n",
					       action.fd);
					ret = -ENOENT;
					fput(action.file);
					goto out;
				}

				new_vcpu = parent_new->private_data;
				new_file = kvm_vcpu_stats_file_create(new_vcpu);
				fput(parent_new);
				if (IS_ERR(new_file)) {
					ret = PTR_ERR(new_file);
					pr_err("superfork: kvm_vcpu_stats clone failed at fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement = new_file;
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
#endif /* CONFIG_KVM */
			case FD_ACT_SIGNALFD_NEW: {
				sigset_t mask;
				struct file *new_file;
				int sfd_flags = SFD_CLOEXEC;

				signalfd_ctx_sigmask(action.file, &mask);
				/*
				 * signalfd stores an inverted mask internally.
				 * signalfd_file_create() expects user-visible (non-inverted) mask.
				 */
				signotset(&mask);
				if (action.file->f_flags & O_NONBLOCK)
					sfd_flags |= SFD_NONBLOCK;

				new_file = signalfd_file_create(&mask, sfd_flags);
				if (IS_ERR(new_file)) {
					ret = PTR_ERR(new_file);
					fput(action.file);
					goto out;
				}
				replacement = new_file;
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
			case FD_ACT_CLONE:
				replacement = superfork_open_path_backed_clone(action.fd,
								      action.file,
								      src_bundle_path,
								      dst_bundle_path);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to reopen path-backed fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			case FD_ACT_UNIX_SOCK_SERVER:
				replacement = superfork_create_unix_server(action.file,
									   src_bundle_path,
									   dst_bundle_path);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to recreate unix server socket at fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			case FD_ACT_EVENTFD_NEW: {
				struct eventfd_ctx *src_ctx = eventfd_ctx_fileget(action.file);
				u64 count = 0;
				unsigned int flags = 0;

				if (!IS_ERR(src_ctx)) {
					count = eventfd_ctx_count(src_ctx);
					flags = eventfd_ctx_flags(src_ctx);
					eventfd_ctx_put(src_ctx);
				}

				replacement = eventfd_file_create(count, flags);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					fput(action.file);
					goto out;
				}
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
			case FD_ACT_NONE:
				break;
			}
		}

		if (replacement_needs_install) {
			int rc = superfork_replace_file_at(files, action.fd, replacement);
			if (rc < 0) {
				pr_err("superfork: failed to replace fd %u: %d\n", action.fd, rc);
				ret = rc;
				fput(replacement);
				fput(action.file);
				goto out;
			}
		}

		if (replacement_should_track) {
			int rc = superfork_fd_alias_map_add(&alias_map, action.file,
							  replacement);
			if (rc < 0) {
				pr_err("superfork: alias map add failed for fd %u: %d\n",
				       action.fd, rc);
				ret = rc;
				fput(replacement);
				fput(action.file);
				goto out;
			}
		}

		if (replacement)
				fput(replacement);

		fput(action.file);
		start = ret;
	}

out:
	superfork_fd_alias_map_release(&alias_map);

#ifdef CONFIG_KVM
	if (ret >= 0 && tgid_entry) {
		int i;

		for (i = 0; i < tgid_entry->kvm_vm_count; i++) {
			struct sf_kvm_vm_map *vm = &tgid_entry->kvm_vms[i];
			int rc;

			if (!vm->new_kvm || !vm->src_kvm)
				continue;

			rc = kvm_superfork_finalize_vm(vm->new_kvm, vm->src_kvm);
			if (rc < 0) {
				pr_err("superfork: finalize_vm failed: %d\n", rc);
				ret = rc;
				break;
			}
		}
	}
#endif

	return ret < 0 ? ret : 0;
}

struct sf_fd_snapshot_entry {
	unsigned int fd;
	struct file *file;
};

struct sf_fd_snapshot {
	struct sf_fd_snapshot_entry *entries;
	unsigned int count;
	unsigned int capacity;
};

static int superfork_fd_snapshot_count_cb(const void *arg, struct file *file,
					 unsigned int fd)
{
	unsigned int *count = (unsigned int *)arg;

	(void)file;
	(*count)++;
	return fd + 1;
}

static int superfork_fd_snapshot_collect_cb(const void *arg, struct file *file,
					   unsigned int fd)
{
	struct sf_fd_snapshot *snap = (struct sf_fd_snapshot *)arg;

	if (snap->count >= snap->capacity)
		return 0;

	snap->entries[snap->count].fd = fd;
	snap->entries[snap->count].file = get_file(file);
	snap->count++;
	return fd + 1;
}

static void superfork_fd_snapshot_release(struct sf_fd_snapshot *snap)
{
	unsigned int i;

	for (i = 0; i < snap->count; i++)
		fput(snap->entries[i].file);

	kfree(snap->entries);
	snap->entries = NULL;
	snap->count = 0;
	snap->capacity = 0;
}

static int superfork_build_fd_snapshot(struct files_struct *files,
				      struct sf_fd_snapshot *snap)
{
	unsigned int start = 0;
	unsigned int count = 0;
	int ret;

	memset(snap, 0, sizeof(*snap));

	for (;;) {
		ret = iterate_fd(files, start, superfork_fd_snapshot_count_cb, &count);
		if (ret == 0)
			break;
		start = ret;
	}

	if (!count)
		return 0;

	snap->entries = kcalloc(count, sizeof(*snap->entries), GFP_KERNEL);
	if (!snap->entries)
		return -ENOMEM;

	snap->capacity = count;
	snap->count = 0;
	start = 0;

	for (;;) {
		ret = iterate_fd(files, start, superfork_fd_snapshot_collect_cb, snap);
		if (ret == 0)
			break;
		start = ret;
	}

	if (snap->count != snap->capacity) {
		pr_err("superfork: fd snapshot changed while collecting (%u != %u)\n",
		       snap->count, snap->capacity);
		superfork_fd_snapshot_release(snap);
		return -EAGAIN;
	}

	return 0;
}

static int superfork_verify_fd_snapshot_pair(const struct sf_fd_snapshot *old_snap,
					      const struct sf_fd_snapshot *new_snap,
					      pid_t src_pid,
					      pid_t new_pid)
{
	unsigned int i, j;

	if (old_snap->count != new_snap->count) {
		pr_err("superfork: fd count mismatch src_pid=%d new_pid=%d src=%u new=%u\n",
		       src_pid, new_pid, old_snap->count, new_snap->count);
		return -EUCLEAN;
	}

	for (i = 0; i < old_snap->count; i++) {
		const struct sf_fd_snapshot_entry *old_e = &old_snap->entries[i];
		const struct sf_fd_snapshot_entry *new_e = &new_snap->entries[i];

		if (old_e->fd != new_e->fd) {
			pr_err("superfork: fd slot mismatch src_pid=%d new_pid=%d idx=%u src_fd=%u new_fd=%u\n",
			       src_pid, new_pid, i, old_e->fd, new_e->fd);
			return -EUCLEAN;
		}

		if (old_e->file == new_e->file) {
			pr_err("superfork: source file pointer leaked into clone src_pid=%d new_pid=%d fd=%u ptr=%p\n",
			       src_pid, new_pid, old_e->fd, old_e->file);
			return -EUCLEAN;
		}

		for (j = 0; j < i; j++) {
			bool old_alias = old_e->file == old_snap->entries[j].file;
			bool new_alias = new_e->file == new_snap->entries[j].file;

			if (old_alias != new_alias) {
				pr_err("superfork: fd alias mismatch src_pid=%d new_pid=%d fd=%u peer_fd=%u\n",
				       src_pid, new_pid, old_e->fd, old_snap->entries[j].fd);
				return -EUCLEAN;
			}
		}
	}

	return 0;
}

static int superfork_verify_files_pair(struct files_struct *oldf,
				      struct files_struct *newf,
				      pid_t src_pid,
				      pid_t new_pid)
{
	struct sf_fd_snapshot old_snap;
	struct sf_fd_snapshot new_snap;
	int ret;

	ret = superfork_build_fd_snapshot(oldf, &old_snap);
	if (ret < 0)
		return ret;

	ret = superfork_build_fd_snapshot(newf, &new_snap);
	if (ret < 0) {
		superfork_fd_snapshot_release(&old_snap);
		return ret;
	}

	ret = superfork_verify_fd_snapshot_pair(&old_snap, &new_snap,
					      src_pid, new_pid);

	superfork_fd_snapshot_release(&new_snap);
	superfork_fd_snapshot_release(&old_snap);
	return ret;
}

struct sf_seen_files_pair {
	struct files_struct *oldf;
	struct files_struct *newf;
};

static int superfork_verify_cloned_fds(struct container_clone_ctx *ctx)
{
	struct sf_seen_files_pair *seen_pairs;
	int seen_count = 0;
	int ret = 0;

	seen_pairs = kcalloc(MAX_CLONE_TASKS, sizeof(*seen_pairs), GFP_KERNEL);
	if (!seen_pairs)
		return -ENOMEM;

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct files_struct *oldf;
		struct files_struct *newf;
		bool already_verified = false;
		int j;

		if (!task->old_task || !task->new_task)
			continue;

		oldf = READ_ONCE(task->old_task->files);
		newf = READ_ONCE(task->new_task->files);

		if (!oldf && !newf)
			continue;

		if (!oldf || !newf) {
			pr_err("superfork: files_struct presence mismatch src_pid=%d new_pid=%d\n",
			       task->old_task->pid, task->new_task->pid);
			ret = -EUCLEAN;
			goto out;
		}

		if (oldf == newf) {
			pr_err("superfork: files_struct still shared with source src_pid=%d new_pid=%d\n",
			       task->old_task->pid, task->new_task->pid);
			ret = -EUCLEAN;
			goto out;
		}

		for (j = 0; j < seen_count; j++) {
			if (seen_pairs[j].oldf == oldf || seen_pairs[j].newf == newf) {
				if (seen_pairs[j].oldf != oldf || seen_pairs[j].newf != newf) {
					pr_err("superfork: files_struct pairing mismatch src_pid=%d new_pid=%d\n",
					       task->old_task->pid, task->new_task->pid);
					ret = -EUCLEAN;
					goto out;
				}
				already_verified = true;
				break;
			}
		}

		if (already_verified)
			continue;

		ret = superfork_verify_files_pair(oldf, newf,
						 task->old_task->pid,
						 task->new_task->pid);
		if (ret < 0)
			goto out;

		if (seen_count >= MAX_CLONE_TASKS) {
			ret = -E2BIG;
			goto out;
		}

		seen_pairs[seen_count].oldf = oldf;
		seen_pairs[seen_count].newf = newf;
		seen_count++;
	}

out:
	kfree(seen_pairs);
	return ret;
}

static struct files_struct *superfork_dup_files_for_container(struct files_struct *oldf,
					      const char *src_bundle_path,
					      const char *dst_bundle_path,
					      struct mm_struct *new_mm,
					      struct tgid_clone_entry *tgid_entry)
{
	struct files_struct *newf;
	int ret;

	newf = dup_fd(oldf, NULL);
	if (IS_ERR(newf))
		return newf;

	ret = superfork_sanitize_inherited_fds(newf, src_bundle_path,
					      dst_bundle_path,
					      new_mm, tgid_entry);
	if (ret < 0) {
		put_files_struct(newf);
		return ERR_PTR(ret);
	}

	return newf;
}

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

/*
 * superfork_copy_sighand - Copy signal handlers from source task
 * Mirrors copy_sighand() but copies from src_task
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
 * superfork_copy_signal - Copy signal struct from source task
 * Mirrors copy_signal() but initializes from src_task
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
 * superfork_copy_mm - Copy memory from source task
 * Mirrors copy_mm() but copies from src_task
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
 
/*
 * superfork_copy_seccomp - Copy seccomp state from source task
 * Mirrors copy_seccomp()
 *
 * seccomp - secure computing mode, restricts syscalls that processes can do.
 */
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

static int sf_read_clone_u32(struct mm_struct *mm, void __user *addr, u32 *val)
{
    struct page *page;
    void *kaddr;
    int ret;

    mmap_read_lock(mm);
    ret = get_user_pages_remote(mm, (unsigned long)addr, 1,
                                FOLL_FORCE, &page, NULL);
    mmap_read_unlock(mm);

    if (ret < 0)
        return ret;
    if (ret == 0)
        return -EFAULT;

    kaddr = kmap_local_page(page);
    *val = *(u32 *)((char *)kaddr + offset_in_page(addr));
    kunmap_local(kaddr);
    put_page(page);
    return 0;
}

static int sf_write_clone_u32(struct mm_struct *mm, void __user *addr, u32 val)
{
    struct page *page;
    void *kaddr;
    int ret;

    mmap_read_lock(mm);
    ret = get_user_pages_remote(mm, (unsigned long)addr, 1,
                                FOLL_FORCE | FOLL_WRITE, &page, NULL);
    mmap_read_unlock(mm);

    if (ret < 0)
        return ret;
    if (ret == 0)
        return -EFAULT;

    kaddr = kmap_local_page(page);
    *(u32 *)((char *)kaddr + offset_in_page(addr)) = val;
    kunmap_local(kaddr);
    set_page_dirty_lock(page);
    put_page(page);
    return 0;
}

static int sf_read_clone_ulong(struct mm_struct *mm, void __user *addr, unsigned long *val)
{
    struct page *page;
    void *kaddr;
    int ret;

    mmap_read_lock(mm);
    ret = get_user_pages_remote(mm, (unsigned long)addr, 1,
                                FOLL_FORCE, &page, NULL);
    mmap_read_unlock(mm);

    if (ret < 0)
        return ret;
    if (ret == 0)
        return -EFAULT;

    kaddr = kmap_local_page(page);
    *val = *(unsigned long *)((char *)kaddr + offset_in_page(addr));
    kunmap_local(kaddr);
    put_page(page);
    return 0;
}

static __maybe_unused void superfork_patch_robust_futexes(struct task_struct *p,
										   struct task_struct *src_task)
{
#ifdef CONFIG_FUTEX
    struct robust_list_head __user *head;
    struct robust_list __user *entry;
    unsigned int limit = ROBUST_LIST_LIMIT;
    pid_t src_tid = src_task->pid;
    pid_t new_tid = p->pid;
    struct mm_struct *clone_mm;
    long futex_offset;
    unsigned long entry_ulong;

    head = src_task->robust_list;
    if (!head)
        return;

    clone_mm = p->mm;
    if (!clone_mm)
        return;

    pr_debug("superfork: patching robust futexes src_tid=%d -> new_tid=%d head=%p\n",
             src_tid, new_tid, head);

    /*
     * All reads and writes go through get_user_pages_remote() on clone_mm.
     * No mm switching needed — GUP walks the page table in software and
     * maps the result via kmap_local, bypassing TTBR0 entirely.
     * FOLL_WRITE on writes triggers CoW into the clone's private pages.
     * Source is frozen so there are no concurrent writers; plain store
     * is sufficient without cmpxchg.
     */

    /* Read futex_offset — constant for this robust_list_head */
    if (sf_read_clone_ulong(clone_mm,
                            (void __user *)&head->futex_offset,
                            (unsigned long *)&futex_offset)) {
        pr_warn("superfork: failed to read futex_offset\n");
        return;
    }

    if (futex_offset > 0 || futex_offset < -4096) {
        pr_warn("superfork: suspicious futex_offset=%ld\n", futex_offset);
        return;
    }

    /* Read head->list.next to get first entry */
    if (sf_read_clone_ulong(clone_mm,
                            (void __user *)&head->list.next,
                            &entry_ulong)) {
        pr_warn("superfork: failed to read robust_list head->list.next\n");
        return;
    }
    entry = (struct robust_list __user *)entry_ulong;

    while (entry != (struct robust_list __user *)&head->list) {
        unsigned long next_ulong;
        struct robust_list __user *next_entry;
        void __user *futex_uaddr;
        u32 curval, newval;

        if (!limit--) {
            pr_warn("superfork: robust list too long for src_tid=%d\n", src_tid);
            break;
        }

        if (sf_read_clone_ulong(clone_mm,
                                (void __user *)&entry->next,
                                &next_ulong))
            break;

        next_entry = (struct robust_list __user *)next_ulong;

        if ((unsigned long)next_entry < PAGE_SIZE ||
            (unsigned long)next_entry >= TASK_SIZE)
            break;

        futex_uaddr = (void __user *)((char __user *)entry + futex_offset);

        if (sf_read_clone_u32(clone_mm, futex_uaddr, &curval))
            goto next;

        if ((curval & FUTEX_TID_MASK) == (u32)src_tid) {
            newval = (curval & ~FUTEX_TID_MASK) | (u32)new_tid;
            if (sf_write_clone_u32(clone_mm, futex_uaddr, newval))
                pr_warn("superfork: failed to patch futex at %p\n", futex_uaddr);
            else
                pr_debug("superfork: patched futex %p: 0x%x -> 0x%x\n",
                         futex_uaddr, curval, newval);
        }

next:
        entry = next_entry;
    }

    /* Handle list_op_pending — may not be on the list yet */
    {
        unsigned long pending_ulong;
        struct robust_list __user *pending;
        void __user *futex_uaddr;
        u32 curval, newval;

        if (sf_read_clone_ulong(clone_mm,
                                (void __user *)&head->list_op_pending,
                                &pending_ulong))
            return;

        pending = (struct robust_list __user *)pending_ulong;

        if (!pending ||
            (unsigned long)pending < PAGE_SIZE ||
            (unsigned long)pending >= TASK_SIZE)
            return;

        futex_uaddr = (void __user *)((char __user *)pending + futex_offset);

        if (sf_read_clone_u32(clone_mm, futex_uaddr, &curval))
            return;

        if ((curval & FUTEX_TID_MASK) == (u32)src_tid) {
            newval = (curval & ~FUTEX_TID_MASK) | (u32)new_tid;
            if (sf_write_clone_u32(clone_mm, futex_uaddr, newval))
                pr_warn("superfork: failed to patch list_op_pending futex\n");
            else
                pr_debug("superfork: patched list_op_pending: 0x%x -> 0x%x\n",
                         curval, newval);
        }
    }
#endif
}

/*
 * superfork_copy_process - Create a new task as a copy of a frozen task
 *
 * This is the core function that mirrors copy_process() from fork.c.
 * It creates a new task_struct that will resume execution at the same
 * point as the frozen source task.
 *
 * @ctx: Container clone context
 * @src_task: The frozen source task to clone
 * @tgid_entry: Thread group entry for sharing resources
 * @is_leader: Whether this is a thread group leader
 *
 * Returns the new task on success, or ERR_PTR on failure.
 */
static struct task_struct *superfork_copy_process(
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


/*
 * superfork_attach_task - Attach a cloned task to the system
 *
 * This function makes the cloned task visible to the rest of the system
 * by attaching it to the tasklist and pid hashes. Mirrors the attachment
 * portion of copy_process().
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
 * superfork_attach_tasks - Attach all cloned tasks to the system
 *
 * This rebuilds the process tree structure by:
 * 1. Setting parent pointers based on the original container's hierarchy
 * 2. Adding leaders to parent's children list
 * 3. Adding threads to their leader's thread group
 *
 * The new tree should be INDEPENDENT of the original:
 * - Container root processes get 'current' as parent
 * - Child processes get their corresponding new parent
 */
static void superfork_attach_tasks(struct container_clone_ctx *ctx)
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

static void superfork_post_fork(struct container_clone_ctx *ctx)
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

static int superfork_seed_cgroup_membership(struct container_clone_ctx *ctx)
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

static void superfork_wake_tasks(struct container_clone_ctx *ctx)
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
 * Attach a fresh sf_vcpu_snap to every thread in every target tgid. Called
 * before cgroup_freeze_sync so the snap is in place when KVM's block loop
 * notices the freezer signal. Non-vCPU threads never trigger the snapshot
 * hook and their snap stays valid=false — harmless.
 */
static void superfork_free_vcpu_snaps(pid_t *kpids, size_t count);

static int superfork_alloc_vcpu_snaps(pid_t *kpids, size_t count)
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

/*
 * Detach and free sf_vcpu_snap from every thread in the target tgids.
 * Idempotent: safe to call on error paths even if alloc partially ran.
 */
static void superfork_free_vcpu_snaps(pid_t *kpids, size_t count)
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
#define SUPERFORK_FREEZE_WAIT_MS 5

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
static int wait_source_tasks_frozen(pid_t *kpids, size_t count)
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

static void release_collected_tasks(struct container_clone_ctx *ctx);

static int collect_frozen_tasks(struct container_clone_ctx *ctx,
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


static void superfork_adjust_netns_isolation(struct container_clone_ctx *ctx)
{
	ctx->isolate_netns = true;
}

static void release_collected_tasks(struct container_clone_ctx *ctx)
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
	pr_info("superfork: fd verification passed\n");

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

/*
 * superfork_destroy_container - Destroy a partially created container
 *
 * @ctx: Container clone context
 *
 * Kills all cloned tasks and cleans up resources
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

	pr_info("superfork: starting with %zu pids\n", count);

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
	pr_info("superfork: config copied, src_cgroup='%s'\n", config->src_cgroup_path);
	pr_info("superfork: container_clone_ctx size=%zu bytes\n", sizeof(*ctx));

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
	pr_info("superfork: pids copied, first=%d\n", kpids[0]);

	/*
	 * Resolve the scratch/destination cgroup that will be frozen. The
	 * source tasks are migrated into this cgroup before freezing so the
	 * freeze affects only the tasks being cloned, not whatever cgroup
	 * the caller happened to live in (e.g. a shared user session scope).
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
