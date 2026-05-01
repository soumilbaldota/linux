// SPDX-License-Identifier: GPL-2.0
/*
 * superfork/fd.c — file-descriptor handling for container cloning.
 *
 * Covers: fd classification, path remapping, KVM fd dispatch, Unix socket
 * server recreation, eventfd/signalfd recreation, fd alias deduplication,
 * post-clone fd verification, and the top-level dup_files_for_container().
 */

#include <linux/eventfd.h>
#include <linux/signalfd.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/magic.h>
#include <linux/eventpoll.h>
#include <linux/inotify.h>
#include <linux/io_uring.h>
#include <linux/kvm_host.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/pid.h>
#include <linux/pidfs.h>
#include <linux/pipe_fs_i.h>
#include <linux/security.h>
#include <linux/shmem_fs.h>
#include <linux/slab.h>
#include <linux/superfork.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <net/af_unix.h>
#include <uapi/linux/pidfd.h>
#include <uapi/linux/un.h>
#include "internal.h"

struct sock *unix_peer_get(struct sock *sk);

struct sf_placeholder_peer {
	struct list_head list;
	struct pid *owner_tgid;
	struct file *file;
};

static LIST_HEAD(sf_placeholder_peers);
static DEFINE_SPINLOCK(sf_placeholder_peers_lock);

static bool superfork_is_allowed_shared_source_file(
				const struct container_clone_ctx *ctx,
				const struct file *file)
{
	unsigned int i;

	if (!ctx || !file)
		return false;

	for (i = 0; i < ctx->allowed_shared_file_count; i++) {
		if (ctx->allowed_shared_files[i] == file)
			return true;
	}

	return false;
}

static int superfork_grow_allowed_shared_files(struct container_clone_ctx *ctx)
{
	struct file **files;
	unsigned int old_cap;
	unsigned int new_cap;

	if (!ctx)
		return -EINVAL;

	old_cap = ctx->allowed_shared_file_capacity;
	new_cap = old_cap ? old_cap * 2 : 16;
	if (new_cap <= old_cap)
		return -EOVERFLOW;

	files = krealloc_array(ctx->allowed_shared_files, new_cap,
			       sizeof(*ctx->allowed_shared_files), GFP_KERNEL);
	if (!files)
		return -ENOMEM;

	memset(files + old_cap, 0,
	       (new_cap - old_cap) * sizeof(*ctx->allowed_shared_files));
	ctx->allowed_shared_files = files;
	ctx->allowed_shared_file_capacity = new_cap;
	return 0;
}

static int superfork_allow_shared_source_file(struct container_clone_ctx *ctx,
					      struct file *file)
{
	unsigned int i;
	int ret;

	if (!ctx || !file)
		return -EINVAL;

	for (i = 0; i < ctx->allowed_shared_file_count; i++) {
		if (ctx->allowed_shared_files[i] == file)
			return 0;
	}

	if (ctx->allowed_shared_file_count >= ctx->allowed_shared_file_capacity) {
		ret = superfork_grow_allowed_shared_files(ctx);
		if (ret < 0)
			return ret;
	}

	ctx->allowed_shared_files[ctx->allowed_shared_file_count++] = get_file(file);
	return 0;
}

void superfork_release_allowed_shared_files(struct container_clone_ctx *ctx)
{
	unsigned int i;

	if (!ctx)
		return;

	for (i = 0; i < ctx->allowed_shared_file_count; i++) {
		if (ctx->allowed_shared_files[i]) {
			fput(ctx->allowed_shared_files[i]);
			ctx->allowed_shared_files[i] = NULL;
		}
	}

	kfree(ctx->allowed_shared_files);
	ctx->allowed_shared_files = NULL;
	ctx->allowed_shared_file_count = 0;
	ctx->allowed_shared_file_capacity = 0;
}

/* --- fd classification -------------------------------------------------- */

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

static bool superfork_is_path_backed_fifo(const struct file *file)
{
	const struct inode *inode;

	if (!file)
		return false;

	inode = file_inode(file);
	if (!inode || !S_ISFIFO(inode->i_mode) || !inode->i_sb)
		return false;

	/*
	 * pipefs-backed FIFOs are anonymous pipe endpoints.  Keep treating
	 * those as pipes so internal pairs can be recreated and external ones
	 * can still fall back to placeholder handling.
	 */
	return inode->i_sb->s_magic != PIPEFS_MAGIC;
}

int superfork_replace_file_at(struct files_struct *files, unsigned int fd,
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
	FD_ACT_DEVNULL,		/* replace with /dev/null (FIFO, pipe, connected socket, pidfd) */
	FD_ACT_PROCFS_REOPEN,	/* placeholder /dev/null now; reopen procfs path post-attach */
	FD_ACT_EVENTFD_NEW,
	FD_ACT_SIGNALFD_NEW,
	FD_ACT_EPOLL_NEW,	/* create fresh empty epoll instance */
	FD_ACT_INOTIFY_NEW,	/* create fresh empty inotify instance */
	FD_ACT_IOURING_NEW,	/* create fresh io_uring ring matching source geometry */
	FD_ACT_PIDFD_REOPEN,	/* placeholder /dev/null now; reopen pidfd post-attach */
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
	int sock_family;
	int sock_type;
	int sock_state;
	unsigned int pipe_readers;
	unsigned int pipe_writers;
	unsigned int pipe_files;
	unsigned int pipe_bufs;
	unsigned int pipe_max_usage;
	bool pipe_watch_queue;
	/* FD_ACT_PROCFS_REOPEN: d_path result relative to procfs root. */
	char procfs_path[256];
	/* FD_ACT_PIDFD_REOPEN */
	pid_t pidfd_old_pid;
	unsigned int pidfd_flags;
};

struct sf_unix_sock_edge {
	struct file *src_file[2];
	struct file *new_file[2];
	pid_t src_tgid[2];
	unsigned int src_fd[2];
};

struct sf_pipe_edge {
	struct file *src_file[2];
	struct file *new_file[2];
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
	const char *dname = file->f_path.dentry ?
			    file->f_path.dentry->d_name.name : NULL;

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
		struct socket *sock = sock_from_file(file);
		struct unix_sock *u = unix_get_socket(file);

		act->sock_family = sock && sock->sk ? sock->sk->sk_family : 0;
		act->sock_type = sock ? sock->type : 0;
		act->sock_state = sock && sock->sk ? sock->sk->sk_state : 0;

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

		/*
		 * All other sockets (connected TCP/UDP, connected Unix, vsock,
		 * etc.) cannot be cloned — the connection endpoints live outside
		 * the process group being forked.  Replace with /dev/null so the
		 * clone starts without stale fds; userspace reconnects as needed.
		 */
		act->fd = fd;
		act->type = FD_ACT_DEVNULL;
		act->file = get_file(file);
		act->hint = "socket";
		return fd + 1;
	}

	if (inode && S_ISFIFO(inode->i_mode)) {
		struct pipe_inode_info *pipe = get_pipe_info(file, false);

		if (pipe) {
			act->pipe_readers = READ_ONCE(pipe->readers);
			act->pipe_writers = READ_ONCE(pipe->writers);
			act->pipe_files = READ_ONCE(pipe->files);
			act->pipe_bufs = pipe_buf_usage(pipe);
			act->pipe_max_usage = READ_ONCE(pipe->max_usage);
			act->pipe_watch_queue = pipe_has_watch_queue(pipe);
		}

		/*
		 * Named FIFOs and anonymous pipes cannot be cloned: a pipe
		 * connects two endpoints and cloning only one side produces a
		 * broken pair.  Replace with /dev/null; the clone's stdio/log
		 * streams are re-established at the container management layer.
		 */
		act->fd = fd;
		act->type = FD_ACT_DEVNULL;
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

	if (inode && S_ISCHR(inode->i_mode) && dname &&
	    !strcmp(dname, "vhost-vsock")) {
		/*
		 * /dev/vhost-vsock is not a plain reopenable char device.
		 * The live transport state sits behind file->private_data and
		 * its source-side worker thread is now excluded from the clone
		 * set. Reopening the path produces a fresh, unconfigured vhost
		 * endpoint that looks valid to userspace but has none of the
		 * original backend state. Until there is a real restore path,
		 * treat it as a dead placeholder.
		 */
		act->fd = fd;
		act->type = FD_ACT_DEVNULL;
		act->file = get_file(file);
		act->hint = "vhost_vsock";
		return fd + 1;
	}

	/*
	 * pidfs inodes are S_IFREG (prepare_anon_dentry sets i_mode = S_IFREG
	 * before pidfs_init_inode ORs in S_IRWXU), so they would fall into the
	 * path_backed FD_ACT_CLONE branch below.  d_path on a pidfs file
	 * returns "anon_inode:[pidfd]" via pidfs_dname — not a real path —
	 * causing filp_open to fail with ENOENT.  Detect pidfds here and
	 * replace with /dev/null before the S_ISREG check.
	 */
	if (!IS_ERR(pidfd_pid(file))) {
		struct pid *pid = pidfd_pid(file);

		act->fd = fd;
		act->type = FD_ACT_PIDFD_REOPEN;
		act->file = get_file(file);
		act->hint = "[pidfd]";
		act->pidfd_old_pid = pid_nr(pid);
		act->pidfd_flags = file->f_flags & (PIDFD_NONBLOCK | PIDFD_THREAD);
		return fd + 1;
	}

	/*
	 * procfs files (e.g. /proc/<pid>/mountinfo, /proc/<pid>/fd/<n>) live on a
	 * virtual filesystem whose vfsmount belongs to the source task's mount
	 * namespace.  When superfork calls d_path() from the host context, that
	 * vfsmount is not visible in the host's mount namespace, so d_path()
	 * returns a path relative to the procfs root (e.g. "/2684/mountinfo")
	 * instead of the absolute path.  filp_open on that path fails with ENOENT.
	 *
	 * Install /dev/null as a placeholder now and record the procfs-relative
	 * d_path() result so superfork_reopen_procfs_fds() can reopen it once the
	 * clone has a stable PID in the tasklist.
	 */
	if (inode && inode->i_sb->s_magic == PROC_SUPER_MAGIC) {
		char *path_buf;
		char *resolved;
		ssize_t copied = -EINVAL;

		act->fd = fd;
		act->file = get_file(file);
		act->hint = "procfs";

		path_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (path_buf) {
			resolved = d_path(&file->f_path, path_buf, PAGE_SIZE);
			if (!IS_ERR(resolved))
				copied = strscpy(act->procfs_path, resolved,
						 sizeof(act->procfs_path));
			kfree(path_buf);
		}

		if (copied >= 0) {
			act->type = FD_ACT_PROCFS_REOPEN;
		} else {
			act->type = FD_ACT_UNSUPPORTED;
			act->hint = "procfs_unresolved";
		}
		return fd + 1;
	}

	/*
	 * anon_inode users present as S_IFREG internally, so classify any
	 * exported special cases before the generic path-backed reopen path.
	 */
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

#ifdef CONFIG_IO_URING
	if (io_is_uring_fops(file)) {
		/*
		 * io_uring: create a fresh ring with the same sq/cq geometry as
		 * the source.  The source process is frozen, so SQEs/CQEs are
		 * zero — the clone gets a clean ring ready for new submissions.
		 */
		act->fd = fd;
		act->type = FD_ACT_IOURING_NEW;
		act->file = get_file(file);
		act->hint = "io_uring";
		return fd + 1;
	}
#endif

	/*
	 * Remaining anon-inode types: detected by dentry name since their fops
	 * are not exported.  These names are stable kernel ABI strings.
	 */
	{
		if (dname && !strcmp(dname, "[eventpoll]")) {
			/*
			 * epoll: create a fresh empty instance.  The clone's
			 * event loop starts with no watched fds; userspace adds
			 * them as new connections arrive.
			 */
			act->fd = fd;
			act->type = FD_ACT_EPOLL_NEW;
			act->file = get_file(file);
			act->hint = "epoll";
			return fd + 1;
		}

		if (dname && !strcmp(dname, "inotify")) {
			/* inotify: create a fresh empty instance. */
			act->fd = fd;
			act->type = FD_ACT_INOTIFY_NEW;
			act->file = get_file(file);
			act->hint = "inotify";
			return fd + 1;
		}

		if (dname && !strcmp(dname, "[userfaultfd]")) {
			/*
			 * userfaultfd: the ctx is bound to the source mm and
			 * cannot be cloned.  Replace with /dev/null; the clone's
			 * QEMU opens a fresh userfaultfd when it first touches
			 * memory that needs it.
			 */
			act->fd = fd;
			act->type = FD_ACT_DEVNULL;
			act->file = get_file(file);
			act->hint = "userfaultfd";
			return fd + 1;
		}
	}

	if (inode && (S_ISREG(inode->i_mode) || S_ISDIR(inode->i_mode) ||
		      S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
		      S_ISLNK(inode->i_mode))) {
		act->fd = fd;
		act->type = FD_ACT_CLONE;
		act->file = get_file(file);
		act->hint = "path_backed";
		return fd + 1;
	}

	act->fd = fd;
	act->type = FD_ACT_UNSUPPORTED;
	act->file = get_file(file);
	act->hint = dname ? dname : (inode ? "inode_other" : "anon_or_special");
	return fd + 1;
}



static struct sf_unix_sock_edge *superfork_find_internal_unix_edge(
					struct container_clone_ctx *ctx,
					const struct file *src_file,
					unsigned int *slot)
{
	unsigned int i;

	if (!ctx)
		return NULL;

	for (i = 0; i < ctx->unix_sock_edge_count; i++) {
		struct sf_unix_sock_edge *edge = &ctx->unix_sock_edges[i];

		if (edge->src_file[0] == src_file) {
			if (slot)
				*slot = 0;
			return edge;
		}
		if (edge->src_file[1] == src_file) {
			if (slot)
				*slot = 1;
			return edge;
		}
	}

	return NULL;
}

static int superfork_grow_internal_unix_edges(struct container_clone_ctx *ctx)
{
	struct sf_unix_sock_edge *edges;
	unsigned int old_cap = ctx->unix_sock_edge_capacity;
	unsigned int new_cap = old_cap ? old_cap * 2 : 8;

	if (new_cap <= old_cap)
		return -EOVERFLOW;

	edges = krealloc_array(ctx->unix_sock_edges, new_cap,
			       sizeof(*ctx->unix_sock_edges), GFP_KERNEL);
	if (!edges)
		return -ENOMEM;

	memset(edges + old_cap, 0,
	       (new_cap - old_cap) * sizeof(*ctx->unix_sock_edges));
	ctx->unix_sock_edges = edges;
	ctx->unix_sock_edge_capacity = new_cap;
	return 0;
}

struct sf_unix_sock_candidate {
	struct sock  *sk;
	struct file  *file; /* holds a get_file() reference */
	pid_t owner_tgid;
	unsigned int fd;
};

static int superfork_add_internal_unix_edge(
				struct container_clone_ctx *ctx,
				const struct sf_unix_sock_candidate *src_a,
				const struct sf_unix_sock_candidate *src_b)
{
	struct sf_unix_sock_edge *edge;
	int ret;

	if (superfork_find_internal_unix_edge(ctx, src_a->file, NULL))
		return 0;

	if (ctx->unix_sock_edge_count >= ctx->unix_sock_edge_capacity) {
		ret = superfork_grow_internal_unix_edges(ctx);
		if (ret < 0)
			return ret;
	}

	edge = &ctx->unix_sock_edges[ctx->unix_sock_edge_count++];
	edge->src_file[0] = get_file(src_a->file);
	edge->src_file[1] = get_file(src_b->file);
	edge->src_tgid[0] = src_a->owner_tgid;
	edge->src_tgid[1] = src_b->owner_tgid;
	edge->src_fd[0] = src_a->fd;
	edge->src_fd[1] = src_b->fd;
	pr_info("superfork: internal unix edge add idx=%u left=%d fd=%u file=%p right=%d fd=%u file=%p\n",
		ctx->unix_sock_edge_count - 1,
		edge->src_tgid[0], edge->src_fd[0], edge->src_file[0],
		edge->src_tgid[1], edge->src_fd[1], edge->src_file[1]);
	return 0;
}

/*
 * Two-pass internal Unix edge collection.
 *
 * We cannot call iterate_fd() from within an iterate_fd() callback because
 * iterate_fd() holds files->file_lock across the callback.  If the peer task
 * shares the same files_struct (threads) or the search loops back to the same
 * task, the inner iterate_fd() spins forever on the same spinlock.
 *
 * Fix: pass 1 collects all connected-Unix-socket (sk, file) pairs from every
 * leader task into a flat array — no nesting, no peer lookup under the lock.
 * Pass 2 matches each entry's peer sk against the array without any iterate_fd.
 */

struct sf_unix_prescan_ctx {
	struct sf_unix_sock_candidate *cands;
	unsigned int count;
	unsigned int capacity;
	pid_t owner_tgid;
	int ret;
};

static int superfork_prescan_unix_cb(const void *arg, struct file *file,
				     unsigned int fd)
{
	struct sf_unix_prescan_ctx *scan = (struct sf_unix_prescan_ctx *)arg;
	struct unix_sock *u;
	struct socket *sock;

	sock = sock_from_file(file);
	if (!sock || (sock->type != SOCK_STREAM &&
		      sock->type != SOCK_SEQPACKET &&
		      sock->type != SOCK_DGRAM))
		return fd + 1;

	u = unix_get_socket(file);
	if (!u || u->sk.sk_state == TCP_LISTEN || !unix_peer(&u->sk))
		return fd + 1;

	if (scan->count >= scan->capacity) {
		unsigned int new_cap = scan->capacity ? scan->capacity * 2 : 16;
		struct sf_unix_sock_candidate *arr;

		arr = krealloc_array(scan->cands, new_cap, sizeof(*arr),
				     GFP_ATOMIC);
		if (!arr) {
			scan->ret = -ENOMEM;
			return 0;
		}
		scan->cands    = arr;
		scan->capacity = new_cap;
	}

	scan->cands[scan->count].sk   = &u->sk;
	scan->cands[scan->count].file = get_file(file);
	scan->cands[scan->count].owner_tgid = scan->owner_tgid;
	scan->cands[scan->count].fd = fd;
	scan->count++;
	return fd + 1;
}

void superfork_release_internal_unix_edges(struct container_clone_ctx *ctx);

int superfork_prepare_internal_unix_edges(struct container_clone_ctx *ctx)
{
	struct sf_unix_prescan_ctx scan = {};
	unsigned int i, j;
	int ret = 0;

	superfork_release_internal_unix_edges(ctx);

	/* Pass 1: collect all connected Unix socket (sk, file) pairs from every
	 * leader task.  Each iterate_fd call is independent; no nesting. */
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct files_struct *files;
		unsigned int start = 0;

		if (!task->is_leader || !task->old_task)
			continue;

		files = READ_ONCE(task->old_task->files);
		if (!files)
			continue;
		scan.owner_tgid = task->old_tgid;

		for (;;) {
			ret = iterate_fd(files, start, superfork_prescan_unix_cb,
					 &scan);
			if (scan.ret < 0) {
				ret = scan.ret;
				goto out_free_scan;
			}
			if (ret == 0)
				break;
			start = ret;
		}
	}

	/* Pass 2: for each candidate, find its peer in the pre-collected array
	 * by matching sk pointers — no iterate_fd, no lock contention. */
	for (i = 0; i < scan.count; i++) {
		struct sock *peer_sk;
		const struct sf_unix_sock_candidate *peer_cand = NULL;

		if (superfork_find_internal_unix_edge(ctx, scan.cands[i].file, NULL))
			continue;

		peer_sk = unix_peer_get(scan.cands[i].sk);
		if (!peer_sk)
			continue;

		for (j = 0; j < scan.count; j++) {
			if (j == i)
				continue;
			if (scan.cands[j].sk == peer_sk) {
				peer_cand = &scan.cands[j];
				break;
			}
		}
		sock_put(peer_sk);

		if (!peer_cand)
			continue;

		ret = superfork_add_internal_unix_edge(ctx, &scan.cands[i],
						       peer_cand);
		if (ret < 0)
			goto out_free_scan;
	}

out_free_scan:
	for (i = 0; i < scan.count; i++)
		fput(scan.cands[i].file);
	kfree(scan.cands);

	if (ret < 0)
		superfork_release_internal_unix_edges(ctx);
	return ret;
}

void superfork_release_internal_unix_edges(struct container_clone_ctx *ctx)
{
	unsigned int i;

	if (!ctx)
		return;

	for (i = 0; i < ctx->unix_sock_edge_count; i++) {
		struct sf_unix_sock_edge *edge = &ctx->unix_sock_edges[i];

		if (edge->src_file[0]) {
			fput(edge->src_file[0]);
			edge->src_file[0] = NULL;
		}
		if (edge->src_file[1]) {
			fput(edge->src_file[1]);
			edge->src_file[1] = NULL;
		}
		if (edge->new_file[0]) {
			fput(edge->new_file[0]);
			edge->new_file[0] = NULL;
		}
		if (edge->new_file[1]) {
			fput(edge->new_file[1]);
			edge->new_file[1] = NULL;
		}
	}

	kfree(ctx->unix_sock_edges);
	ctx->unix_sock_edges = NULL;
	ctx->unix_sock_edge_count = 0;
	ctx->unix_sock_edge_capacity = 0;
}

static struct sf_pipe_edge *superfork_find_internal_pipe_edge(
					struct container_clone_ctx *ctx,
					const struct file *src_file,
					unsigned int *slot)
{
	unsigned int i;

	if (!ctx)
		return NULL;

	for (i = 0; i < ctx->pipe_edge_count; i++) {
		struct sf_pipe_edge *edge = &ctx->pipe_edges[i];

		if (edge->src_file[0] == src_file) {
			if (slot)
				*slot = 0;
			return edge;
		}
		if (edge->src_file[1] == src_file) {
			if (slot)
				*slot = 1;
			return edge;
		}
	}

	return NULL;
}

static int superfork_grow_internal_pipe_edges(struct container_clone_ctx *ctx)
{
	struct sf_pipe_edge *edges;
	unsigned int old_cap = ctx->pipe_edge_capacity;
	unsigned int new_cap = old_cap ? old_cap * 2 : 8;

	if (new_cap <= old_cap)
		return -EOVERFLOW;

	edges = krealloc_array(ctx->pipe_edges, new_cap, sizeof(*ctx->pipe_edges),
			       GFP_KERNEL);
	if (!edges)
		return -ENOMEM;

	memset(edges + old_cap, 0, (new_cap - old_cap) * sizeof(*ctx->pipe_edges));
	ctx->pipe_edges = edges;
	ctx->pipe_edge_capacity = new_cap;
	return 0;
}

static int superfork_add_internal_pipe_edge(struct container_clone_ctx *ctx,
					    struct file *src_a,
					    struct file *src_b)
{
	struct sf_pipe_edge *edge;
	struct file *reader = src_a;
	struct file *writer = src_b;
	int ret;

	if (superfork_find_internal_pipe_edge(ctx, src_a, NULL))
		return 0;

	if ((reader->f_mode & FMODE_WRITE) && !(reader->f_mode & FMODE_READ)) {
		reader = src_b;
		writer = src_a;
	}

	if (!(reader->f_mode & FMODE_READ) || !(writer->f_mode & FMODE_WRITE))
		return 0;

	if (ctx->pipe_edge_count >= ctx->pipe_edge_capacity) {
		ret = superfork_grow_internal_pipe_edges(ctx);
		if (ret < 0)
			return ret;
	}

	edge = &ctx->pipe_edges[ctx->pipe_edge_count++];
	edge->src_file[0] = get_file(reader);
	edge->src_file[1] = get_file(writer);
	return 0;
}

struct sf_pipe_candidate {
	struct pipe_inode_info *pipe;
	struct file *file;
};

struct sf_pipe_prescan_ctx {
	struct sf_pipe_candidate *cands;
	unsigned int count;
	unsigned int capacity;
	int ret;
};

static int superfork_prescan_pipe_cb(const void *arg, struct file *file,
				     unsigned int fd)
{
	struct sf_pipe_prescan_ctx *scan = (struct sf_pipe_prescan_ctx *)arg;
	struct pipe_inode_info *pipe;

	pipe = get_pipe_info(file, false);
	if (!pipe)
		return fd + 1;

	if (!(file->f_mode & (FMODE_READ | FMODE_WRITE)))
		return fd + 1;

	if (scan->count >= scan->capacity) {
		unsigned int new_cap = scan->capacity ? scan->capacity * 2 : 16;
		struct sf_pipe_candidate *arr;

		arr = krealloc_array(scan->cands, new_cap, sizeof(*arr),
				     GFP_ATOMIC);
		if (!arr) {
			scan->ret = -ENOMEM;
			return 0;
		}
		scan->cands = arr;
		scan->capacity = new_cap;
	}

	scan->cands[scan->count].pipe = pipe;
	scan->cands[scan->count].file = get_file(file);
	scan->count++;
	return fd + 1;
}

int superfork_prepare_internal_pipe_edges(struct container_clone_ctx *ctx)
{
	struct sf_pipe_prescan_ctx scan = {};
	unsigned int i, j;
	int ret = 0;

	superfork_release_internal_pipe_edges(ctx);

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct files_struct *files;
		unsigned int start = 0;

		if (!task->is_leader || !task->old_task)
			continue;

		files = READ_ONCE(task->old_task->files);
		if (!files)
			continue;

		for (;;) {
			ret = iterate_fd(files, start, superfork_prescan_pipe_cb, &scan);
			if (scan.ret < 0) {
				ret = scan.ret;
				goto out_free_scan;
			}
			if (ret == 0)
				break;
			start = ret;
		}
	}

	for (i = 0; i < scan.count; i++) {
		struct file *peer_file = NULL;

		if (superfork_find_internal_pipe_edge(ctx, scan.cands[i].file, NULL))
			continue;

		for (j = 0; j < scan.count; j++) {
			if (j == i)
				continue;
			if (scan.cands[j].pipe != scan.cands[i].pipe)
				continue;
			if (!!(scan.cands[j].file->f_mode & FMODE_READ) ==
			    !!(scan.cands[i].file->f_mode & FMODE_READ))
				continue;
			peer_file = scan.cands[j].file;
			break;
		}

		if (!peer_file)
			continue;

		ret = superfork_add_internal_pipe_edge(ctx, scan.cands[i].file,
						       peer_file);
		if (ret < 0)
			goto out_free_scan;
	}

out_free_scan:
	for (i = 0; i < scan.count; i++)
		fput(scan.cands[i].file);
	kfree(scan.cands);

	if (ret < 0)
		superfork_release_internal_pipe_edges(ctx);
	return ret;
}

void superfork_release_internal_pipe_edges(struct container_clone_ctx *ctx)
{
	unsigned int i;

	if (!ctx)
		return;

	for (i = 0; i < ctx->pipe_edge_count; i++) {
		struct sf_pipe_edge *edge = &ctx->pipe_edges[i];

		if (edge->src_file[0]) {
			fput(edge->src_file[0]);
			edge->src_file[0] = NULL;
		}
		if (edge->src_file[1]) {
			fput(edge->src_file[1]);
			edge->src_file[1] = NULL;
		}
		if (edge->new_file[0]) {
			fput(edge->new_file[0]);
			edge->new_file[0] = NULL;
		}
		if (edge->new_file[1]) {
			fput(edge->new_file[1]);
			edge->new_file[1] = NULL;
		}
	}

	kfree(ctx->pipe_edges);
	ctx->pipe_edges = NULL;
	ctx->pipe_edge_count = 0;
	ctx->pipe_edge_capacity = 0;
}

static int superfork_parse_pid_component(const char *s, const char **endp,
					 pid_t *pid)
{
	unsigned int nr = 0;
	const char *p = s;

	if (!p || *p < '0' || *p > '9')
		return -EINVAL;

	for (; *p && *p != '/'; p++) {
		if (*p < '0' || *p > '9')
			return -EINVAL;
		nr = (nr * 10) + (*p - '0');
	}

	if (endp)
		*endp = p;
	if (pid)
		*pid = (pid_t)nr;

	return 0;
}

static int superfork_parse_procfs_reopen_path(const char *path, pid_t *old_pid,
					      const char **relpath)
{
	const char *end;
	int ret;

	if (!path || path[0] != '/')
		return -EINVAL;

	/*
	 * d_path() on procfs returns a path relative to the procfs root.
	 * Accept both pid-scoped entries ("/1234/mountinfo") and procfs-global
	 * ones such as "/" or "/sys/kernel/...".
	 */
	if (path[1] == '\0') {
		*old_pid = 0;
		*relpath = path + 1;
		return 0;
	}

	if (path[1] < '0' || path[1] > '9') {
		*old_pid = 0;
		*relpath = path + 1;
		return 0;
	}

	ret = superfork_parse_pid_component(path + 1, &end, old_pid);
	if (ret < 0)
		return ret;

	if (*end == '\0') {
		*relpath = end;
		return 0;
	}

	if (*end != '/')
		return -EINVAL;

	*relpath = end + 1;
	return 0;
}

/* --- path remapping ----------------------------------------------------- */

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

static const char *superfork_bundle_src_path(const struct container_config *config,
						 unsigned int idx)
{
	if (!config)
		return NULL;

	if (idx == 0)
		return config->root_src_bundle_path;

	idx--;
	if (idx >= config->aux_bundle_count)
		return NULL;

	return config->aux_src_bundle_paths[idx];
}

static const char *superfork_bundle_dst_path(const struct container_config *config,
						 unsigned int idx)
{
	if (!config)
		return NULL;

	if (idx == 0)
		return config->root_dst_bundle_path;

	idx--;
	if (idx >= config->aux_bundle_count)
		return NULL;

	return config->aux_dst_bundle_paths[idx];
}

static unsigned int superfork_bundle_count(const struct container_config *config)
{
	return config ? config->aux_bundle_count + 1 : 0;
}

static const char *superfork_find_run_component(const char *path)
{
	const char *run;

	if (!path)
		return NULL;
	if (!strcmp(path, "/run") || !strncmp(path, "/run/", 5))
		return path;

	run = strstr(path, "/run/");
	if (run)
		return run;

	return NULL;
}

static char *superfork_remap_live_run_path(const char *src_path,
					   const struct container_config *config)
{
	const char *best_src_run = NULL, *best_dst_run = NULL, *suffix;
	size_t best_src_len = 0, dst_len;
	bool dst_has_slash, suffix_has_slash;
	unsigned int i;

	if (!src_path || !config)
		return NULL;
	if (strcmp(src_path, "/run") && strncmp(src_path, "/run/", 5))
		return NULL;

	for (i = 0; i < superfork_bundle_count(config); i++) {
		const char *src_root = superfork_bundle_src_path(config, i);
		const char *dst_root = superfork_bundle_dst_path(config, i);
		const char *src_run;
		const char *dst_run;
		size_t src_len;

		if (!src_root || !src_root[0] || !dst_root || !dst_root[0])
			continue;

		src_run = superfork_find_run_component(src_root);
		dst_run = superfork_find_run_component(dst_root);
		if (!src_run || !dst_run ||
		    !superfork_path_matches_root_prefix(src_path, src_run))
			continue;

		src_len = strlen(src_run);
		if (src_len < best_src_len)
			continue;

		best_src_run = src_run;
		best_dst_run = dst_run;
		best_src_len = src_len;
	}

	if (!best_src_run || !best_dst_run)
		return NULL;

	suffix = src_path + best_src_len;
	dst_len = strlen(best_dst_run);

	if (!suffix[0])
		return kstrdup(best_dst_run, GFP_KERNEL);

	dst_has_slash = dst_len && best_dst_run[dst_len - 1] == '/';
	suffix_has_slash = suffix[0] == '/';

	if (dst_has_slash && suffix_has_slash)
		return kasprintf(GFP_KERNEL, "%s%s", best_dst_run, suffix + 1);

	if (!dst_has_slash && !suffix_has_slash)
		return kasprintf(GFP_KERNEL, "%s/%s", best_dst_run, suffix);

	return kasprintf(GFP_KERNEL, "%s%s", best_dst_run, suffix);
}

static char *superfork_short_run_socket_path(const char *src_path,
					     const struct container_config *config)
{
	const char *root;
	const char *run;
	const char *tag;
	const char *base;
	size_t prefix_len;
	size_t tag_len;

	if (!src_path || !config || !config->root_dst_bundle_path[0])
		return NULL;

	root = config->root_dst_bundle_path;
	run = superfork_find_run_component(root);
	if (!run)
		return NULL;

	prefix_len = run - root;
	while (prefix_len > 0 && root[prefix_len - 1] == '/')
		prefix_len--;
	if (!prefix_len)
		return NULL;

	tag = root + prefix_len;
	while (tag > root && tag[-1] != '/')
		tag--;
	tag_len = prefix_len - (tag - root);
	if (!tag_len)
		return NULL;

	/*
	 * Keep the synthesized runtime socket path under UNIX_PATH_MAX even
	 * when the original basename is a 64-byte containerd socket ID.
	 */
	tag_len = min(tag_len, (size_t)24);

	base = strrchr(src_path, '/');
	base = base ? base + 1 : src_path;

	return kasprintf(GFP_KERNEL, "/run/sf-%.*s-%s",
			 (int)tag_len, tag, base);
}

static char *superfork_remap_snapshot_path(const char *src_path,
					   const struct container_config *config)
{
	const char *best_dst = NULL, *suffix;
	size_t best_src_len = 0, dst_len;
	bool dst_has_slash, suffix_has_slash;
	unsigned int i;

	if (!src_path)
		return NULL;

	for (i = 0; i < superfork_bundle_count(config); i++) {
		const char *src_bundle_path = superfork_bundle_src_path(config, i);
		const char *dst_bundle_path = superfork_bundle_dst_path(config, i);
		size_t src_len;

		if (!src_bundle_path || !src_bundle_path[0] ||
		    !dst_bundle_path || !dst_bundle_path[0] ||
		    !superfork_path_matches_root_prefix(src_path, src_bundle_path))
			continue;

		src_len = strlen(src_bundle_path);
		if (src_len < best_src_len)
			continue;

		best_dst = dst_bundle_path;
		best_src_len = src_len;
	}

	if (!best_dst) {
		char *run_path = superfork_remap_live_run_path(src_path, config);

		if (run_path)
			return run_path;
		return kstrdup(src_path, GFP_KERNEL);
	}

	suffix = src_path + best_src_len;
	dst_len = strlen(best_dst);

	if (!suffix[0])
		return kstrdup(best_dst, GFP_KERNEL);

	dst_has_slash = dst_len && best_dst[dst_len - 1] == '/';
	suffix_has_slash = suffix[0] == '/';

	if (dst_has_slash && suffix_has_slash)
		return kasprintf(GFP_KERNEL, "%s%s", best_dst, suffix + 1);

	if (!dst_has_slash && !suffix_has_slash)
		return kasprintf(GFP_KERNEL, "%s/%s", best_dst, suffix);

	return kasprintf(GFP_KERNEL, "%s%s", best_dst, suffix);
}

/*
 * superfork_clone_shmem_file - copy an unlinked shmem file for the clone.
 *
 * QEMU and similar programs open /dev/shm files (e.g. qemu_back_mem.dimm*)
 * and immediately unlink them so only the open fd keeps them alive.  d_path()
 * returns a " (deleted)" path that filp_open cannot reopen.  Create a fresh
 * anonymous shmem file of the same size and copy the frozen source contents so
 * the clone gets independent memory.
 */
static struct file *superfork_clone_shmem_file(unsigned int fd,
					       struct file *src_file)
{
	loff_t size = i_size_read(file_inode(src_file));
	struct file *clone;
	loff_t src_off = 0, dst_off = 0, remaining = size;
	loff_t src_pos;

	clone = shmem_file_setup("superfork-shmem", size, 0);
	if (IS_ERR(clone)) {
		pr_err("superfork: shmem_file_setup for fd %u (%lld bytes) failed: %ld\n",
		       fd, size, PTR_ERR(clone));
		return clone;
	}
	/* shmem_file_setup opens with O_RDWR only; without O_LARGEFILE,
	 * generic_write_check_limits caps writes at MAX_NON_LFS (2GB-1). */
	clone->f_flags |= O_LARGEFILE;

	while (remaining > 0) {
		size_t chunk = min_t(loff_t, remaining, (loff_t)MAX_RW_COUNT);
		ssize_t copied;

		/*
		 * COPY_FILE_SPLICE forces do_splice_direct, which works across
		 * different superblocks (e.g. user /dev/shm mount vs. shm_mnt).
		 * Without it, vfs_copy_file_range silently returns 0 when the
		 * two files sit on different superblocks and neither fs implements
		 * ->copy_file_range or ->remap_file_range.
		 */
		copied = vfs_copy_file_range(src_file, src_off, clone,
					     dst_off, chunk, COPY_FILE_SPLICE);

		if (copied < 0) {
			pr_err("superfork: vfs_copy_file_range fd %u failed at offset %lld: %zd\n",
			       fd, src_off, copied);
			fput(clone);
			return ERR_PTR(copied);
		}
		src_off += copied;
		dst_off += copied;
		remaining -= copied;
	}

	spin_lock(&src_file->f_lock);
	src_pos = src_file->f_pos;
	spin_unlock(&src_file->f_lock);

	spin_lock(&clone->f_lock);
	clone->f_pos = src_pos;
	spin_unlock(&clone->f_lock);

	return clone;
}

static int superfork_remap_shmem_vma(struct mm_struct *new_mm,
				     struct file *src_file,
				     struct file *new_shmem_file)
{
	VMA_ITERATOR(vmi, new_mm, 0);
	struct vm_area_struct *vma;
	int ret = 0;
	int found = 0;
	bool remap_now = io_is_uring_fops(new_shmem_file);

	mmap_write_lock(new_mm);
	for_each_vma(vmi, vma) {
		if (vma->vm_file == src_file) {
			vma_set_file(vma, new_shmem_file);
			zap_vma_pages(vma);

			if (remap_now) {
				if (!new_shmem_file->f_op || !new_shmem_file->f_op->mmap) {
					ret = -ENODEV;
					pr_err("superfork: io_uring VMA remap missing mmap op\n");
					vma_set_file(vma, src_file);
					break;
				}

				ret = new_shmem_file->f_op->mmap(new_shmem_file, vma);
				if (ret < 0) {
					pr_err("superfork: io_uring VMA remap failed at %#lx-%#lx pgoff=%#lx: %d\n",
					       vma->vm_start, vma->vm_end,
					       vma->vm_pgoff, ret);
					zap_vma_pages(vma);
					vma_set_file(vma, src_file);
					break;
				}
			}

			found++;
		}
	}
	mmap_write_unlock(new_mm);

	if (!found)
		pr_debug("superfork: no VMAs found for shmem remap (fd may not be mmap'd)\n");

	return ret;
}

static struct file *superfork_open_path_backed_clone(unsigned int fd,
						     struct file *src_file,
						     const struct container_config *config,
						     const struct sf_ns_domain *domain)
{
	char *path_buf = NULL;
	char *src_path = NULL;
	char *dst_path = NULL;
	char *resolved = NULL;
	struct file *clone = NULL;
	loff_t src_pos;
	int open_flags;
	int ret;

	/*
	 * QEMU opens /dev/shm/qemu_back_mem.* files and immediately unlinks
	 * them so only the fd keeps them alive.  d_unlinked() detects this;
	 * filp_open on the " (deleted)" path would fail with ENOENT.  Copy the
	 * frozen content into a fresh anonymous shmem file instead.
	 */
	if (d_unlinked(src_file->f_path.dentry) && shmem_mapping(src_file->f_mapping))
		return superfork_clone_shmem_file(fd, src_file);

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

	dst_path = superfork_remap_snapshot_path(src_path, config);
	if (!dst_path) {
		ret = -ENOMEM;
		goto out_err;
	}

	open_flags = src_file->f_flags &
		~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_TMPFILE);

	/*
	 * If no bundle prefix matched, dst_path == src_path. Reopen the file in
	 * the cloned task's mount domain first, because namespace-relative paths
	 * like "/kata-nginx/..." only make sense there. Returning get_file()
	 * here would leak the source struct file into the clone and fail
	 * superfork_verify_cloned_fds().
	 */
	if (!strcmp(src_path, dst_path)) {
		clone = superfork_domain_open_path(domain, src_path, open_flags, 0);
		if (IS_ERR(clone)) {
			pr_debug("superfork: fd %u path '%s' not reopenable in domain context (%ld), retrying host context\n",
				 fd, src_path, PTR_ERR(clone));
			clone = filp_open(src_path, open_flags, 0);
		}
		if (IS_ERR(clone)) {
			pr_debug("superfork: fd %u path '%s' not reopenable from host context (%ld), using /dev/null\n",
				 fd, src_path, PTR_ERR(clone));
			clone = filp_open("/dev/null", O_RDWR, 0);
		} else {
			spin_lock(&src_file->f_lock);
			src_pos = src_file->f_pos;
			spin_unlock(&src_file->f_lock);
			spin_lock(&clone->f_lock);
			clone->f_pos = src_pos;
			spin_unlock(&clone->f_lock);
		}
		kfree(dst_path);
		kfree(src_path);
		kfree(path_buf);
		return clone;
	}

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
						  const struct container_config *config)
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

	dst_path = superfork_remap_snapshot_path(src_path, config);
	if (!dst_path) {
		ret = -ENOMEM;
		goto out_err;
	}

	if (strlen(dst_path) >= UNIX_PATH_MAX) {
		char *short_path;

		short_path = superfork_short_run_socket_path(src_path, config);
		if (!short_path) {
			pr_err("superfork: remapped unix socket path too long: %s\n",
			       dst_path);
			ret = -ENAMETOOLONG;
			goto out_err;
		}

		if (strlen(short_path) >= UNIX_PATH_MAX) {
			pr_err("superfork: synthesized unix socket path still too long: %s\n",
			       short_path);
			kfree(short_path);
			ret = -ENAMETOOLONG;
			goto out_err;
		}

		pr_info("superfork: remapped unix socket path too long, using short path '%s' for source '%s'\n",
			short_path, src_path);
		kfree(dst_path);
		dst_path = short_path;
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

static int superfork_create_internal_unix_pair(struct sf_unix_sock_edge *edge)
{
	struct socket *src_sock;
	struct socket *sock1 = NULL;
	struct socket *sock2 = NULL;
	struct file *file1;
	struct file *file2;
	int sock_type;
	int flags1;
	int flags2;
	int ret;

	if (!edge || !edge->src_file[0] || !edge->src_file[1])
		return -EINVAL;
	if (edge->new_file[0] && edge->new_file[1])
		return 0;

	src_sock = sock_from_file(edge->src_file[0]);
	if (!src_sock)
		return -EINVAL;

	sock_type = src_sock->type;
	flags1 = edge->src_file[0]->f_flags & O_NONBLOCK;
	flags2 = edge->src_file[1]->f_flags & O_NONBLOCK;

	ret = sock_create(PF_UNIX, sock_type, 0, &sock1);
	if (ret < 0)
		return ret;

	ret = sock_create(PF_UNIX, sock_type, 0, &sock2);
	if (ret < 0)
		goto out_release_sock1;

	ret = security_socket_socketpair(sock1, sock2);
	if (ret < 0)
		goto out_release_pair;

	ret = READ_ONCE(sock1->ops)->socketpair(sock1, sock2);
	if (ret < 0)
		goto out_release_pair;

	file1 = sock_alloc_file(sock1, flags1, NULL);
	if (IS_ERR(file1)) {
		ret = PTR_ERR(file1);
		sock1 = NULL;
		goto out_release_sock2;
	}

	file2 = sock_alloc_file(sock2, flags2, NULL);
	if (IS_ERR(file2)) {
		ret = PTR_ERR(file2);
		fput(file1);
		sock2 = NULL;
		goto out_release_sock2;
	}

	edge->new_file[0] = file1;
	edge->new_file[1] = file2;
	pr_info("superfork: internal unix pair create left=%d fd=%u -> new=%p right=%d fd=%u -> new=%p type=%d\n",
		edge->src_tgid[0], edge->src_fd[0], edge->new_file[0],
		edge->src_tgid[1], edge->src_fd[1], edge->new_file[1],
		sock_type);
	return 0;

out_release_pair:
	sock_release(sock2);
out_release_sock1:
	sock_release(sock1);
	return ret;

out_release_sock2:
	if (sock2)
		sock_release(sock2);
	return ret;
}

static struct file *superfork_get_internal_unix_replacement(
				struct container_clone_ctx *ctx,
				struct file *src_file)
{
	struct sf_unix_sock_edge *edge;
	unsigned int slot;
	int ret;

	edge = superfork_find_internal_unix_edge(ctx, src_file, &slot);
	if (!edge)
		return NULL;

	ret = superfork_create_internal_unix_pair(edge);
	if (ret < 0)
		return ERR_PTR(ret);

	pr_info("superfork: internal unix replacement request src=%d fd=%u peer=%d fd=%u slot=%u replacement=%p\n",
		edge->src_tgid[slot], edge->src_fd[slot],
		edge->src_tgid[slot ^ 1], edge->src_fd[slot ^ 1],
		slot, edge->new_file[slot]);
	return get_file(edge->new_file[slot]);
}

static int superfork_register_placeholder_peer(struct task_struct *owner_task,
					       struct file *file)
{
	struct sf_placeholder_peer *peer;
	struct pid *owner_tgid;

	if (!owner_task || !file)
		return -EINVAL;

	owner_tgid = get_task_pid(owner_task, PIDTYPE_TGID);
	if (!owner_tgid)
		return -ESRCH;

	peer = kzalloc(sizeof(*peer), GFP_KERNEL);
	if (!peer) {
		put_pid(owner_tgid);
		return -ENOMEM;
	}

	peer->owner_tgid = owner_tgid;
	peer->file = file;

	spin_lock(&sf_placeholder_peers_lock);
	list_add_tail(&peer->list, &sf_placeholder_peers);
	spin_unlock(&sf_placeholder_peers_lock);
	return 0;
}

void superfork_release_placeholder_peers(struct task_struct *task)
{
	LIST_HEAD(release_list);
	struct sf_placeholder_peer *peer, *tmp;
	struct pid *owner_tgid;

	if (!task || !thread_group_leader(task))
		return;

	owner_tgid = get_task_pid(task, PIDTYPE_TGID);
	if (!owner_tgid)
		return;

	spin_lock(&sf_placeholder_peers_lock);
	list_for_each_entry_safe(peer, tmp, &sf_placeholder_peers, list) {
		if (peer->owner_tgid != owner_tgid)
			continue;
		list_move_tail(&peer->list, &release_list);
	}
	spin_unlock(&sf_placeholder_peers_lock);

	put_pid(owner_tgid);

	list_for_each_entry_safe(peer, tmp, &release_list, list) {
		list_del_init(&peer->list);
		fput(peer->file);
		put_pid(peer->owner_tgid);
		kfree(peer);
	}
}

static struct file *superfork_create_external_unix_placeholder(
				struct file *src_file,
				struct task_struct *owner_task)
{
	struct socket *src_sock;
	struct socket *sock1 = NULL;
	struct socket *sock2 = NULL;
	struct file *file1;
	struct file *file2;
	int sock_type;
	int flags;
	int ret;

	src_sock = sock_from_file(src_file);
	if (!src_sock || !unix_get_socket(src_file))
		return NULL;

	sock_type = src_sock->type;
	flags = src_file->f_flags & O_NONBLOCK;

	ret = sock_create(PF_UNIX, sock_type, 0, &sock1);
	if (ret < 0)
		return ERR_PTR(ret);

	ret = sock_create(PF_UNIX, sock_type, 0, &sock2);
	if (ret < 0)
		goto out_release_sock1;

	ret = security_socket_socketpair(sock1, sock2);
	if (ret < 0)
		goto out_release_pair;

	ret = READ_ONCE(sock1->ops)->socketpair(sock1, sock2);
	if (ret < 0)
		goto out_release_pair;

	file1 = sock_alloc_file(sock1, flags, NULL);
	if (IS_ERR(file1)) {
		ret = PTR_ERR(file1);
		sock1 = NULL;
		goto out_release_sock2;
	}

	file2 = sock_alloc_file(sock2, flags, NULL);
	if (IS_ERR(file2)) {
		ret = PTR_ERR(file2);
		fput(file1);
		sock2 = NULL;
		goto out_release_sock2;
	}

	ret = superfork_register_placeholder_peer(owner_task, file2);
	if (ret < 0) {
		fput(file2);
		fput(file1);
		return ERR_PTR(ret);
	}

	pr_info("superfork: fd placeholder unix socket owner=%d src=%pD2 type=%d\n",
		owner_task->pid, src_file, sock_type);
	return file1;

out_release_pair:
	sock_release(sock2);
out_release_sock1:
	sock_release(sock1);
	return ERR_PTR(ret);

out_release_sock2:
	if (sock2)
		sock_release(sock2);
	return ERR_PTR(ret);
}

static int superfork_create_internal_pipe_pair(struct sf_pipe_edge *edge)
{
	struct file *files[2];
	int flags = 0;
	int ret;

	if (!edge || !edge->src_file[0] || !edge->src_file[1])
		return -EINVAL;
	if (edge->new_file[0] && edge->new_file[1])
		return 0;

	flags |= (edge->src_file[0]->f_flags | edge->src_file[1]->f_flags) &
		 (O_NONBLOCK | O_DIRECT);

	ret = create_pipe_files(files, flags);
	if (ret < 0)
		return ret;

	edge->new_file[0] = files[0];
	edge->new_file[1] = files[1];
	return 0;
}

static struct file *superfork_get_internal_pipe_replacement(
				struct container_clone_ctx *ctx,
				struct file *src_file)
{
	struct sf_pipe_edge *edge;
	unsigned int slot;
	int ret;

	edge = superfork_find_internal_pipe_edge(ctx, src_file, &slot);
	if (!edge)
		return NULL;

	ret = superfork_create_internal_pipe_pair(edge);
	if (ret < 0)
		return ERR_PTR(ret);

	return get_file(edge->new_file[slot]);
}

static struct file *superfork_create_external_pipe_placeholder(
				struct file *src_file,
				struct task_struct *owner_task)
{
	struct file *files[2];
	struct file *replacement;
	struct file *peer;
	int flags = src_file->f_flags & (O_NONBLOCK | O_DIRECT);
	int ret;

	if (!!(src_file->f_mode & FMODE_READ) ==
	    !!(src_file->f_mode & FMODE_WRITE))
		return NULL;

	ret = create_pipe_files(files, flags);
	if (ret < 0)
		return ERR_PTR(ret);

	if (src_file->f_mode & FMODE_READ) {
		replacement = files[0];
		peer = files[1];
	} else {
		replacement = files[1];
		peer = files[0];
	}

	ret = superfork_register_placeholder_peer(owner_task, peer);
	if (ret < 0) {
		fput(peer);
		fput(replacement);
		return ERR_PTR(ret);
	}

	pr_info("superfork: fd placeholder pipe owner=%d src=%pD2 mode=0x%x\n",
		owner_task->pid, src_file, src_file->f_mode);
	return replacement;
}

static bool superfork_pipe_endpoint_is_orphaned(struct file *src_file)
{
	struct pipe_inode_info *pipe;
	bool is_read;
	bool is_write;

	pipe = get_pipe_info(src_file, false);
	if (!pipe)
		return false;

	is_read = !!(src_file->f_mode & FMODE_READ);
	is_write = !!(src_file->f_mode & FMODE_WRITE);
	if (is_read == is_write)
		return false;

	if (is_read)
		return READ_ONCE(pipe->writers) == 0;

	return READ_ONCE(pipe->readers) == 0;
}

/* --- fd alias map ------------------------------------------------------- */

struct sf_epoll_replay_entry {
	struct file *src_file;
	struct file *dst_file;
};

struct sf_epoll_replay_queue {
	struct sf_epoll_replay_entry *entries;
	unsigned int count;
	unsigned int capacity;
};

struct sf_io_uring_replay_entry {
	struct file *src_file;
	struct file *dst_file;
};

struct sf_io_uring_replay_queue {
	struct sf_io_uring_replay_entry *entries;
	unsigned int count;
	unsigned int capacity;
};

static void superfork_epoll_replay_queue_release(
				struct sf_epoll_replay_queue *queue)
{
	unsigned int i;

	for (i = 0; i < queue->count; i++) {
		fput(queue->entries[i].src_file);
		fput(queue->entries[i].dst_file);
	}

	kfree(queue->entries);
	queue->entries = NULL;
	queue->count = 0;
	queue->capacity = 0;
}

static int superfork_epoll_replay_queue_grow(
				struct sf_epoll_replay_queue *queue)
{
	struct sf_epoll_replay_entry *entries;
	unsigned int old_capacity = queue->capacity;
	unsigned int new_capacity = old_capacity ? old_capacity * 2 : 4;

	if (new_capacity <= old_capacity)
		return -EOVERFLOW;

	entries = krealloc_array(queue->entries, new_capacity,
				 sizeof(*queue->entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	memset(entries + old_capacity, 0,
	       (new_capacity - old_capacity) * sizeof(*queue->entries));
	queue->entries = entries;
	queue->capacity = new_capacity;
	return 0;
}

static int superfork_queue_epoll_replay(struct sf_epoll_replay_queue *queue,
					struct file *src_file,
					struct file *dst_file)
{
	if (queue->count >= queue->capacity) {
		int ret = superfork_epoll_replay_queue_grow(queue);

		if (ret < 0)
			return ret;
	}

	queue->entries[queue->count].src_file = get_file(src_file);
	queue->entries[queue->count].dst_file = get_file(dst_file);
	queue->count++;
	return 0;
}

static int superfork_replay_epoll_watch_sets(struct files_struct *files,
					     struct sf_epoll_replay_queue *queue)
{
	unsigned int i;

	for (i = 0; i < queue->count; i++) {
		int ret = epoll_file_replay(queue->entries[i].dst_file,
					    queue->entries[i].src_file,
					    files);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static void superfork_io_uring_replay_queue_release(
				struct sf_io_uring_replay_queue *queue)
{
	unsigned int i;

	for (i = 0; i < queue->count; i++) {
		fput(queue->entries[i].src_file);
		fput(queue->entries[i].dst_file);
	}

	kfree(queue->entries);
	queue->entries = NULL;
	queue->count = 0;
	queue->capacity = 0;
}

static int superfork_queue_io_uring_replay(
				struct sf_io_uring_replay_queue *queue,
				struct file *src_file,
				struct file *dst_file)
{
	/*
	 * io_uring poll replay submits synthetic requests from the superfork
	 * caller's context before the cloned task has ever run.  The replayed
	 * requests then complete against cloned task_structs whose lifetime is
	 * still managed by the normal exit path, and we observed that this can
	 * drive task->usage to zero while the task is still alive.  The first
	 * symptom is free_task()/task_dump_owner() warnings and NULL-cred
	 * crashes on the cloned Kata helpers.
	 *
	 * Keep creating a fresh ring and remapping the clone's io_uring VMAs
	 * to it, but skip re-submitting inherited poll requests until there is
	 * an in-task-context replay mechanism.
	 */
	return 0;
}

static int superfork_replay_io_uring_polls(struct files_struct *files,
					   struct sf_io_uring_replay_queue *queue,
					   struct task_struct *owner_task)
{
	return 0;
}

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

static int superfork_fd_alias_map_grow(struct sf_fd_alias_map *map)
{
	struct sf_fd_alias_entry *entries;
	unsigned int old_capacity = map->capacity;
	unsigned int new_capacity;

	new_capacity = old_capacity ? old_capacity * 2 : 16;
	if (new_capacity <= old_capacity)
		return -EOVERFLOW;

	entries = krealloc_array(map->entries, new_capacity,
				 sizeof(*map->entries), GFP_KERNEL);
	if (!entries)
		return -ENOMEM;

	memset(entries + old_capacity, 0,
	       (new_capacity - old_capacity) * sizeof(*entries));
	map->entries = entries;
	map->capacity = new_capacity;
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
		if (map->entries[i].src_file == src_file) {
			pr_info("superfork: alias_map_find key=%p -> HIT new=%p\n",
				src_file, map->entries[i].new_file);
			return get_file(map->entries[i].new_file);
		}
	}

	pr_info("superfork: alias_map_find key=%p -> MISS (count=%u)\n",
		src_file, map->count);
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

static struct file *superfork_fd_alias_map_resolve_eventfd_file(void *opaque,
						struct eventfd_ctx *src_ctx)
{
	const struct sf_fd_alias_map *map = opaque;
	unsigned int i;

	if (!map || !src_ctx)
		return NULL;

	for (i = 0; i < map->count; i++) {
		struct eventfd_ctx *ctx;

		if (!map->entries[i].src_file || !map->entries[i].new_file)
			continue;

		ctx = eventfd_ctx_fileget(map->entries[i].src_file);
		if (IS_ERR(ctx))
			continue;

		if (ctx == src_ctx) {
			eventfd_ctx_put(ctx);
			return get_file(map->entries[i].new_file);
		}

		eventfd_ctx_put(ctx);
	}

	return NULL;
}
#endif /* CONFIG_KVM */

static int superfork_fd_alias_map_add(struct sf_fd_alias_map *map,
				      struct file *src_file,
				      struct file *new_file)
{
	if (map->count >= map->capacity) {
		int ret;

		ret = superfork_fd_alias_map_grow(map);
		if (ret < 0)
			return ret;
	}

	map->entries[map->count].src_file = src_file;
	map->entries[map->count].new_file = get_file(new_file);
	pr_info("superfork: alias_map_add entry=%u src=%p new=%p\n",
		map->count, src_file, new_file);
	map->count++;
	return 0;
}

static int superfork_queue_procfs_reopen(struct tgid_clone_entry *tgid_entry,
					 const struct fd_action *action)
{
	struct sf_procfs_reopen reopen = {};
	const char *relpath;
	int ret;

	if (!tgid_entry)
		return -EINVAL;

	ret = superfork_parse_procfs_reopen_path(action->procfs_path,
						 &reopen.old_pid,
						 &relpath);
	if (ret < 0) {
		pr_err("superfork: procfs fd %u: bad path '%s': %d\n",
		       action->fd, action->procfs_path, ret);
		return ret;
	}

	if (tgid_entry->procfs_reopen_count >= SF_MAX_PROCFS_REOPENS) {
		pr_err("superfork: procfs fd %u exceeds procfs reopen limit %u\n",
		       action->fd, SF_MAX_PROCFS_REOPENS);
		return -E2BIG;
	}

	reopen.fd = action->fd;
	reopen.open_flags = action->file->f_flags &
		~(O_CREAT | O_EXCL | O_NOCTTY | O_TRUNC | O_TMPFILE);
	spin_lock(&action->file->f_lock);
	reopen.pos = action->file->f_pos;
	spin_unlock(&action->file->f_lock);

	ret = strscpy(reopen.relpath, relpath, sizeof(reopen.relpath));
	if (ret < 0) {
		pr_err("superfork: procfs fd %u relpath too long: '%s'\n",
		       action->fd, action->procfs_path);
		return -ENAMETOOLONG;
	}

	tgid_entry->procfs_reopens[tgid_entry->procfs_reopen_count++] = reopen;
	pr_info("superfork: queue procfs reopen old_tgid=%d fd=%u old_pid=%d relpath='%s' flags=0x%x pos=%lld\n",
		tgid_entry->old_tgid, reopen.fd, reopen.old_pid,
		reopen.relpath, reopen.open_flags, reopen.pos);
	return 0;
}

static int superfork_queue_pidfd_reopen(struct tgid_clone_entry *tgid_entry,
					const struct fd_action *action)
{
	struct sf_pidfd_reopen reopen = {};

	if (!tgid_entry || !action || action->type != FD_ACT_PIDFD_REOPEN)
		return -EINVAL;

	if (tgid_entry->pidfd_reopen_count >= SF_MAX_PIDFD_REOPENS) {
		pr_err("superfork: pidfd fd %u exceeds pidfd reopen limit %u\n",
		       action->fd, SF_MAX_PIDFD_REOPENS);
		return -E2BIG;
	}

	reopen.fd = action->fd;
	reopen.old_pid = action->pidfd_old_pid;
	reopen.flags = action->pidfd_flags;
	tgid_entry->pidfd_reopens[tgid_entry->pidfd_reopen_count++] = reopen;
	return 0;
}

/* --- main fd sanitization ----------------------------------------------- */

static int superfork_sanitize_inherited_fds(struct files_struct *files,
					    struct container_clone_ctx *ctx,
					    const struct container_config *config,
					    const struct sf_ns_domain *domain,
					    struct task_struct *owner_task,
					    struct mm_struct *new_mm,
					    struct tgid_clone_entry *tgid_entry)
{
	struct sf_fd_alias_map alias_map;
	struct sf_epoll_replay_queue epoll_replays = {};
	struct sf_io_uring_replay_queue uring_replays = {};
	unsigned int start = 0;
	int ret = 0;
	bool warned_kvm_phase4 = false;

	ret = superfork_fd_alias_map_init(files, &alias_map);
	if (ret < 0)
		return ret;

	for (;;) {
		struct fd_action action = { .type = FD_ACT_NONE };
		struct file *replacement = NULL;
		const char *replacement_kind = "none";
		bool replacement_needs_install = false;
		bool replacement_should_track = false;
		bool replacement_from_map = false;
		unsigned int next_start;

		ret = iterate_fd(files, start, superfork_collect_fd_action, &action);
		if (ret == 0)
			break;
		next_start = ret;

		if (action.type == FD_ACT_NONE) {
			start = next_start;
			continue;
		}

		if (action.type == FD_ACT_PROCFS_REOPEN) {
			ret = superfork_queue_procfs_reopen(tgid_entry, &action);
			if (ret < 0) {
				fput(action.file);
				goto out;
			}
		}

		if (action.type == FD_ACT_PIDFD_REOPEN) {
			ret = superfork_queue_pidfd_reopen(tgid_entry, &action);
			if (ret < 0) {
				fput(action.file);
				goto out;
			}
		}

		if (action.type != FD_ACT_UNSUPPORTED) {
			replacement = superfork_fd_alias_map_find(&alias_map, action.file);
			if (replacement) {
				replacement_kind = "alias_map";
				replacement_needs_install = true;
				replacement_from_map = true;
			}
		}

		if (!replacement_from_map) {
			if (action.type == FD_ACT_DEVNULL) {
				replacement = superfork_get_internal_unix_replacement(ctx,
									 action.file);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to recreate internal unix socket at fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				if (replacement) {
					replacement_kind = "internal_unix";
					replacement_needs_install = true;
					replacement_should_track = true;
				}

				if (!replacement) {
					replacement = superfork_get_internal_pipe_replacement(
								ctx, action.file);
					if (IS_ERR(replacement)) {
						ret = PTR_ERR(replacement);
						pr_err("superfork: failed to recreate internal pipe at fd %u: %d\n",
						       action.fd, ret);
						fput(action.file);
						goto out;
					}
					if (replacement) {
						replacement_kind = "internal_pipe";
						replacement_needs_install = true;
						replacement_should_track = true;
					}
				}

				/*
				 * Preserve external Unix sockets by sharing the
				 * inherited file object with the source task.
				 *
				 * Unlike /dev/vhost-vsock or generic network
				 * sockets, a connected AF_UNIX control socket is
				 * already a fully configured kernel object and
				 * dup_files() has given the clone a valid ref to
				 * that same endpoint.  Replacing it with a
				 * placeholder forces higher-level control-plane
				 * daemons like the Kata shim to observe a broken
				 * transport immediately and tear the clone down.
				 *
				 * Internal Unix socket pairs are handled above by
				 * recreating a fresh pair for the clone.  This
				 * fallback is only for sockets whose peer lives
				 * outside the clone set.
				 */
				if (!replacement && unix_get_socket(action.file) &&
				    (!owner_task ||
				     (strcmp(owner_task->comm, "containerd-shim") &&
				      strcmp(owner_task->comm, "virtiofsd")))) {
					ret = superfork_allow_shared_source_file(ctx,
									 action.file);
					if (ret < 0) {
						pr_err("superfork: failed to record shared external unix socket at fd %u: %d\n",
						       action.fd, ret);
						fput(action.file);
						goto out;
					}
					replacement = get_file(action.file);
					/*
					 * dup_files() already left this shared
					 * external socket installed in the
					 * clone, so there is nothing to replace
					 * at the fd slot.  We still need to
					 * track it for dup aliases and epoll
					 * replay, and we must skip the generic
					 * FD_ACT_DEVNULL fallback below.
					 */
					replacement_kind = "shared_external_unix";
					replacement_should_track = true;
					pr_info("superfork: preserving shared external unix socket at fd %u file=%pD2\n",
						action.fd, action.file);
					goto install_replacement;
				}

				if (!replacement) {
					if (owner_task &&
					    !strcmp(owner_task->comm, "containerd-shim"))
						pr_info("superfork: isolating containerd-shim external unix socket at fd %u with placeholder\n",
							action.fd);
					else if (owner_task &&
						 !strcmp(owner_task->comm, "virtiofsd"))
						pr_info("superfork: isolating virtiofsd external unix socket at fd %u with placeholder\n",
							action.fd);

					/*
					 * Preserve virtiofsd's Unix datagram socket.
					 *
					 * The supervisor process is launched with
					 * --syslog and keeps a tiny AF_UNIX/SOCK_DGRAM
					 * socket open for that logging path.  Replacing
					 * it with a placeholder is enough to make the
					 * cloned supervisor exit immediately with
					 * status 1, even though its data-plane worker
					 * state is otherwise intact.  Keep sharing the
					 * live file object for this narrow case while
					 * continuing to isolate connected external
					 * control sockets.
					 */
					if (owner_task &&
					    !strcmp(owner_task->comm, "virtiofsd") &&
					    action.sock_family == AF_UNIX &&
					    action.sock_type == SOCK_DGRAM) {
						ret = superfork_allow_shared_source_file(
							ctx, action.file);
						if (ret < 0) {
							pr_err("superfork: failed to record shared virtiofsd unix datagram socket at fd %u: %d\n",
							       action.fd, ret);
							fput(action.file);
							goto out;
						}
						replacement = get_file(action.file);
						replacement_kind = "shared_virtiofsd_unix_dgram";
						replacement_should_track = true;
						pr_info("superfork: preserving virtiofsd external unix datagram socket at fd %u file=%pD2\n",
							action.fd, action.file);
						goto install_replacement;
					}

					/*
					 * Preserve the live vhost-vsock file object.
					 *
					 * QEMU has already fully configured this
					 * backend before superfork runs, and
					 * dup_files() leaves the cloned task with a
					 * valid ref to that same configured object.
					 * Replacing it with /dev/null makes the
					 * cloned QEMU tear its sandbox down
					 * immediately on resume.
					 *
					 * This is intentionally narrow: only the
					 * already-configured /dev/vhost-vsock file
					 * gets shared, and we record it in the
					 * explicit shared-file allowlist so fd
					 * verification still rejects every other
					 * unexpected source file leak.
					 */
					if (action.hint &&
					    !strcmp(action.hint, "vhost_vsock")) {
						ret = superfork_allow_shared_source_file(
							ctx, action.file);
						if (ret < 0) {
							pr_err("superfork: failed to record shared vhost-vsock file at fd %u: %d\n",
							       action.fd, ret);
							fput(action.file);
							goto out;
						}
						replacement = get_file(action.file);
						replacement_kind = "shared_vhost_vsock";
						replacement_should_track = true;
						pr_info("superfork: preserving shared vhost-vsock backend at fd %u file=%pD2\n",
							action.fd, action.file);
						goto install_replacement;
					}

					replacement = superfork_create_external_unix_placeholder(
								action.file, owner_task);
					if (IS_ERR(replacement)) {
						ret = PTR_ERR(replacement);
						pr_err("superfork: failed to create external unix placeholder at fd %u: %d\n",
						       action.fd, ret);
						fput(action.file);
						goto out;
					}
					if (replacement) {
						replacement_kind = "placeholder_unix";
						replacement_needs_install = true;
						replacement_should_track = true;
					}
				}

				if (!replacement) {
					/*
					 * Preserve named FIFOs as shared live file
					 * objects.
					 *
					 * containerd-shim keeps its sandbox log
					 * transport as a path-backed FIFO and also
					 * retains an O_PATH handle to that same
					 * inode.  Replacing those fds with either an
					 * anonymous pipe placeholder or /dev/null
					 * preserves the slot number but destroys the
					 * userspace-visible open mode and backing
					 * endpoint semantics, which makes the cloned
					 * shim fall over immediately after wake.
					 *
					 * Unlike anonymous pipefs endpoints, these
					 * FIFOs already have a stable path-backed
					 * kernel object and dup_files() has left the
					 * clone with a valid ref to the exact same
					 * open file description.  Share that live
					 * file object intentionally and record it in
					 * the explicit allowlist so fd verification
					 * still rejects every other accidental source
					 * file leak.
					 */
					if (superfork_is_path_backed_fifo(action.file)) {
						ret = superfork_allow_shared_source_file(
							ctx, action.file);
						if (ret < 0) {
							pr_err("superfork: failed to record shared named fifo at fd %u: %d\n",
							       action.fd, ret);
							fput(action.file);
							goto out;
						}
						replacement = get_file(action.file);
						replacement_kind = "shared_named_fifo";
						replacement_should_track = true;
						pr_info("superfork: preserving shared named fifo at fd %u file=%pD2 flags=0x%x\n",
							action.fd, action.file,
							action.file->f_flags);
						goto install_replacement;
					}

					/*
					 * Preserve already-orphaned anonymous
					 * pipe endpoints.
					 *
					 * A placeholder pipe keeps the fd slot
					 * alive but rewrites EOF/SIGPIPE
					 * behavior into a fresh live pipe with a
					 * hidden peer. If the opposite end is
					 * already gone in the frozen source
					 * state, keep sharing the exact live file
					 * object instead.
					 */
					if (superfork_pipe_endpoint_is_orphaned(
						    action.file)) {
						ret = superfork_allow_shared_source_file(
							ctx, action.file);
						if (ret < 0) {
							pr_err("superfork: failed to record shared orphaned pipe endpoint at fd %u: %d\n",
							       action.fd, ret);
							fput(action.file);
							goto out;
						}
						replacement = get_file(action.file);
						replacement_kind = "shared_orphan_pipe";
						replacement_should_track = true;
						pr_info("superfork: preserving orphaned pipe endpoint at fd %u file=%pD2 mode=0x%x readers=%u writers=%u files=%u bufs=%u max=%u watch=%d\n",
							action.fd, action.file,
							action.file->f_mode,
							action.pipe_readers,
							action.pipe_writers,
							action.pipe_files,
							action.pipe_bufs,
							action.pipe_max_usage,
							(int)action.pipe_watch_queue);
						goto install_replacement;
					}

					replacement = superfork_create_external_pipe_placeholder(
								action.file, owner_task);
					if (IS_ERR(replacement)) {
						ret = PTR_ERR(replacement);
						pr_err("superfork: failed to create external pipe placeholder at fd %u: %d\n",
						       action.fd, ret);
						fput(action.file);
						goto out;
					}
					if (replacement) {
						replacement_kind = "placeholder_pipe";
						replacement_needs_install = true;
						replacement_should_track = true;
					}
				}
			}

			if (replacement_needs_install)
				goto install_replacement;

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
			case FD_ACT_PROCFS_REOPEN: {
				/* Install /dev/null until post-attach reopen. */
				int nflags = action.file->f_flags & (O_ACCMODE | O_PATH);

				replacement = filp_open("/dev/null", nflags, 0);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to open /dev/null for procfs fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_kind = "procfs_placeholder";
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
			case FD_ACT_PIDFD_REOPEN: {
				int nflags = action.file->f_flags & (O_ACCMODE | O_PATH);

				replacement = filp_open("/dev/null", nflags, 0);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to open /dev/null for pidfd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_kind = "pidfd_placeholder";
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
			case FD_ACT_DEVNULL: {
				/*
				 * Replace with /dev/null preserving access mode.
				 * Covers: FIFOs, pipes, connected sockets, pidfds,
				 * io_uring rings.
				 */
				int acc = action.file->f_flags & O_ACCMODE;
				int nflags = (acc == O_WRONLY) ? O_WRONLY : O_RDWR;

				replacement = filp_open("/dev/null", nflags, 0);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to open /dev/null for fd %u (%s): %d\n",
					       action.fd, action.hint ? action.hint : "?", ret);
					fput(action.file);
					goto out;
				}
				replacement_kind = "devnull";
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
			case FD_ACT_EPOLL_NEW: {
				replacement = epoll_file_create(action.file->f_flags & O_CLOEXEC);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to create epoll for fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_kind = "new_epoll";
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
#ifdef CONFIG_IO_URING
			case FD_ACT_IOURING_NEW: {
				struct io_ring_ctx *src_ctx = action.file->private_data;

				replacement = io_uring_file_create(src_ctx, owner_task);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to create io_uring for fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_kind = "new_io_uring";
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
#endif
			case FD_ACT_INOTIFY_NEW: {
#ifdef CONFIG_INOTIFY_USER
				replacement = inotify_file_create(action.file->f_flags & O_CLOEXEC);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to create inotify for fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_kind = "new_inotify";
				replacement_needs_install = true;
				replacement_should_track = true;
#else
				pr_warn("superfork: inotify fd %u: CONFIG_INOTIFY_USER not set, using /dev/null\n",
					action.fd);
				replacement = filp_open("/dev/null", O_RDONLY, 0);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					fput(action.file);
					goto out;
				}
				replacement_kind = "inotify_devnull";
				replacement_needs_install = true;
#endif
				break;
			}
			case FD_ACT_CLONE:
				replacement = superfork_open_path_backed_clone(action.fd,
								      action.file,
								      config,
								      domain);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to reopen path-backed fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_kind = "reopen_path";
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			case FD_ACT_UNIX_SOCK_SERVER:
				replacement = superfork_create_unix_server(action.file,
									   config);
				if (IS_ERR(replacement)) {
					ret = PTR_ERR(replacement);
					pr_err("superfork: failed to recreate unix server socket at fd %u: %d\n",
					       action.fd, ret);
					fput(action.file);
					goto out;
				}
				replacement_kind = "new_unix_server";
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
				replacement_kind = "new_eventfd";
				replacement_needs_install = true;
				replacement_should_track = true;
				break;
			}
			case FD_ACT_NONE:
				break;
			}
		}

install_replacement:
		if (replacement_needs_install) {
			int rc = superfork_replace_file_at(files, action.fd, replacement);
			if (rc < 0) {
				pr_err("superfork: failed to replace fd %u: %d\n", action.fd, rc);
				ret = rc;
				fput(replacement);
				fput(action.file);
				goto out;
			}

			if (new_mm &&
			    d_unlinked(action.file->f_path.dentry) &&
			    shmem_mapping(action.file->f_mapping)) {
				rc = superfork_remap_shmem_vma(new_mm, action.file,
							       replacement);
				if (rc < 0) {
					pr_err("superfork: failed to remap unlinked shmem VMA for fd %u: %d\n",
					       action.fd, rc);
					ret = rc;
					fput(replacement);
					fput(action.file);
					goto out;
				}
			}

			if (!replacement_from_map && action.type == FD_ACT_EPOLL_NEW) {
				rc = superfork_queue_epoll_replay(&epoll_replays,
								  action.file,
								  replacement);
				if (rc < 0) {
					pr_err("superfork: failed to queue epoll replay for fd %u: %d\n",
					       action.fd, rc);
					ret = rc;
					fput(replacement);
					fput(action.file);
					goto out;
				}
			}

			if (!replacement_from_map && action.type == FD_ACT_IOURING_NEW) {
				rc = superfork_queue_io_uring_replay(&uring_replays,
								     action.file,
								     replacement);
				if (rc < 0) {
					pr_err("superfork: failed to queue io_uring replay for fd %u: %d\n",
					       action.fd, rc);
					ret = rc;
					fput(replacement);
					fput(action.file);
					goto out;
				}
				/*
				 * QEMU maps the io_uring SQ/CQ/sqe ring pages directly
				 * via mmap(io_uring_fd). After replacement the fd points
				 * to a new ring context, but the clone's VAS still
				 * contains VMAs backed by the source ring file. io_uring
				 * populates those VMAs directly from .mmap() with
				 * vm_insert_pages(), so just zapping the old PTEs leaves an
				 * empty ring mapping that faults with SIGBUS. Swap the VMA
				 * to the new file and immediately rerun the new file's
				 * .mmap() setup on that VMA.
				 */
				if (new_mm) {
					rc = superfork_remap_shmem_vma(new_mm, action.file,
							       replacement);
					if (rc < 0) {
						pr_err("superfork: failed to remap io_uring VMA for fd %u: %d\n",
						       action.fd, rc);
						ret = rc;
						fput(replacement);
						fput(action.file);
						goto out;
					}
				}
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

		pr_info("superfork: sanitize owner=%d/%s fd=%u type=%d hint=%s kind=%s sock_family=%d sock_type=%d sock_state=%d pipe_readers=%u pipe_writers=%u pipe_files=%u pipe_bufs=%u pipe_max=%u pipe_watch=%d file=%p from_map=%d track=%d replacement=%p\n",
			owner_task ? owner_task->pid : -1,
			owner_task ? owner_task->comm : "?",
			action.fd, action.type,
			action.hint ? action.hint : "?",
			replacement_kind,
			action.sock_family,
			action.sock_type,
			action.sock_state,
			action.pipe_readers,
			action.pipe_writers,
			action.pipe_files,
			action.pipe_bufs,
			action.pipe_max_usage,
			(int)action.pipe_watch_queue,
			action.file,
			(int)replacement_from_map,
			(int)replacement_should_track,
			replacement);

		if (replacement)
			fput(replacement);

		fput(action.file);
		/*
		 * Keep the iterator position from iterate_fd(). Helpers above
		 * reuse ret for status, and resetting start from that value can
		 * restart the walk at fd 0 and re-sanitize the clone's own fds.
		 */
		start = next_start;
	}

	ret = superfork_replay_epoll_watch_sets(files, &epoll_replays);
	if (ret < 0) {
		pr_err("superfork: epoll watch replay failed: %d\n", ret);
		goto out;
	}

	ret = superfork_replay_io_uring_polls(files, &uring_replays,
						 owner_task);
	if (ret < 0) {
		pr_err("superfork: io_uring poll replay failed: %d\n", ret);
		goto out;
	}

out:
	superfork_io_uring_replay_queue_release(&uring_replays);
	superfork_epoll_replay_queue_release(&epoll_replays);

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

			rc = kvm_superfork_restore_vm_io(
				vm->new_kvm, vm->src_kvm,
				superfork_fd_alias_map_resolve_eventfd_file,
				&alias_map);
			if (rc < 0) {
				pr_err("superfork: restore_vm_io failed: %d\n", rc);
				ret = rc;
				break;
			}
			}
		}
#endif
	superfork_fd_alias_map_release(&alias_map);

	return ret < 0 ? ret : 0;
}

static pid_t superfork_map_old_pid_to_new_nr(struct container_clone_ctx *ctx,
					     pid_t old_pid,
					     struct pid_namespace *ns)
{
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);

		if (!task->old_task || !task->new_task)
			continue;
		if (task->old_task->pid != old_pid)
			continue;

		return task_pid_nr_ns(task->new_task, ns);
	}

	return 0;
}

static struct task_struct *superfork_map_old_pid_to_new_task(
					struct container_clone_ctx *ctx,
					pid_t old_pid)
{
	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);

		if (!task->old_task || !task->new_task)
			continue;
		if (task->old_task->pid != old_pid)
			continue;

		return task->new_task;
	}

	return NULL;
}

static char *superfork_build_procfs_reopen_path(struct container_clone_ctx *ctx,
						const struct sf_procfs_reopen *reopen,
						struct pid_namespace *ns)
{
	pid_t proc_pid;
	char *path;

	if (reopen->old_pid <= 0) {
		if (!reopen->relpath[0])
			return kstrdup("/proc", GFP_KERNEL);

		path = kasprintf(GFP_KERNEL, "/proc/%s", reopen->relpath);
		return path ? path : ERR_PTR(-ENOMEM);
	}

	proc_pid = superfork_map_old_pid_to_new_nr(ctx, reopen->old_pid, ns);
	if (proc_pid <= 0)
		return ERR_PTR(-ESRCH);

	if (!reopen->relpath[0]) {
		path = kasprintf(GFP_KERNEL, "/proc/%d", proc_pid);
		return path ? path : ERR_PTR(-ENOMEM);
	}

	if (!strncmp(reopen->relpath, "task/", 5)) {
		const char *end;
		pid_t old_tid;
		pid_t new_tid;
		int ret;

		ret = superfork_parse_pid_component(reopen->relpath + 5, &end, &old_tid);
		if (ret < 0)
			return ERR_PTR(ret);

		new_tid = superfork_map_old_pid_to_new_nr(ctx, old_tid, ns);
		if (new_tid <= 0)
			return ERR_PTR(-ESRCH);

		if (*end == '\0') {
			path = kasprintf(GFP_KERNEL, "/proc/%d/task/%d",
					 proc_pid, new_tid);
			return path ? path : ERR_PTR(-ENOMEM);
		}
		if (*end != '/')
			return ERR_PTR(-EINVAL);

		path = kasprintf(GFP_KERNEL, "/proc/%d/task/%d/%s",
				 proc_pid, new_tid, end + 1);
		return path ? path : ERR_PTR(-ENOMEM);
	}

	path = kasprintf(GFP_KERNEL, "/proc/%d/%s", proc_pid, reopen->relpath);
	return path ? path : ERR_PTR(-ENOMEM);
}

/*
 * Reopen procfs descriptors through the caller's /proc mount once every
 * cloned task is attached to the tasklist and therefore reachable by pid.
 * This is a file swap in the clone's shared files_struct, not a mount attach.
 */
int superfork_reopen_procfs_fds(struct container_clone_ctx *ctx)
{
	struct pid_namespace *proc_ns = task_active_pid_ns(current);
	int i, j;

	for (i = 0; i < ctx->tgid_count; i++) {
		struct tgid_clone_entry *tgid_entry = &ctx->tgids[i];

		if (!tgid_entry->procfs_reopen_count)
			continue;
		if (!tgid_entry->shared_files || !tgid_entry->new_leader) {
			pr_err("superfork: missing files/leader for procfs reopen old_tgid=%d\n",
			       tgid_entry->old_tgid);
			return -EINVAL;
		}

		for (j = 0; j < tgid_entry->procfs_reopen_count; j++) {
			const struct sf_procfs_reopen *reopen =
				&tgid_entry->procfs_reopens[j];
			struct file *replacement;
			char *proc_path;
			int ret;

			proc_path = superfork_build_procfs_reopen_path(ctx, reopen, proc_ns);
			if (IS_ERR(proc_path)) {
				ret = PTR_ERR(proc_path);
				pr_err("superfork: procfs fd %u path rebuild failed old_pid=%d relpath='%s': %d\n",
				       reopen->fd, reopen->old_pid, reopen->relpath, ret);
				return ret;
			}

			pr_info("superfork: procfs reopen begin old_tgid=%d new_leader=%d fd=%u old_pid=%d path='%s' flags=0x%x pos=%lld\n",
				tgid_entry->old_tgid,
				tgid_entry->new_leader->pid,
				reopen->fd, reopen->old_pid, proc_path,
				reopen->open_flags, reopen->pos);
			replacement = filp_open(proc_path, reopen->open_flags, 0);
			if (IS_ERR(replacement)) {
				ret = PTR_ERR(replacement);
				pr_err("superfork: procfs fd %u reopen failed path='%s': %d\n",
				       reopen->fd, proc_path, ret);
				kfree(proc_path);
				return ret;
			}

			spin_lock(&replacement->f_lock);
			replacement->f_pos = reopen->pos;
			spin_unlock(&replacement->f_lock);

			ret = superfork_replace_file_at(tgid_entry->shared_files,
							reopen->fd, replacement);
			fput(replacement);
			if (ret < 0) {
				pr_err("superfork: procfs fd %u replace failed path='%s': %d\n",
				       reopen->fd, proc_path, ret);
				kfree(proc_path);
				return ret;
			}
			pr_info("superfork: procfs reopen installed old_tgid=%d new_leader=%d fd=%u path='%s'\n",
				tgid_entry->old_tgid,
				tgid_entry->new_leader->pid,
				reopen->fd, proc_path);
			kfree(proc_path);
		}

		tgid_entry->procfs_reopen_count = 0;
	}

	return 0;
}

int superfork_reopen_pidfds(struct container_clone_ctx *ctx)
{
	int i, j;

	for (i = 0; i < ctx->tgid_count; i++) {
		struct tgid_clone_entry *tgid_entry = &ctx->tgids[i];

		if (!tgid_entry->pidfd_reopen_count)
			continue;
		if (!tgid_entry->shared_files) {
			pr_err("superfork: missing files for pidfd reopen old_tgid=%d\n",
			       tgid_entry->old_tgid);
			return -EINVAL;
		}

		for (j = 0; j < tgid_entry->pidfd_reopen_count; j++) {
			const struct sf_pidfd_reopen *reopen =
				&tgid_entry->pidfd_reopens[j];
			struct task_struct *target;
			struct file *replacement;
			int ret;

			target = superfork_map_old_pid_to_new_task(ctx, reopen->old_pid);
			if (!target)
				continue;

			replacement = pidfs_alloc_file(task_pid(target), reopen->flags);
			if (IS_ERR(replacement)) {
				ret = PTR_ERR(replacement);
				pr_err("superfork: pidfd %u reopen failed old_pid=%d: %d\n",
				       reopen->fd, reopen->old_pid, ret);
				return ret;
			}

			ret = superfork_replace_file_at(tgid_entry->shared_files,
							reopen->fd, replacement);
			fput(replacement);
			if (ret < 0) {
				pr_err("superfork: pidfd %u replace failed: %d\n",
				       reopen->fd, ret);
				return ret;
			}
		}

		tgid_entry->pidfd_reopen_count = 0;
	}

	return 0;
}

/* --- fd snapshot + verification ----------------------------------------- */

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

static int superfork_verify_fd_snapshot_pair(struct container_clone_ctx *ctx,
					      const struct sf_fd_snapshot *old_snap,
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

		if (old_e->file == new_e->file &&
		    !superfork_is_allowed_shared_source_file(ctx, old_e->file)) {
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
				pr_err("superfork:   src  fd=%u file=%p  fd=%u file=%p  alias=%d\n",
				       old_e->fd, old_e->file,
				       old_snap->entries[j].fd, old_snap->entries[j].file,
				       (int)old_alias);
				pr_err("superfork:   new  fd=%u file=%p  fd=%u file=%p  alias=%d\n",
				       new_e->fd, new_e->file,
				       new_snap->entries[j].fd, new_snap->entries[j].file,
				       (int)new_alias);
				return -EUCLEAN;
			}
		}
	}

	return 0;
}

static int superfork_verify_files_pair(struct container_clone_ctx *ctx,
				      struct files_struct *oldf,
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

	ret = superfork_verify_fd_snapshot_pair(ctx, &old_snap, &new_snap,
						src_pid, new_pid);

	superfork_fd_snapshot_release(&new_snap);
	superfork_fd_snapshot_release(&old_snap);
	return ret;
}

struct sf_seen_files_pair {
	struct files_struct *oldf;
	struct files_struct *newf;
};

static int superfork_verify_internal_unix_edges(struct container_clone_ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < ctx->unix_sock_edge_count; i++) {
		struct sf_unix_sock_edge *edge = &ctx->unix_sock_edges[i];
		struct socket *sock0;
		struct socket *sock1;
		struct sock *peer;

		if (!edge->new_file[0] || !edge->new_file[1]) {
			pr_err("superfork: internal unix edge %u missing cloned endpoints left=%d fd=%u right=%d fd=%u\n",
			       i, edge->src_tgid[0], edge->src_fd[0],
			       edge->src_tgid[1], edge->src_fd[1]);
			return -EUCLEAN;
		}

		sock0 = sock_from_file(edge->new_file[0]);
		sock1 = sock_from_file(edge->new_file[1]);
		if (!sock0 || !sock1) {
			pr_err("superfork: internal unix edge %u lost socket type left=%d fd=%u right=%d fd=%u\n",
			       i, edge->src_tgid[0], edge->src_fd[0],
			       edge->src_tgid[1], edge->src_fd[1]);
			return -EUCLEAN;
		}

		peer = unix_peer_get(sock0->sk);
		if (!peer || peer != sock1->sk) {
			if (peer)
				sock_put(peer);
			pr_err("superfork: internal unix edge %u peer mismatch left=%d fd=%u right=%d fd=%u\n",
			       i, edge->src_tgid[0], edge->src_fd[0],
			       edge->src_tgid[1], edge->src_fd[1]);
			return -EUCLEAN;
		}
		sock_put(peer);
		pr_info("superfork: internal unix edge %u verified left=%d fd=%u right=%d fd=%u\n",
			i, edge->src_tgid[0], edge->src_fd[0],
			edge->src_tgid[1], edge->src_fd[1]);
	}

	return 0;
}

static int superfork_verify_internal_pipe_edges(struct container_clone_ctx *ctx)
{
	unsigned int i;

	for (i = 0; i < ctx->pipe_edge_count; i++) {
		struct sf_pipe_edge *edge = &ctx->pipe_edges[i];
		struct pipe_inode_info *pipe0;
		struct pipe_inode_info *pipe1;

		if (!edge->new_file[0] || !edge->new_file[1]) {
			pr_err("superfork: internal pipe edge %u missing cloned endpoints\n",
			       i);
			return -EUCLEAN;
		}

		pipe0 = get_pipe_info(edge->new_file[0], false);
		pipe1 = get_pipe_info(edge->new_file[1], false);
		if (!pipe0 || !pipe1 || pipe0 != pipe1) {
			pr_err("superfork: internal pipe edge %u peer mismatch\n", i);
			return -EUCLEAN;
		}
	}

	return 0;
}

int superfork_verify_cloned_fds(struct container_clone_ctx *ctx)
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

		ret = superfork_verify_files_pair(ctx, oldf, newf,
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

	ret = superfork_verify_internal_unix_edges(ctx);
	if (ret < 0)
		goto out;

	ret = superfork_verify_internal_pipe_edges(ctx);

out:
	kfree(seen_pairs);
	return ret;
}

struct files_struct *superfork_dup_files_for_container(struct container_clone_ctx *ctx,
						      struct files_struct *oldf,
						      const struct container_config *config,
						      const struct sf_ns_domain *domain,
						      struct task_struct *owner_task,
						      struct mm_struct *new_mm,
						      struct tgid_clone_entry *tgid_entry)
{
	struct files_struct *newf;
	int ret;

	newf = dup_fd(oldf, NULL);
	if (IS_ERR(newf))
		return newf;

	ret = superfork_sanitize_inherited_fds(newf, ctx, config, domain,
					      owner_task,
					      new_mm, tgid_entry);
	if (ret < 0) {
		put_files_struct(newf);
		return ERR_PTR(ret);
	}

	return newf;
}
