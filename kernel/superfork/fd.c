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
#include <linux/kvm_host.h>
#include <linux/major.h>
#include <linux/mm.h>
#include <linux/namei.h>
#include <linux/net.h>
#include <linux/slab.h>
#include <linux/superfork.h>
#include <linux/tty.h>
#include <linux/uaccess.h>
#include <net/af_unix.h>
#include <uapi/linux/un.h>
#include "internal.h"

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

/* --- fd alias map ------------------------------------------------------- */

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

/* --- main fd sanitization ----------------------------------------------- */

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

struct files_struct *superfork_dup_files_for_container(struct files_struct *oldf,
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
