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
#include "../fs/internal.h"
#include "../fs/mount.h"
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
#include <uapi/linux/mount.h>
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
#define CREATE_TRACE_POINTS
#include <trace/events/superfork.h>
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

static bool superfork_same_namespace_domain(const struct nsproxy *a,
					    const struct nsproxy *b)
{
	if (!a || !b)
		return false;

	return a->mnt_ns == b->mnt_ns &&
	       a->uts_ns == b->uts_ns &&
	       a->ipc_ns == b->ipc_ns &&
	       a->net_ns == b->net_ns &&
	       a->cgroup_ns == b->cgroup_ns &&
	       a->pid_ns_for_children == b->pid_ns_for_children;
}

static bool superfork_prefer_domain_source_task(const struct task_struct *candidate,
						const struct task_struct *current_rep)
{
	if (!candidate)
		return false;
	if (!current_rep)
		return true;

	if (!(candidate->flags & PF_KTHREAD) && (current_rep->flags & PF_KTHREAD))
		return true;
	if (candidate->group_leader == candidate &&
	    current_rep->group_leader != current_rep)
		return true;
	if (candidate->mm && !current_rep->mm)
		return true;
	if (candidate->fs && !current_rep->fs)
		return true;

	return false;
}

static inline void superfork_trace_phase(int phase, int ret, pid_t pid,
					 unsigned int count)
{
	trace_superfork_phase(phase, ret, pid, count);
}

static inline unsigned int superfork_bundle_count(const struct container_config *config)
{
	return config ? config->aux_bundle_count + 1 : 0;
}

static int superfork_get_domain_root_path(const struct sf_ns_domain *domain,
					  struct path *path);
static int superfork_capture_path_string(const struct path *path,
					 char *dst, size_t dst_sz);

static void superfork_capture_path_or_placeholder(const struct path *path,
						  char *dst, size_t dst_sz)
{
	int ret;

	if (!dst_sz)
		return;

	if (!path) {
		strscpy(dst, "<null>", dst_sz);
		return;
	}

	ret = superfork_capture_path_string(path, dst, dst_sz);
	if (ret < 0)
		snprintf(dst, dst_sz, "<err:%d>", ret);
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

static char *superfork_bundle_runtime_path(const char *bundle_path)
{
	const char *run;

	run = superfork_find_run_component(bundle_path);
	if (!run)
		return NULL;

	return kstrdup(run, GFP_KERNEL);
}

static char *superfork_derive_sbs_path(const char *bundle_path)
{
	static const char marker[] = "/run/vc/vm/";
	const char *vm;
	const char *sandbox;
	size_t prefix_len;

	if (!bundle_path)
		return NULL;

	vm = strstr(bundle_path, marker);
	if (!vm)
		return NULL;

	sandbox = vm + strlen(marker);
	if (!sandbox[0])
		return NULL;

	prefix_len = vm - bundle_path;
	return kasprintf(GFP_KERNEL, "%.*s/run/vc/sbs/%s",
			 (int)prefix_len, bundle_path, sandbox);
}

static char *superfork_derive_sbs_runtime_path(const char *bundle_path)
{
	static const char marker[] = "/run/vc/vm/";
	const char *vm;
	const char *sandbox;

	if (!bundle_path)
		return NULL;

	vm = strstr(bundle_path, marker);
	if (!vm)
		return NULL;

	sandbox = vm + strlen(marker);
	if (!sandbox[0])
		return NULL;

	return kasprintf(GFP_KERNEL, "/run/vc/sbs/%s", sandbox);
}

static int superfork_switch_current_to_domain_mntns(const struct sf_ns_domain *domain,
						    struct nsproxy **saved_nsproxy,
						    struct path *saved_root,
						    struct path *saved_pwd)
{
	struct mnt_namespace *mnt_ns;
	struct path new_root;
	int ret;

	if (!domain || !domain->new_nsproxy || !domain->new_nsproxy->mnt_ns ||
	    !domain->new_nsproxy->mnt_ns->root)
		return -EINVAL;

	*saved_nsproxy = superfork_get_task_nsproxy(current);
	if (!*saved_nsproxy)
		return -EINVAL;

	get_fs_root(current->fs, saved_root);
	get_fs_pwd(current->fs, saved_pwd);

	mnt_ns = domain->new_nsproxy->mnt_ns;
	ret = vfs_path_lookup(mnt_ns->root->mnt.mnt_root,
			      &mnt_ns->root->mnt, "/",
			      LOOKUP_DOWN, &new_root);
	if (ret < 0)
		goto out_put_saved_ns;

	get_nsproxy(domain->new_nsproxy);
	switch_task_namespaces(current, domain->new_nsproxy);
	set_fs_root(current->fs, &new_root);
	set_fs_pwd(current->fs, &new_root);
	path_put(&new_root);
	return 0;

out_put_saved_ns:
	path_put(saved_root);
	path_put(saved_pwd);
	put_nsproxy(*saved_nsproxy);
	*saved_nsproxy = NULL;
	return ret;
}

static void superfork_restore_current_mntns(struct nsproxy *saved_nsproxy,
					    struct path *saved_root,
					    struct path *saved_pwd)
{
	if (!saved_nsproxy)
		return;

	switch_task_namespaces(current, saved_nsproxy);
	set_fs_root(current->fs, saved_root);
	set_fs_pwd(current->fs, saved_pwd);
	path_put(saved_root);
	path_put(saved_pwd);
}

static int superfork_make_domain_mounts_private(const struct sf_ns_domain *domain)
{
	struct nsproxy *saved_nsproxy = NULL;
	struct path saved_root = {};
	struct path saved_pwd = {};
	struct path root = {};
	int ret;

	ret = superfork_switch_current_to_domain_mntns(domain, &saved_nsproxy,
						       &saved_root, &saved_pwd);
	if (ret < 0)
		return ret;

	ret = superfork_domain_lookup_path(domain, "/",
					   LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
					   &root);
	if (ret < 0)
		goto out_restore;

	ret = path_mount(NULL, &root, NULL, MS_PRIVATE | MS_REC, NULL);
	path_put(&root);

out_restore:
	superfork_restore_current_mntns(saved_nsproxy, &saved_root, &saved_pwd);
	return ret;
}

static int superfork_bind_mount_in_domain(const struct sf_ns_domain *domain,
					  const char *src_path,
					  const char *target_path)
{
	struct nsproxy *saved_nsproxy = NULL;
	struct path saved_root = {};
	struct path saved_pwd = {};
	struct path target = {};
	struct path src = {};
	struct path target_current = {};
	struct path fs_root = {};
	struct path fs_pwd = {};
	char fs_root_buf[128];
	char fs_pwd_buf[128];
	char src_buf[128];
	char target_buf[128];
	char target_current_buf[128];
	int src_lookup_ret;
	int target_current_ret;
	int ret;

	if (!src_path || !target_path)
		return -EINVAL;

	ret = superfork_switch_current_to_domain_mntns(domain, &saved_nsproxy,
						       &saved_root, &saved_pwd);
	if (ret < 0)
		return ret;

	get_fs_root(current->fs, &fs_root);
	superfork_capture_path_or_placeholder(&fs_root, fs_root_buf,
					      sizeof(fs_root_buf));
	path_put(&fs_root);

	get_fs_pwd(current->fs, &fs_pwd);
	superfork_capture_path_or_placeholder(&fs_pwd, fs_pwd_buf,
					      sizeof(fs_pwd_buf));
	path_put(&fs_pwd);

	src_lookup_ret = kern_path(src_path, LOOKUP_FOLLOW | LOOKUP_AUTOMOUNT, &src);
	if (!src_lookup_ret) {
		superfork_capture_path_or_placeholder(&src, src_buf,
						      sizeof(src_buf));
		path_put(&src);
	} else {
		snprintf(src_buf, sizeof(src_buf), "<lookup:%d>", src_lookup_ret);
	}

	target_current_ret = kern_path(target_path,
				       LOOKUP_FOLLOW | LOOKUP_DIRECTORY,
				       &target_current);
	if (!target_current_ret) {
		superfork_capture_path_or_placeholder(&target_current,
						      target_current_buf,
						      sizeof(target_current_buf));
	} else {
		snprintf(target_current_buf, sizeof(target_current_buf),
			 "<lookup:%d>", target_current_ret);
	}

	if (src_lookup_ret == -ENOENT || target_current_ret == -ENOENT) {
		pr_info("superfork: skipping runtime mount remap src='%s' target='%s' fs_root='%s' fs_pwd='%s' src_lookup=%d target_lookup=%d\n",
			src_path, target_path, fs_root_buf, fs_pwd_buf,
			src_lookup_ret, target_current_ret);
		ret = 0;
		goto out_restore;
	}

	if (target_current_ret < 0) {
		pr_err("superfork: bind target lookup failed src='%s' target='%s' ret=%d fs_root='%s' fs_pwd='%s' src_lookup=%d src_resolved='%s' target_current=%d target_current_resolved='%s'\n",
		       src_path, target_path, target_current_ret,
		       fs_root_buf, fs_pwd_buf, src_lookup_ret, src_buf,
		       target_current_ret, target_current_buf);
		ret = target_current_ret;
		goto out_restore;
	}

	target = target_current;
	superfork_capture_path_or_placeholder(&target, target_buf,
					      sizeof(target_buf));

	ret = path_mount(src_path, &target, NULL, MS_BIND, NULL);
	if (ret < 0)
		pr_err("superfork: bind mount failed src='%s' target='%s' ret=%d fs_root='%s' fs_pwd='%s' src_lookup=%d src_resolved='%s' target_domain_resolved='%s' target_current=%d target_current_resolved='%s'\n",
		       src_path, target_path, ret, fs_root_buf, fs_pwd_buf,
		       src_lookup_ret, src_buf, target_buf,
		       target_current_ret, target_current_buf);
	path_put(&target);

out_restore:
	superfork_restore_current_mntns(saved_nsproxy, &saved_root, &saved_pwd);
	return ret;
}

static int superfork_umount_mountpoint_in_domain(const struct sf_ns_domain *domain,
						 const char *target_path)
{
	struct nsproxy *saved_nsproxy = NULL;
	struct path saved_root = {};
	struct path saved_pwd = {};
	struct path target = {};
	int ret;

	if (!target_path)
		return -EINVAL;

	ret = superfork_switch_current_to_domain_mntns(domain, &saved_nsproxy,
						       &saved_root, &saved_pwd);
	if (ret < 0)
		return ret;

	ret = kern_path(target_path, LOOKUP_FOLLOW | LOOKUP_MOUNTPOINT, &target);
	if (ret == -ENOENT) {
		ret = 0;
		goto out_restore;
	}
	if (ret < 0)
		goto out_restore;

	ret = path_umount(&target, MNT_DETACH);
	if (ret == -EINVAL || ret == -ENOENT)
		ret = 0;

out_restore:
	superfork_restore_current_mntns(saved_nsproxy, &saved_root, &saved_pwd);
	return ret;
}

static int superfork_replace_runtime_mount_in_domain(const struct sf_ns_domain *domain,
						     const char *clone_path,
						     const char *runtime_path)
{
	int ret;

	if (!clone_path || !runtime_path)
		return -EINVAL;

	/*
	 * Replace the copied source runtime mount before rebinding the clone.
	 * If we bind on top first, any stale child mounts under the covered
	 * source tree become unreachable by pathname and cannot be detached.
	 */
	ret = superfork_umount_mountpoint_in_domain(domain, runtime_path);
	if (ret < 0) {
		pr_err("superfork: failed to clear runtime mount '%s': %d\n",
		       runtime_path, ret);
		return ret;
	}

	ret = superfork_bind_mount_in_domain(domain, clone_path, runtime_path);
	if (ret < 0) {
		pr_err("superfork: failed to remap runtime mount '%s' -> '%s': %d\n",
		       runtime_path, clone_path, ret);
		return ret;
	}

	pr_info("superfork: remapped runtime mount '%s' -> '%s'\n",
		runtime_path, clone_path);
	return 0;
}

static int superfork_overlay_shared_sandbox_mounts_in_domain(const struct sf_ns_domain *domain,
							     const char *runtime_root,
							     const char *clone_root)
{
	char *clone_mounts = NULL;
	char *runtime_shared = NULL;
	char *runtime_mounts = NULL;
	int ret;

	if (!runtime_root || !clone_root)
		return -EINVAL;

	clone_mounts = kasprintf(GFP_KERNEL, "%s/mounts", clone_root);
	runtime_shared = kasprintf(GFP_KERNEL, "%s/shared", runtime_root);
	runtime_mounts = kasprintf(GFP_KERNEL, "%s/mounts", runtime_root);
	if (!clone_mounts || !runtime_shared || !runtime_mounts) {
		ret = -ENOMEM;
		goto out_free;
	}

	ret = superfork_bind_mount_in_domain(domain, clone_mounts, runtime_shared);
	if (ret < 0) {
		pr_err("superfork: failed to overlay shared sandbox mount '%s' -> '%s': %d\n",
		       runtime_shared, clone_mounts, ret);
		goto out_free;
	}

	ret = superfork_bind_mount_in_domain(domain, clone_mounts, runtime_mounts);
	if (ret < 0) {
		pr_err("superfork: failed to overlay shared sandbox mount '%s' -> '%s': %d\n",
		       runtime_mounts, clone_mounts, ret);
		goto out_free;
	}

	pr_info("superfork: overlaid shared sandbox children '%s' and '%s' from '%s'\n",
		runtime_shared, runtime_mounts, clone_mounts);
	ret = 0;

out_free:
	kfree(clone_mounts);
	kfree(runtime_shared);
	kfree(runtime_mounts);
	return ret;
}

static int superfork_remap_domain_runtime_mounts(const struct sf_ns_domain *domain,
						 const struct container_config *config)
{
	char *src_path = NULL;
	char *dst_path = NULL;
	int ret;
	unsigned int i;

	ret = superfork_make_domain_mounts_private(domain);
	if (ret < 0) {
		pr_err("superfork: failed to privatize cloned mount namespace: %d\n",
		       ret);
		return ret;
	}

	src_path = superfork_bundle_runtime_path(config->root_src_bundle_path);
	dst_path = config->root_dst_bundle_path[0] ?
		kstrdup(config->root_dst_bundle_path, GFP_KERNEL) : NULL;
	if (!src_path || !dst_path) {
		ret = -ENOMEM;
		goto out_free_root;
	}

	ret = superfork_replace_runtime_mount_in_domain(domain, dst_path, src_path);
	if (ret < 0)
		goto out_free_root;

	kfree(src_path);
	kfree(dst_path);
	src_path = superfork_derive_sbs_runtime_path(config->root_src_bundle_path);
	dst_path = superfork_derive_sbs_path(config->root_dst_bundle_path);
	if (!src_path || !dst_path) {
		ret = -ENOMEM;
		goto out_free_root;
	}

	ret = superfork_replace_runtime_mount_in_domain(domain, dst_path, src_path);
	if (ret < 0)
		goto out_free_root;

	kfree(src_path);
	kfree(dst_path);
	src_path = NULL;
	dst_path = NULL;

	for (i = 0; i < config->aux_bundle_count; i++) {
		const char *aux_src = config->aux_src_bundle_paths[i];
		const char *aux_dst = config->aux_dst_bundle_paths[i];

		if (!aux_src[0] || !aux_dst[0])
			continue;

		src_path = superfork_bundle_runtime_path(aux_src);
		dst_path = kstrdup(aux_dst, GFP_KERNEL);
		if (!src_path || !dst_path) {
			ret = -ENOMEM;
			goto out_free_root;
		}

		ret = superfork_replace_runtime_mount_in_domain(domain,
							       dst_path,
							       src_path);
		if (ret < 0)
			goto out_free_root;

		if (!strncmp(src_path,
			     "/run/kata-containers/shared/sandboxes/",
			     strlen("/run/kata-containers/shared/sandboxes/"))) {
			ret = superfork_overlay_shared_sandbox_mounts_in_domain(domain,
									       src_path,
									       dst_path);
			if (ret < 0)
				goto out_free_root;
		}

		kfree(src_path);
		kfree(dst_path);
		src_path = NULL;
		dst_path = NULL;
	}

	return 0;

out_free_root:
	kfree(src_path);
	kfree(dst_path);
	return ret;
}

static int superfork_remap_runtime_mounts(struct container_clone_ctx *ctx,
					  const struct container_config *config)
{
	int i;
	int ret;

	for (i = 0; i < ctx->domain_count; i++) {
		ret = superfork_remap_domain_runtime_mounts(get_ctx_domain(ctx, i),
							     config);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int superfork_get_domain_root_path(const struct sf_ns_domain *domain,
					  struct path *path)
{
	struct mount *root_mnt;

	if (!domain || !domain->new_nsproxy || !domain->new_nsproxy->mnt_ns ||
	    !domain->new_nsproxy->mnt_ns->root)
		return -EINVAL;

	root_mnt = domain->new_nsproxy->mnt_ns->root;
	path->mnt = &root_mnt->mnt;
	path->dentry = root_mnt->mnt.mnt_root;
	path_get(path);
	return 0;
}

int superfork_domain_lookup_path(const struct sf_ns_domain *domain,
				     const char *path_name,
				     unsigned int lookup_flags,
				     struct path *path)
{
	struct path root;
	int ret;

	ret = superfork_get_domain_root_path(domain, &root);
	if (ret < 0)
		return ret;

	if (!path_name || !path_name[0] || !strcmp(path_name, "/")) {
		*path = root;
		return 0;
	}

	ret = vfs_path_lookup(root.dentry, root.mnt, path_name,
			      lookup_flags, path);
	path_put(&root);
	return ret;
}

struct file *superfork_domain_open_path(const struct sf_ns_domain *domain,
					    const char *path_name,
					    int open_flags,
					    umode_t mode)
{
	struct path root;
	struct file *file;
	int ret;

	ret = superfork_get_domain_root_path(domain, &root);
	if (ret < 0)
		return ERR_PTR(ret);

	file = file_open_root(&root,
			      (path_name && path_name[0]) ? path_name : "",
			      open_flags, mode);
	path_put(&root);
	return file;
}

static int superfork_capture_path_string(const struct path *path,
					 char *dst, size_t dst_sz)
{
	char *path_buf;
	char *resolved;
	int ret;

	path_buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!path_buf)
		return -ENOMEM;

	resolved = d_path(path, path_buf, PAGE_SIZE);
	if (IS_ERR(resolved)) {
		ret = PTR_ERR(resolved);
		goto out;
	}

	ret = strscpy(dst, resolved, dst_sz);
	if (ret < 0)
		ret = -ENAMETOOLONG;

out:
	kfree(path_buf);
	return ret;
}

static int superfork_capture_task_fs_paths(struct task_clone_entry *task)
{
	struct path root;
	struct path pwd;
	int ret;

	if (!task || !task->old_task || !task->old_task->fs)
		return -EINVAL;

	get_fs_root(task->old_task->fs, &root);
	ret = superfork_capture_path_string(&root, task->src_root_path,
					    sizeof(task->src_root_path));
	path_put(&root);
	if (ret < 0)
		return ret;

	get_fs_pwd(task->old_task->fs, &pwd);
	ret = superfork_capture_path_string(&pwd, task->src_pwd_path,
					    sizeof(task->src_pwd_path));
	path_put(&pwd);
	return ret;
}

static void superfork_release_task_domains(struct container_clone_ctx *ctx)
{
	int i;

	if (!ctx)
		return;

	for (i = 0; i < ctx->domain_count; i++) {
		struct sf_ns_domain *domain = get_ctx_domain(ctx, i);

		if (domain->new_nsproxy) {
			put_nsproxy(domain->new_nsproxy);
			domain->new_nsproxy = NULL;
		}
		if (domain->src_nsproxy) {
			put_nsproxy(domain->src_nsproxy);
			domain->src_nsproxy = NULL;
		}
		domain->src_task = NULL;
	}

	ctx->domain_count = 0;
}

static int superfork_prepare_task_domains(struct container_clone_ctx *ctx)
{
	int ret;

	ctx->domain_count = 0;

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct nsproxy *src_nsproxy;
		unsigned int domain_id;

		ret = superfork_capture_task_fs_paths(task);
		if (ret < 0) {
			pr_err("superfork: failed to capture fs paths for pid %d: %d\n",
			       task->old_task ? task->old_task->pid : -1, ret);
			goto err_release_domains;
		}

		src_nsproxy = superfork_get_task_nsproxy(task->old_task);
		if (!src_nsproxy || !src_nsproxy->pid_ns_for_children) {
			if (src_nsproxy)
				put_nsproxy(src_nsproxy);
			ret = -EINVAL;
			pr_err("superfork: task %d has no usable namespaces\n",
			       task->old_task ? task->old_task->pid : -1);
			goto err_release_domains;
		}

		for (domain_id = 0; domain_id < ctx->domain_count; domain_id++) {
			struct sf_ns_domain *domain = get_ctx_domain(ctx, domain_id);

			if (!superfork_same_namespace_domain(domain->src_nsproxy,
							     src_nsproxy))
				continue;

			task->domain_id = domain_id;
			if (superfork_prefer_domain_source_task(task->old_task,
							      domain->src_task))
				domain->src_task = task->old_task;
			put_nsproxy(src_nsproxy);
			src_nsproxy = NULL;
			goto next_task;
		}

		if (ctx->domain_count >= MAX_CLONE_TASKS) {
			put_nsproxy(src_nsproxy);
			ret = -E2BIG;
			goto err_release_domains;
		}

		if (!ctx->src_pid_ns)
			ctx->src_pid_ns = get_pid_ns(task_active_pid_ns(task->old_task));
		/* Tasks in different pid namespaces are allowed; multi-domain clones
		 * like qemu+virtiofsd legitimately span pid namespaces. src_pid_ns
		 * is only used to derive the parent for the new clone pid_ns. */

		task->domain_id = ctx->domain_count;
		get_ctx_domain(ctx, ctx->domain_count)->src_task = task->old_task;
		get_ctx_domain(ctx, ctx->domain_count)->src_nsproxy = src_nsproxy;
		ctx->domain_count++;

next_task:
		pr_debug("superfork: task %d assigned to domain %u root='%s' pwd='%s'\n",
			 task->old_task->pid, task->domain_id,
			 task->src_root_path, task->src_pwd_path);
	}

	if (!ctx->domain_count || !ctx->src_pid_ns) {
		ret = -EINVAL;
		goto err_release_domains;
	}

	return 0;

err_release_domains:
	superfork_release_task_domains(ctx);
	if (ctx->src_pid_ns) {
		put_pid_ns(ctx->src_pid_ns);
		ctx->src_pid_ns = NULL;
	}
	return ret;
}

static void superfork_release_task_seccomp(struct task_struct *p)
{
#ifdef CONFIG_SECCOMP
	if (!p || !p->sighand || !READ_ONCE(p->seccomp.filter))
		return;

	p->flags |= PF_EXITING;
	seccomp_filter_release(p);
#endif
}

static inline void superfork_mm_clear_owner(struct mm_struct *mm,
					    struct task_struct *p)
{
#ifdef CONFIG_MEMCG
	if (mm && mm->owner == p)
		WRITE_ONCE(mm->owner, NULL);
#endif
}

static void superfork_release_new_task(struct task_struct *p, bool post_fork_done)
{
	if (!post_fork_done)
		sched_cancel_fork(p);
	superfork_release_placeholder_peers(p);
	superfork_release_task_seccomp(p);
	if (p->thread_pid)
		free_pid(p->thread_pid);
	WRITE_ONCE(p->exit_state, EXIT_DEAD);
	put_task_struct(p);
}

static void superfork_discard_unattached_task(struct task_struct *p,
					      bool is_leader)
{
	if (!p)
		return;

	superfork_release_placeholder_peers(p);
	superfork_release_task_seccomp(p);
	exit_thread(p);
	exit_task_namespaces(p);

	if (is_leader && p->signal) {
		free_signal_struct(p->signal);
		p->signal = NULL;
	}

	__cleanup_sighand(p->sighand);
	p->sighand = NULL;

	exit_fs(p);
	exit_files(p);

	if (p->mm) {
		superfork_mm_clear_owner(p->mm, p);
		mmput(p->mm);
		p->mm = NULL;
		p->active_mm = NULL;
	}

	exit_sem(p);
	security_task_free(p);
	audit_free(p);
	perf_event_free_task(p);
	sched_cancel_fork(p);
	lockdep_free_task(p);
#ifdef CONFIG_NUMA
	mpol_put(p->mempolicy);
#endif
	delayacct_tsk_free(p);
	dec_rlimit_ucounts(task_ucounts(p), UCOUNT_RLIMIT_NPROC, 1);

	if (p->thread_pid) {
		free_pid(p->thread_pid);
		p->thread_pid = NULL;
	}

	exit_creds(p);
	sched_core_free(p);
	ftrace_graph_exit_task(p);
	WRITE_ONCE(p->exit_state, EXIT_DEAD);
	superfork_free_task_struct(p);
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

static const char *superfork_primary_dst_bundle_path(const struct container_config *config)
{
	return config ? config->root_dst_bundle_path : NULL;
}

static int superfork_copy_user_path(char *dst, size_t dst_sz,
				       const char __user *upath,
				       const char *field_name)
{
	long copied;

	if (!upath)
		return -EINVAL;

	copied = strncpy_from_user(dst, upath, dst_sz);
	if (copied < 0)
		return copied;
	if (copied == 0)
		return -EINVAL;
	if (copied >= dst_sz) {
		pr_err("superfork: %s too long\n", field_name);
		return -ENAMETOOLONG;
	}

	return 0;
}

static int superfork_copy_config_from_user(struct container_config *config,
					   const struct container_config_user __user *user_config)
{
	struct container_config_user *user_cfg;
	unsigned int i;
	int ret;

	user_cfg = memdup_user(user_config, sizeof(*user_cfg));
	if (IS_ERR(user_cfg)) {
		pr_err("superfork: copy_from_user config failed\n");
		return PTR_ERR(user_cfg);
	}

	memset(config, 0, sizeof(*config));
	memcpy(config->src_cgroup_path, user_cfg->src_cgroup_path,
	       sizeof(config->src_cgroup_path));
	memcpy(config->root_src_bundle_path, user_cfg->root_src_bundle_path,
	       sizeof(config->root_src_bundle_path));
	memcpy(config->root_dst_bundle_path, user_cfg->root_dst_bundle_path,
	       sizeof(config->root_dst_bundle_path));
	memcpy(&config->btrfs_args, &user_cfg->btrfs_args, sizeof(config->btrfs_args));
	config->aux_bundle_count = user_cfg->aux_bundle_count;

	if (!config->root_src_bundle_path[0] || !config->root_dst_bundle_path[0]) {
		ret = -EINVAL;
		goto out_free_user_cfg;
	}

	if (user_cfg->aux_bundle_count > SF_MAX_BUNDLES) {
		pr_err("superfork: aux_bundle_count %u exceeds max %u\n",
		       user_cfg->aux_bundle_count, SF_MAX_BUNDLES);
		ret = -E2BIG;
		goto out_free_user_cfg;
	}

	if (user_cfg->aux_bundle_count &&
	    (!user_cfg->aux_src_bundle_paths_ptr || !user_cfg->aux_dst_bundle_paths_ptr)) {
		ret = -EINVAL;
		goto out_free_user_cfg;
	}

	for (i = 0; i < user_cfg->aux_bundle_count; i++) {
		const char __user *src_upath;
		const char __user *dst_upath;

		if (get_user(src_upath,
			     &((const char __user * __user *)u64_to_user_ptr(user_cfg->aux_src_bundle_paths_ptr))[i])) {
			ret = -EFAULT;
			goto out_free_user_cfg;
		}
		if (get_user(dst_upath,
			     &((const char __user * __user *)u64_to_user_ptr(user_cfg->aux_dst_bundle_paths_ptr))[i])) {
			ret = -EFAULT;
			goto out_free_user_cfg;
		}

		ret = superfork_copy_user_path(config->aux_src_bundle_paths[i],
					       sizeof(config->aux_src_bundle_paths[i]),
					       src_upath, "aux_src_bundle_paths");
		if (ret < 0)
			goto out_free_user_cfg;

		ret = superfork_copy_user_path(config->aux_dst_bundle_paths[i],
					       sizeof(config->aux_dst_bundle_paths[i]),
					       dst_upath, "aux_dst_bundle_paths");
		if (ret < 0)
			goto out_free_user_cfg;
	}

	ret = 0;

out_free_user_cfg:
	kfree(user_cfg);
	return ret;
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
	ctx->tgids[ctx->tgid_count].fs_share_count = 0;
	ctx->tgids[ctx->tgid_count].cred_share_count = 0;
	ctx->tgids[ctx->tgid_count].kvm_vm_count = 0;
	ctx->tgids[ctx->tgid_count].procfs_reopen_count = 0;
	ctx->tgids[ctx->tgid_count].pidfd_reopen_count = 0;

	return &ctx->tgids[ctx->tgid_count++];
}

/* ---- namespace setup --------------------------------------------------- */

static int superfork_setup_container_namespaces(struct container_clone_ctx *ctx)
{
	struct user_namespace *user_ns;
	const struct cred *cred;
	unsigned long ns_flags;
	struct sf_ns_domain *first_domain;
	int ret;
	struct pid_namespace *parent_ns;
	int i;

	if (!ctx || !ctx->domain_count || !ctx->src_pid_ns) {
		pr_err("superfork: invalid namespace setup context\n");
		return -EINVAL;
	}

	first_domain = get_ctx_domain(ctx, 0);
	if (!first_domain->src_task || !first_domain->src_nsproxy) {
		pr_err("superfork: namespace domain 0 is incomplete\n");
		return -EINVAL;
	}

	pr_debug("superfork: prepared %d namespace domains, src pid_ns=%p\n",
		 ctx->domain_count, ctx->src_pid_ns);

	/* Get user namespace for PID namespace creation */
	cred = get_task_cred(first_domain->src_task);
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

	/* Always isolate mount/ipc/uts/cgroup/net and PID namespaces. */
	ns_flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS |
		   CLONE_NEWCGROUP | CLONE_NEWNET;

	put_user_ns(user_ns);

	for (i = 0; i < ctx->domain_count; i++) {
		struct sf_ns_domain *domain = get_ctx_domain(ctx, i);

		cred = get_task_cred(domain->src_task);
		user_ns = get_user_ns(cred->user_ns);
		put_cred(cred);

		domain->new_nsproxy = create_new_namespaces(ns_flags, domain->src_task,
							    user_ns, domain->src_task->fs);
		put_user_ns(user_ns);

		if (IS_ERR(domain->new_nsproxy)) {
			ret = PTR_ERR(domain->new_nsproxy);
			domain->new_nsproxy = NULL;
			pr_err("superfork: failed to create nsproxy for domain %d (task=%d flags=0x%lx): %d\n",
			       i, domain->src_task->pid, ns_flags, ret);
			superfork_release_task_domains(ctx);
			put_pid_ns(ctx->new_pid_ns);
			ctx->new_pid_ns = NULL;
			return ret;
		}

		put_pid_ns(domain->new_nsproxy->pid_ns_for_children);
		domain->new_nsproxy->pid_ns_for_children = get_pid_ns(ctx->new_pid_ns);

		pr_debug("superfork: domain %d nsproxy %p -> %p (task=%d)\n",
			 i, domain->src_nsproxy, domain->new_nsproxy,
			 domain->src_task->pid);
		pr_debug("    PID ns:   %p (shared)\n",
			 domain->new_nsproxy->pid_ns_for_children);
		pr_debug("    Mount ns: %p (NEW)\n", domain->new_nsproxy->mnt_ns);
		pr_debug("    IPC ns:   %p (NEW)\n", domain->new_nsproxy->ipc_ns);
		pr_debug("    UTS ns:   %p (NEW)\n", domain->new_nsproxy->uts_ns);
		pr_debug("    Net ns:   %p (NEW)\n", domain->new_nsproxy->net_ns);
	}

	return 0;
}

/* ---- process clone loop ------------------------------------------------ */

static int superfork_clone_processes(struct container_clone_ctx *ctx,
				     const struct container_config *config)
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

		new_task = superfork_copy_process(ctx, task, tgid_entry,
					  config, true);
		if (IS_ERR(new_task)) {
			ret = PTR_ERR(new_task);
			goto cleanup_after_leaders;
		}

		task->new_task = new_task;
		task->attached = false;
		trace_superfork_task_clone(task->old_task->pid, task->old_tgid,
					 new_task->pid, true);

		if (new_init_pid == 0)
			new_init_pid = new_task->pid;
	}
	superfork_trace_phase(SUPERFORK_PHASE_CLONE_LEADERS, 0, new_init_pid,
			      ctx->task_count);

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

		new_task = superfork_copy_process(ctx, task, tgid_entry,
					  config, false);
		if (IS_ERR(new_task)) {
			ret = PTR_ERR(new_task);
			goto cleanup_after_leaders;
		}

		task->new_task = new_task;
		task->attached = false;
		trace_superfork_task_clone(task->old_task->pid, task->old_tgid,
					 new_task->pid, false);
	}
	superfork_trace_phase(SUPERFORK_PHASE_CLONE_THREADS, 0, new_init_pid,
			      ctx->task_count);

	ret = superfork_verify_cloned_fds(ctx);
	superfork_trace_phase(SUPERFORK_PHASE_VERIFY_FDS, ret, new_init_pid,
			      ctx->task_count);
	if (ret < 0) {
		pr_err("superfork: fd verification failed: %d\n", ret);
		goto cleanup_after_leaders;
	}
	/* Phase 4: Attach tasks */
	ret = superfork_attach_tasks(ctx);
	superfork_trace_phase(SUPERFORK_PHASE_ATTACH_TASKS, ret, new_init_pid,
			      ctx->task_count);
	if (ret < 0) {
		pr_err("superfork: attach_tasks failed: %d\n", ret);
		goto cleanup_after_leaders;
	}

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
	superfork_trace_phase(SUPERFORK_PHASE_CLONE_PROCESSES_FAILED, ret,
			      new_init_pid,
			       ctx->task_count);
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
		struct task_struct *p = task->new_task;

		if (!p || task->is_leader)
			continue;

		if (!task->attached)
			superfork_discard_unattached_task(p, false);
		else
			superfork_release_new_task(p, false);
		task->new_task = NULL;
		task->attached = false;
	}

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *p = task->new_task;

		if (!p || !task->is_leader)
			continue;

		if (!task->attached)
			superfork_discard_unattached_task(p, true);
		else
			superfork_release_new_task(p, false);
		task->new_task = NULL;
		task->attached = false;
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
		struct task_struct *p = task->new_task;

		if (!p || task->is_leader)
			continue;

		if (!task->attached)
			superfork_discard_unattached_task(p, false);
		else
			superfork_release_new_task(p, ctx->post_fork_done);
		task->new_task = NULL;
		task->attached = false;
	}

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);
		struct task_struct *p = task->new_task;

		if (!p || !task->is_leader)
			continue;

		if (!task->attached)
			superfork_discard_unattached_task(p, true);
		else
			superfork_release_new_task(p, ctx->post_fork_done);
		task->new_task = NULL;
		task->attached = false;
	}

	release_collected_tasks(ctx);
	if (ctx->new_pid_ns) {
		put_pid_ns(ctx->new_pid_ns);
		ctx->new_pid_ns = NULL;
	}
	if (ctx->src_pid_ns) {
		put_pid_ns(ctx->src_pid_ns);
		ctx->src_pid_ns = NULL;
	}
	superfork_release_internal_pipe_edges(ctx);
	superfork_release_internal_unix_edges(ctx);
	superfork_release_allowed_shared_files(ctx);
	superfork_release_task_domains(ctx);
}

/* ---- container phase sequencer ----------------------------------------- */

static int clone_container(struct container_clone_ctx *ctx,
			   pid_t *kpids, size_t count,
			   struct container_config *config,
			   pid_t *new_init_pid)
{
	int ret;
	pid_t init_pid = 0;
	pid_t ns_trace_pid = 0;

	pr_debug("superfork: Phase 0 - collecting frozen tasks\n");

	ret = collect_frozen_tasks(ctx, kpids, count);
	superfork_trace_phase(SUPERFORK_PHASE_COLLECT_FROZEN_TASKS, ret, 0,
			      ctx->task_count);

	if (ret < 0) {
		pr_err("superfork: failed to collect frozen tasks: %d\n", ret);
		return ret;
	}

	if (ctx->task_count == 0) {
		pr_err("superfork: no tasks collected\n");
		ret = -ESRCH;
		goto cleanup_final;
	}

	ret = superfork_prepare_task_domains(ctx);
	if (ret < 0) {
		pr_err("superfork: task domain preparation failed: %d\n", ret);
		goto cleanup_final;
	}

	ret = superfork_prepare_internal_unix_edges(ctx);
	if (ret < 0) {
		pr_err("superfork: internal unix edge preparation failed: %d\n", ret);
		goto cleanup_final;
	}

	ret = superfork_prepare_internal_pipe_edges(ctx);
	if (ret < 0) {
		pr_err("superfork: internal pipe edge preparation failed: %d\n", ret);
		goto cleanup_final;
	}

	if (ctx->domain_count > 0 && get_ctx_domain(ctx, 0)->src_task)
		ns_trace_pid = get_ctx_domain(ctx, 0)->src_task->pid;

	ret = superfork_setup_container_namespaces(ctx);
	superfork_trace_phase(SUPERFORK_PHASE_SETUP_NAMESPACES, ret,
			      ns_trace_pid,
			       ctx->task_count);
	if (ret < 0) {
		pr_err("superfork: namespace setup failed: %d\n", ret);
		goto cleanup_final;
	}

	ret = superfork_remap_runtime_mounts(ctx, config);
	if (ret < 0) {
		pr_err("superfork: runtime mount remap failed: %d\n", ret);
		goto cleanup_final;
	}

	pr_info("superfork: using cloned root bundle path: '%s'\n",
		superfork_primary_dst_bundle_path(config));

	init_pid = superfork_clone_processes(ctx, config);
	superfork_trace_phase(SUPERFORK_PHASE_CLONE_PROCESSES,
			      init_pid < 0 ? init_pid : 0,
			       init_pid < 0 ? 0 : init_pid, ctx->task_count);
	if (init_pid < 0) {
		ret = init_pid;
		goto cleanup_destroy;
	}

	*new_init_pid = init_pid;
	superfork_trace_phase(SUPERFORK_PHASE_CONTAINER_CREATED, 0, init_pid,
			      ctx->task_count);

	pr_info("superfork: container created successfully, init=%d\n", init_pid);

	/*
	 * Note: We don't release ctx resources here because the caller
	 * (syscall handler) needs to do final cleanup and wake tasks.
	 */
	return 0;

cleanup_destroy:
	superfork_trace_phase(SUPERFORK_PHASE_DESTROY_CONTAINER, ret, 0,
			      ctx->task_count);
	superfork_destroy_container(ctx);
	return ret;

cleanup_final:
	pr_warn("superfork: cleaning up after early failure\n");
	superfork_trace_phase(SUPERFORK_PHASE_CLEANUP_EARLY_FAILURE, ret, 0,
			      ctx->task_count);

	release_collected_tasks(ctx);

	if (ctx->new_pid_ns) {
		put_pid_ns(ctx->new_pid_ns);
		ctx->new_pid_ns = NULL;
	}
	if (ctx->src_pid_ns) {
		put_pid_ns(ctx->src_pid_ns);
		ctx->src_pid_ns = NULL;
	}
	superfork_release_internal_pipe_edges(ctx);
	superfork_release_internal_unix_edges(ctx);
	superfork_release_allowed_shared_files(ctx);
	superfork_release_task_domains(ctx);

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

static int btrfs_snapshot_one(struct container_config_user __user *user_config,
			      const char *src,
			      const char *dst)
{
	struct file *src_file = NULL, *dst_dir_file = NULL;
	char *kdst, *dst_name;
	int src_fd = -1;
	int ret = 0;

	/* open src_bundle_path — we need an fd for the source subvolume */
	src_file = filp_open(src, O_RDONLY | O_DIRECTORY, 0);
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

	dst_name = strrchr(kdst, '/');
	if (!dst_name || dst_name == kdst) {
		ret = -EINVAL;
		goto out_free_dst;
	}
	*dst_name++ = '\0';

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

static int btrfs_snapshot(const struct container_config *config,
			  struct container_config_user __user *user_config)
{
	unsigned int i, bundle_count;
	int ret;

	bundle_count = superfork_bundle_count(config);
	if (!bundle_count)
		return -EINVAL;

	for (i = 0; i < bundle_count; i++) {
		const char *src = superfork_bundle_src_path(config, i);
		const char *dst = superfork_bundle_dst_path(config, i);

		if (!src || !src[0] || !dst || !dst[0])
			return -EINVAL;

		ret = btrfs_snapshot_one(user_config, src, dst);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/* ---- syscall entry ----------------------------------------------------- */

SYSCALL_DEFINE4(superfork,
		pid_t __user *, pids,
		size_t, count,
		struct container_config_user __user *, user_config,
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

	ret = superfork_copy_config_from_user(config, user_config);
	if (ret < 0)
		goto out_free_config;
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
	superfork_trace_phase(SUPERFORK_PHASE_PREPARE_SOURCE_CGROUPS, ret, 0,
			      count);
	if (ret < 0)
		goto out_cleanup;

	/*
	 * Pre-allocate per-thread pt_regs snapshot slots before freezing so
	 * KVM's block loop can capture the vCPU's userspace frame when the
	 * freezer signal arrives. See superfork_kvm_vcpu_snapshot_entry().
	 */
	ret = superfork_alloc_vcpu_snaps(kpids, count);
	superfork_trace_phase(SUPERFORK_PHASE_ALLOC_VCPU_SNAPS, ret, 0, count);
	if (ret < 0) {
		pr_err("superfork: alloc_vcpu_snaps failed: %d\n", ret);
		goto out_cleanup;
	}

	ret = cgroup_freeze_sync(src_cgrp);
	superfork_trace_phase(SUPERFORK_PHASE_FREEZE_SOURCE_CGROUP, ret, 0,
			      count);
	if (ret < 0) {
		pr_err("superfork: cgroup_freeze_sync failed: %d\n", ret);
		goto out_cleanup;
	}
	src_cgrp_frozen = true;
	pr_info("superfork: src cgroup frozen\n");

	ret = wait_source_tasks_frozen(kpids, count);
	superfork_trace_phase(SUPERFORK_PHASE_WAIT_SOURCE_FROZEN, ret, 0,
			      count);
	if (ret < 0) {
		pr_err("superfork: timed out waiting for source tasks to freeze\n");
		goto out_cleanup;
	}

	ret = btrfs_snapshot(config, user_config);
	superfork_trace_phase(SUPERFORK_PHASE_BTRFS_SNAPSHOT, ret, 0, count);
	if (ret < 0) {
		pr_err("superfork: btrfs_snapshot failed for root bundle '%s' -> '%s': %d\n",
		       superfork_bundle_src_path(config, 0),
		       superfork_primary_dst_bundle_path(config), ret);
		goto out_cleanup;
	}
	pr_info("superfork: snapshot set created; root bundle '%s' -> '%s'\n",
		superfork_bundle_src_path(config, 0),
		superfork_primary_dst_bundle_path(config));

	ret = clone_container(ctx, kpids, count, config, &new_init_pid);
	superfork_trace_phase(SUPERFORK_PHASE_CLONE_CONTAINER, ret,
			      new_init_pid,
			       ctx->task_count);
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
	superfork_trace_phase(SUPERFORK_PHASE_THAW_SOURCE_CGROUP, ret,
			      new_init_pid, count);
	if (ret < 0)
		goto out_destroy_container;
	src_cgrp_frozen = false;

	restore_ret = superfork_restore_source_task_cgroups(src_moves, count);
	superfork_trace_phase(SUPERFORK_PHASE_RESTORE_SOURCE_CGROUPS,
			      restore_ret,
			       new_init_pid, count);
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
	superfork_trace_phase(SUPERFORK_PHASE_SEED_CGROUP_MEMBERSHIP, ret,
			      new_init_pid,
			       ctx->task_count);
	if (ret < 0) {
		pr_err("superfork: seed_cgroup_membership failed: %d\n", ret);
		goto out_destroy_container;
	}

	/* Phase 5: Post-fork setup (must run after cgroup seeding). */
	superfork_post_fork(ctx);
	superfork_trace_phase(SUPERFORK_PHASE_POST_FORK, 0, new_init_pid,
			      ctx->task_count);

	if (copy_to_user(user_new_init_pid, &new_init_pid, sizeof(pid_t))) {
		pr_err("superfork: copy_to_user new_init_pid failed\n");
		ret = -EFAULT;
		superfork_trace_phase(SUPERFORK_PHASE_COPY_NEW_INIT_PID, ret,
				      new_init_pid,
				       ctx->task_count);
		goto out_destroy_container;
	}
	superfork_trace_phase(SUPERFORK_PHASE_COPY_NEW_INIT_PID, 0,
			      new_init_pid,
			       ctx->task_count);
	pr_info("superfork: userspace pid copied; waking cloned tasks\n");

	pr_info("superfork: Phase 4 - waking tasks\n");
	superfork_wake_tasks(ctx);
	superfork_trace_phase(SUPERFORK_PHASE_WAKE_TASKS, 0, new_init_pid,
			      ctx->task_count);

	ret = 0;
	goto out_cleanup;

out_destroy_container:
	superfork_trace_phase(SUPERFORK_PHASE_DESTROY_CONTAINER, ret,
			      new_init_pid,
			       ctx->task_count);
	superfork_destroy_container(ctx);

out_cleanup:
	if (src_cgrp_frozen) {
		thaw_ret = superfork_thaw_source_cgroup_sync(src_cgrp, "cleanup");
		superfork_trace_phase(
			      SUPERFORK_PHASE_THAW_SOURCE_CGROUP_CLEANUP,
			      thaw_ret,
				       new_init_pid, count);
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
	if (ctx->new_pid_ns)
		put_pid_ns(ctx->new_pid_ns);
	if (ctx->src_pid_ns)
		put_pid_ns(ctx->src_pid_ns);
	superfork_release_internal_pipe_edges(ctx);
	superfork_release_internal_unix_edges(ctx);
	superfork_release_allowed_shared_files(ctx);
	superfork_release_task_domains(ctx);

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
