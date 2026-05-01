/* SPDX-License-Identifier: GPL-2.0 */
/*
 * superfork internal header — types and prototypes shared across the
 * kernel/superfork/ source files.  Not for inclusion outside this directory.
 */
#ifndef _SUPERFORK_INTERNAL_H
#define _SUPERFORK_INTERNAL_H

#include <linux/string.h>
#include <linux/superfork.h>

/*
 * Inline accessor so every file can iterate the task array without
 * embedding knowledge of the layout.
 */
static inline struct task_clone_entry *get_ctx_task(struct container_clone_ctx *ctx, int i)
{
	return &ctx->tasks[i];
}

static inline struct sf_ns_domain *get_ctx_domain(struct container_clone_ctx *ctx, int i)
{
	return &ctx->domains[i];
}

static inline bool superfork_comm_is_containerd_shim(const char *comm)
{
	return comm && !strcmp(comm, "containerd-shim");
}

static inline bool superfork_comm_is_virtiofsd(const char *comm)
{
	return comm && !strcmp(comm, "virtiofsd");
}

static inline bool superfork_task_is_containerd_shim(const struct task_struct *task)
{
	return task && superfork_comm_is_containerd_shim(task->comm);
}

static inline bool superfork_task_is_virtiofsd(const struct task_struct *task)
{
	return task && superfork_comm_is_virtiofsd(task->comm);
}

static inline pid_t superfork_map_old_pid_to_new_nr(
				struct container_clone_ctx *ctx,
				pid_t old_pid,
				struct pid_namespace *old_ns,
				struct pid_namespace *new_ns)
{
	if (!ctx || old_pid <= 0 || !old_ns || !new_ns)
		return 0;

	for_each_task_in_ctx(ctx) {
		struct task_clone_entry *task = get_ctx_task(ctx, i);

		if (!task->old_task || !task->new_task)
			continue;
		if (task_pid_nr_ns(task->old_task, old_ns) != old_pid)
			continue;

		return task_pid_nr_ns(task->new_task, new_ns);
	}

	return 0;
}

/*
 * Per-leader record used while migrating source tasks into src_cgrp before
 * freezing and restoring them afterward.
 */
struct sf_src_cgroup_move {
	pid_t              tgid;
	struct task_struct *leader;
	struct cgroup      *orig_cgrp;
	bool               moved;
};

/* ---- freeze.c ---------------------------------------------------------- */

int  cgroup_freeze_sync(struct cgroup *cgrp);
int  cgroup_thaw_sync(struct cgroup *cgrp);
int  superfork_thaw_source_cgroup_sync(struct cgroup *src_cgrp, const char *stage);
int  superfork_prepare_source_task_cgroups(struct cgroup *src_cgrp,
					   const pid_t *kpids, size_t count,
					   struct sf_src_cgroup_move *moves);
int  superfork_restore_source_task_cgroups(struct sf_src_cgroup_move *moves,
					   size_t count);
void superfork_put_source_task_cgroup_moves(struct sf_src_cgroup_move *moves,
					    size_t count);
int  superfork_alloc_vcpu_snaps(pid_t *kpids, size_t count);
void superfork_free_vcpu_snaps(pid_t *kpids, size_t count);
int  wait_source_tasks_frozen(pid_t *kpids, size_t count);
int  collect_frozen_tasks(struct container_clone_ctx *ctx,
			  pid_t *kpids, size_t count);
void release_collected_tasks(struct container_clone_ctx *ctx);

/* ---- superfork.c ------------------------------------------------------- */

struct tgid_clone_entry *find_or_create_tgid_entry(struct container_clone_ctx *ctx,
						    pid_t old_tgid);
int  superfork_domain_lookup_path(const struct sf_ns_domain *domain,
				      const char *path_name,
				      unsigned int lookup_flags,
				      struct path *path);
struct file *superfork_domain_open_path(const struct sf_ns_domain *domain,
					     const char *path_name,
					     int open_flags,
					     umode_t mode);
int  superfork_switch_current_to_domain_mntns(const struct sf_ns_domain *domain,
					      struct nsproxy **saved_nsproxy,
					      struct path *saved_root,
					      struct path *saved_pwd);
void superfork_restore_current_mntns(struct nsproxy *saved_nsproxy,
				     struct path *saved_root,
				     struct path *saved_pwd);

/* ---- fd.c -------------------------------------------------------------- */

struct files_struct *superfork_dup_files_for_container(
	struct container_clone_ctx *ctx,
	struct files_struct *oldf,
	const struct container_config *config,
	const struct sf_ns_domain *domain,
	struct task_struct *owner_task,
	struct mm_struct *new_mm,
	struct tgid_clone_entry *tgid_entry);
int  superfork_verify_cloned_fds(struct container_clone_ctx *ctx);
int  superfork_replace_file_at(struct files_struct *files, unsigned int fd,
			       struct file *replacement);
int  superfork_reopen_procfs_fds(struct container_clone_ctx *ctx);
int  superfork_reopen_pidfds(struct container_clone_ctx *ctx);
int  superfork_prepare_internal_unix_edges(struct container_clone_ctx *ctx);
int  superfork_prepare_internal_pipe_edges(struct container_clone_ctx *ctx);
void superfork_release_internal_pipe_edges(struct container_clone_ctx *ctx);
void superfork_release_internal_unix_edges(struct container_clone_ctx *ctx);
void superfork_release_allowed_shared_files(struct container_clone_ctx *ctx);

/* ---- kvm.c ------------------------------------------------------------- */

#ifdef CONFIG_KVM
int superfork_clone_kvm_vm_fd(struct files_struct *files, unsigned int fd,
			      struct file *src_file, struct mm_struct *new_mm,
			      struct tgid_clone_entry *tgid_entry);
int superfork_clone_kvm_vcpu_fd(struct files_struct *files, unsigned int fd,
				struct file *src_file, struct mm_struct *new_mm,
				struct tgid_clone_entry *tgid_entry);
#endif /* CONFIG_KVM */

/* ---- attach.c ---------------------------------------------------------- */

int  superfork_attach_tasks(struct container_clone_ctx *ctx);
void superfork_post_fork(struct container_clone_ctx *ctx);
int  superfork_seed_cgroup_membership(struct container_clone_ctx *ctx);
void superfork_wake_tasks(struct container_clone_ctx *ctx);

#endif /* _SUPERFORK_INTERNAL_H */
