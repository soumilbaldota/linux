/* SPDX-License-Identifier: GPL-2.0 */
/*
 * superfork internal header — types and prototypes shared across the
 * kernel/superfork/ source files.  Not for inclusion outside this directory.
 */
#ifndef _SUPERFORK_INTERNAL_H
#define _SUPERFORK_INTERNAL_H

#include <linux/superfork.h>

/*
 * Inline accessor so every file can iterate the task array without
 * embedding knowledge of the layout.
 */
static inline struct task_clone_entry *get_ctx_task(struct container_clone_ctx *ctx, int i)
{
	return &ctx->tasks[i];
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

/* ---- fd.c -------------------------------------------------------------- */

struct files_struct *superfork_dup_files_for_container(
	struct files_struct *oldf,
	const char *src_bundle_path,
	const char *dst_bundle_path,
	struct mm_struct *new_mm,
	struct tgid_clone_entry *tgid_entry);
int  superfork_verify_cloned_fds(struct container_clone_ctx *ctx);
int  superfork_replace_file_at(struct files_struct *files, unsigned int fd,
			       struct file *replacement);

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

void superfork_attach_tasks(struct container_clone_ctx *ctx);
void superfork_post_fork(struct container_clone_ctx *ctx);
int  superfork_seed_cgroup_membership(struct container_clone_ctx *ctx);
void superfork_wake_tasks(struct container_clone_ctx *ctx);

#endif /* _SUPERFORK_INTERNAL_H */
