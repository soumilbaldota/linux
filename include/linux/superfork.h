/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SUPERFORK_H
#define _LINUX_SUPERFORK_H

#include <linux/sched.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include <linux/fs_struct.h>
#include <linux/user_namespace.h>
#include <linux/btrfs.h>
#include <asm/ptrace.h>

struct task_struct;
struct signal_struct;
struct sighand_struct;
struct pid_namespace;
struct nsproxy;
struct fs_struct;
struct file;
struct kvm;
struct kvm_vcpu;

/*
 * Snapshot of a vCPU thread's userspace pt_regs, captured at the moment KVM
 * is about to bounce it out of kvm_vcpu_block() due to a freezer signal.
 * Used by superfork to make the clone re-enter ioctl(KVM_RUN) instead of
 * returning to userspace at futex_wait (where QEMU would park in
 * pthread_cond_wait and never deliver SIGUSR1 because it's masked there).
 */
struct sf_vcpu_snap {
	struct pt_regs	saved_regs;
	bool		valid;
};

/* Called from KVM's kvm_vcpu_block() when about to exit due to signal. */
void superfork_kvm_vcpu_snapshot_entry(void);

/* Implemented in arch/{arm64,x86}/kernel/superfork_process.c */
int superfork_copy_thread(struct task_struct *p,
			  struct task_struct *src_task,
			  u64 clone_flags);

/* From fork.c - task allocation */
struct task_struct *alloc_task_struct_node(int node);
void free_task_struct(struct task_struct *tsk);
int alloc_thread_stack_node(struct task_struct *tsk, int node);
void free_thread_stack(struct task_struct *tsk);

/* From fork.c - superfork helpers */
struct task_struct *superfork_dup_task_struct(struct task_struct *orig, int node);
void superfork_free_task_struct(struct task_struct *tsk);
void superfork_rt_mutex_init_task(struct task_struct *p);
void superfork_rcu_copy_process(struct task_struct *p);
void superfork_account_new_task(bool is_leader);

/* From fork.c - signal handling */
extern struct kmem_cache *signal_cachep;
void free_signal_struct(struct signal_struct *sig);

/* From nsproxy.c - namespace cloning */
struct nsproxy *superfork_clone_nsproxy(struct nsproxy *src_nsproxy,
					struct user_namespace *user_ns,
					struct pid_namespace *new_pid_ns,
					struct fs_struct *new_fs,
					struct mnt_namespace *prepared_mnt_ns);

/* From pid_namespace.c - namespace creation */
struct pid_namespace *create_pid_namespace(struct user_namespace *user_ns,
					   struct pid_namespace *parent_ns);

/* From cgroup.c - cgroup attachment */
int cgroup_superfork_attach(struct task_struct *new_task,
			    struct task_struct *src_task);

/* From fork.c */
extern struct mm_struct *dup_mm(struct task_struct *tsk, struct mm_struct *oldmm);
extern struct pid *alloc_pid(struct pid_namespace *ns, pid_t *set_tid, size_t set_tid_size);
extern struct kmem_cache *sighand_cachep;

/*
 * Container configuration for superfork_create
 */
struct container_config {
	char container_id[64];
	char cgroup_path[256];
	char src_cgroup_path[256];
	char src_bundle_path[4096];
	char dst_bundle_path[4096];
	char new_rootfs_path[4096];
	struct btrfs_ioctl_vol_args_v2 btrfs_args; /* pre-filled by userspace */
	char pid_ns_path[256];
	char mnt_ns_path[256];
	char ipc_ns_path[256];
	char uts_ns_path[256];
	char net_ns_path[256];
	char user_ns_path[256];
	char cgroup_ns_path[256];
	uid_t owner_uid;
	gid_t owner_gid;
	bool share_namespaces;
};

#define MAX_CLONE_TASKS         256
#define MAX_CLONE_TGIDS         64
#define SUPERFORK_WAKE_TASKS    1
#define SF_MAX_KVM_VMS_PER_PROC 8
#define SF_MAX_KVM_VCPUS_PER_VM 512

struct task_clone_entry {
	struct task_struct *old_task;
	struct task_struct *new_task;
	pid_t old_tgid;
	bool is_leader;
};

struct sf_kvm_vcpu_map {
	unsigned int src_fd;
	unsigned int vcpu_id;
	struct file *new_file;
	struct kvm_vcpu *new_vcpu;
};

struct sf_kvm_vm_map {
	unsigned int src_fd;
	struct file *src_vm_file;
	struct file *new_vm_file;
	struct kvm *src_kvm;
	struct kvm *new_kvm;
	struct sf_kvm_vcpu_map vcpus[SF_MAX_KVM_VCPUS_PER_VM];
	int vcpu_count;
};

struct tgid_clone_entry {
	pid_t old_tgid;
	struct task_struct *new_leader;
	struct mm_struct *shared_mm;
	struct signal_struct *shared_signal;
	struct sighand_struct *shared_sighand;
	struct files_struct *shared_files;
	struct fs_struct *shared_fs;
	/* KVM fd replacement map is keyed per leader because files/mm are leader-shared. */
	struct sf_kvm_vm_map kvm_vms[SF_MAX_KVM_VMS_PER_PROC];
	int kvm_vm_count;
};

struct container_clone_ctx {
	struct pid_namespace *src_pid_ns;
	struct nsproxy *src_nsproxy;

	struct pid_namespace *new_pid_ns;
	struct nsproxy *new_nsproxy;
	bool isolate_netns;

	struct task_clone_entry tasks[MAX_CLONE_TASKS];
	int task_count;

	struct tgid_clone_entry tgids[MAX_CLONE_TGIDS];
	int tgid_count;
};

#define for_each_task_in_ctx(ctx) \
	for (int i = 0; i < ctx->task_count; i++)

/* From process.c - called by superfork_clone_processes */
struct task_struct *superfork_copy_process(
	struct container_clone_ctx *ctx,
	struct task_struct *src_task,
	struct tgid_clone_entry *tgid_entry,
	const char *new_rootfs_path,
	const char *src_bundle_path,
	const char *dst_bundle_path,
	bool is_leader);

#ifdef CONFIG_TASK_XACCT
void acct_clear_integrals(struct task_struct *tsk);
#else
static inline void acct_clear_integrals(struct task_struct *tsk) { }
#endif

#endif /* _LINUX_SUPERFORK_H */
