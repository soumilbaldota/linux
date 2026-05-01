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

#define SF_MAX_BUNDLES         16

struct task_struct;
struct signal_struct;
struct sighand_struct;
struct cred;
struct pid_namespace;
struct nsproxy;
struct fs_struct;
struct file;
struct kvm;
struct kvm_vcpu;
struct sf_pipe_edge;
struct sf_unix_sock_edge;

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

/* From pid_namespace.c - namespace creation */
struct pid_namespace *create_pid_namespace(struct user_namespace *user_ns,
					   struct pid_namespace *parent_ns);

/* From fork.c */
extern struct mm_struct *dup_mm(struct task_struct *tsk, struct mm_struct *oldmm);
extern struct pid *alloc_pid(struct pid_namespace *ns, pid_t *set_tid, size_t set_tid_size);
extern struct kmem_cache *sighand_cachep;

/*
 * Userspace-visible syscall payload. Pointer fields store userspace addresses.
 *
 * The bundle interface is intentionally split into:
 *   - one root bundle
 *   - zero or more auxiliary bundles
 *
 * The root bundle is the primary cloned snapshot root. Auxiliary bundles may
 * contribute additional mount-visible paths for helper daemons that do not run
 * with the primary bundle as their effective fs root.
 *
 * Auxiliary bundles are additional snapshot/remap roots that belong to the
 * same logical container but are not themselves the cloned process root. This
 * matches runtimes like Kata, where sandbox state is spread across multiple
 * directories and only one of them should become the clone's rootfs.
 */
struct container_config_user {
	char src_cgroup_path[256];
	char root_src_bundle_path[4096];
	char root_dst_bundle_path[4096];
	__u32 aux_bundle_count;
	__u32 reserved;
	__u64 aux_src_bundle_paths_ptr;
	__u64 aux_dst_bundle_paths_ptr;
	struct btrfs_ioctl_vol_args_v2 btrfs_args;
};

struct container_config {
	char src_cgroup_path[256];
	char root_src_bundle_path[4096];
	char root_dst_bundle_path[4096];
	__u32 aux_bundle_count;
	char aux_src_bundle_paths[SF_MAX_BUNDLES][4096];
	char aux_dst_bundle_paths[SF_MAX_BUNDLES][4096];
	struct btrfs_ioctl_vol_args_v2 btrfs_args;
};

#define MAX_CLONE_TASKS         256
#define MAX_CLONE_TGIDS         64
#define SF_MAX_KVM_VMS_PER_PROC 8
#define SF_MAX_KVM_VCPUS_PER_VM 512
#define SF_MAX_PROCFS_REOPENS   32
#define SF_MAX_PIDFD_REOPENS    32

/*
 * Records a single procfs fd that needs to be reopened after
 * superfork_attach_tasks gives the clone stable PIDs.
 *
 * If old_pid > 0, the file is pid-scoped and relpath stores everything after
 * /proc/<old_pid>/ so it can be rebuilt as /proc/<new_pid>/<relpath>.
 *
 * If old_pid == 0, the file is procfs-global and relpath stores the path
 * relative to the procfs root without the leading slash; the empty string
 * denotes the procfs root itself and reopens as /proc.
 *
 * Until reopen, the fd slot holds /dev/null as a placeholder.
 */
struct sf_procfs_reopen {
	unsigned int fd;
	pid_t        old_pid;
	struct pid_namespace *old_pid_ns;
	int          open_flags;
	loff_t       pos;
	char         relpath[256];
};

struct sf_fs_share_entry {
	const struct fs_struct *src_fs;
	struct fs_struct *new_fs;
};

struct sf_cred_share_entry {
	const struct cred *src_cred;
	const struct cred *new_cred;
};

struct sf_pidfd_reopen {
	unsigned int fd;
	pid_t        old_pid;
	unsigned int flags;
};

struct sf_ns_domain {
	struct task_struct *src_task;
	struct nsproxy *src_nsproxy;
	struct nsproxy *new_nsproxy;
};

struct task_clone_entry {
	struct task_struct *old_task;
	struct task_struct *new_task;
	pid_t old_tgid;
	unsigned int domain_id;
	bool is_leader;
	bool attached;
	char src_root_path[4096];
	char src_pwd_path[4096];
};

struct sf_kvm_vcpu_map {
	unsigned int src_fd;
	unsigned int vcpu_id;
	struct kvm_vcpu *new_vcpu;
};

struct sf_kvm_vm_map {
	unsigned int src_fd;
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
	struct sf_fs_share_entry fs_shares[MAX_CLONE_TASKS];
	int fs_share_count;
	struct sf_cred_share_entry cred_shares[MAX_CLONE_TASKS];
	int cred_share_count;
	/* KVM fd replacement map is keyed per leader because files/mm are leader-shared. */
	struct sf_kvm_vm_map kvm_vms[SF_MAX_KVM_VMS_PER_PROC];
	int kvm_vm_count;
	/* procfs fds to reopen post-attach once the clone has a stable PID. */
	struct sf_procfs_reopen procfs_reopens[SF_MAX_PROCFS_REOPENS];
	int procfs_reopen_count;
	/* pidfds to retarget to cloned tasks post-attach. */
	struct sf_pidfd_reopen pidfd_reopens[SF_MAX_PIDFD_REOPENS];
	int pidfd_reopen_count;
};

struct container_clone_ctx {
	struct pid_namespace *src_pid_ns;
	struct pid_namespace *new_pid_ns;

	struct sf_ns_domain domains[MAX_CLONE_TASKS];
	int domain_count;
	struct sf_unix_sock_edge *unix_sock_edges;
	unsigned int unix_sock_edge_count;
	unsigned int unix_sock_edge_capacity;
	struct sf_pipe_edge *pipe_edges;
	unsigned int pipe_edge_count;
	unsigned int pipe_edge_capacity;
	struct file **allowed_shared_files;
	unsigned int allowed_shared_file_count;
	unsigned int allowed_shared_file_capacity;

	struct task_clone_entry tasks[MAX_CLONE_TASKS];
	int task_count;

	struct tgid_clone_entry tgids[MAX_CLONE_TGIDS];
	int tgid_count;
	bool post_fork_done;
};

#define for_each_task_in_ctx(ctx) \
	for (int i = 0; i < ctx->task_count; i++)

/* From process.c - called by superfork_clone_processes */
struct task_struct *superfork_copy_process(
	struct container_clone_ctx *ctx,
	struct task_clone_entry *task_entry,
	struct tgid_clone_entry *tgid_entry,
	const struct container_config *config,
	bool is_leader);

void superfork_release_placeholder_peers(struct task_struct *task);

#ifdef CONFIG_TASK_XACCT
void acct_clear_integrals(struct task_struct *tsk);
#else
static inline void acct_clear_integrals(struct task_struct *tsk) { }
#endif

#endif /* _LINUX_SUPERFORK_H */
