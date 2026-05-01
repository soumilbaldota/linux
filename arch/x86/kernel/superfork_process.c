#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/string.h>
#include <linux/superfork.h>
#include <asm/processor.h>
#include <asm/syscall.h>
#include <asm/unistd.h>
#include <asm/frame.h>
#include <asm/switch_to.h>
#include <asm/fpu/api.h>
#include <asm/fpu/sched.h>
#include <asm/fpu/types.h>
#include <asm/pkru.h>
#include <asm/shstk.h>
#include <asm/mmu_context.h>
#include <asm/io_bitmap.h>

static inline unsigned long
superfork_get_nr_restart_syscall(struct task_struct *p,
				 const struct pt_regs *regs)
{
#ifdef CONFIG_IA32_EMULATION
	if (p->restart_block.arch_data & TS_COMPAT)
		return __NR_ia32_restart_syscall;
#endif
#ifdef CONFIG_X86_X32_ABI
	return __NR_restart_syscall | (regs->orig_ax & __X32_SYSCALL_BIT);
#else
	return __NR_restart_syscall;
#endif
}

/*
 * copy_thread() zeroes ax so a normal fork child returns 0 from clone/fork.
 * superfork is exact-state cloning instead: if the frozen source task was on
 * the way out of an interrupted syscall, preserve that exit state and apply
 * the same restart rewrite x86 signal exit would have used.
 */
static void superfork_rewrite_interrupted_syscall(struct task_struct *p,
						  struct pt_regs *regs)
{
	long err;
	int nr;

	nr = syscall_get_nr(p, regs);
	if (nr == -1)
		return;

	err = syscall_get_error(p, regs);
	switch (err) {
	case -ERESTARTNOHAND:
	case -ERESTARTSYS:
	case -ERESTARTNOINTR:
		regs->ax = regs->orig_ax;
		regs->ip -= 2;
		pr_info_ratelimited("superfork: restart cloned syscall pid=%d comm=%s nr=%d err=%ld ip=0x%lx\n",
				    p->pid, p->comm, nr, err, regs->ip);
		break;

	case -ERESTART_RESTARTBLOCK:
		regs->ax = superfork_get_nr_restart_syscall(p, regs);
		regs->ip -= 2;
		pr_info_ratelimited("superfork: restartblock cloned syscall pid=%d comm=%s nr=%d err=%ld ip=0x%lx ax=0x%lx\n",
				    p->pid, p->comm, nr, err, regs->ip, regs->ax);
		break;
	}
}

/*
 * Clone a running kernel thread or vhost_task user-worker.
 *
 * These tasks live entirely in kernel space and never iret to userspace, so
 * the ret_from_fork_asm recipe used for QEMU's userspace threads is wrong
 * for them on two counts:
 *
 *   1. Their task_pt_regs() slot is effectively zero — upstream copy_thread
 *      memsets it for PF_KTHREAD and sets sp=ip=0 for user_workers.  Iret'ing
 *      that frame segfaults at RIP=0 (which is the "kvm-nx-lpage-re segfault
 *      at 0 ip 0 sp 0" symptom).
 *
 *   2. The user-return path hits WARN_ON_ONCE(current->flags &
 *      (PF_KTHREAD | PF_USER_WORKER)) in fpregs_restore_userregs(), because
 *      the flag is still set on the clone.
 *
 * kthread_frame_init() (what upstream copy_thread uses for these task types)
 * only works for a task that has never run: it wires frame->bx = fn,
 * frame->r12 = fn_arg so ret_from_fork() dispatches fn(fn_arg) from scratch.
 * A long-lived kthread or vhost_task_fn loop has already been scheduled many
 * times and is parked somewhere deep inside schedule() — restarting it at
 * its entry function would re-run its init and lose live state.
 *
 * What we do instead: copy the source's entire kernel stack into the
 * clone's stack and set p->thread.sp to the same byte offset.  When the
 * scheduler picks up the clone, __switch_to_asm pops the callee-saved regs
 * that the source pushed on its last schedule-out and rets straight back
 * into the middle of __schedule().  Exact-state resume, no ret_from_fork
 * involvement, no user-return path, no pt_regs iret.
 *
 * Preconditions:
 *   - src_task must be off-CPU at clone time.  For vhost_tasks sharing the
 *     QEMU thread group this is guaranteed by the cgroup freezer: the worker
 *     parks in schedule() called from get_signal() inside vhost_task_fn.
 *   - The destination thread group must also clone the KVM state that any
 *     on-stack pointers refer to; that is handled in phase 5 before us.
 */
static int superfork_copy_kthread(struct task_struct *p,
                                  struct task_struct *src_task,
                                  u64 clone_flags)
{
    void         *src_stack = task_stack_page(src_task);
    void         *dst_stack = task_stack_page(p);
    unsigned long sp_off;
    unsigned long new_ssp;
    struct fpu   *dst_fpu;
    struct fpu   *src_fpu = x86_task_fpu(src_task);
    unsigned int  copy_size;

    if (WARN_ON_ONCE(!src_stack || !dst_stack))
        return -EINVAL;
    if (WARN_ON_ONCE(src_task->thread.sp <  (unsigned long)src_stack ||
                     src_task->thread.sp >= (unsigned long)src_stack + THREAD_SIZE))
        return -EINVAL;

    /*
     * Copy the full kernel stack contents.  This carries over:
     *   - the inactive_task_frame at src->thread.sp (callee-saved regs +
     *     ret_addr pointing into __switch_to_asm's epilogue),
     *   - every caller frame above it up through vhost_task_fn / kthread(),
     *   - the (unused for these tasks) pt_regs slot at the top.
     */
    memcpy(dst_stack, src_stack, THREAD_SIZE);

#ifndef CONFIG_THREAD_INFO_IN_TASK
    /* Legacy layout: thread_info lives on the stack and back-points at the task. */
    task_thread_info(p)->task = p;
#endif
    set_task_stack_end_magic(p);

#ifdef CONFIG_STACKPROTECTOR
    /*
     * Every function frame on the copied stack was entered with src's
     * canary pushed.  dup_task_struct() just gave the clone a fresh random
     * canary, which would make __stack_chk_fail in __schedule (and every
     * caller above it) panic the moment the clone resumes.  Inherit src's
     * canary so the on-stack saved values match current->stack_canary.
     */
    p->stack_canary = src_task->stack_canary;
#endif

    /* Same byte offset into the new stack. */
    sp_off       = src_task->thread.sp - (unsigned long)src_stack;
    p->thread.sp = (unsigned long)dst_stack + sp_off;

    /*
     * Rewrite all on-stack copies of src_task to point at the clone.
     *
     * `current` is per-CPU stable and gets cached in %rbx at vhost_task_fn
     * entry; callee-save conventions spill it into every frame on the call
     * chain.  Critically, __schedule saves %rbx in its own prologue *before*
     * overwriting it with the runqueue base pointer — so inactive_task_frame.bx
     * holds the runqueue, not src_task.  The real src_task copy sits in
     * __schedule's callee-save area (at [rbp-40] or wherever the compiler put
     * it).  A targeted check of frame->bx misses it entirely.
     *
     * When the clone resumes, __schedule's epilogue pops its saved %rbx
     * (= src_task) back into the register, which propagates up through
     * schedule() into vhost_task_fn.  Every set_current_state() call then
     * writes to src_task->__state instead of the clone's, keeping the clone
     * permanently TASK_RUNNING and spinning at 100% CPU.
     *
     * Scan the entire copied stack and replace every occurrence.  A targeted
     * [rbp-N] rewrite would be fragile across compiler versions.  False
     * positives (kthread stack data that coincidentally equals src_task's
     * address) are negligible in practice.
     */
    {
        unsigned long *slot = (unsigned long *)dst_stack;
        unsigned long *end  = slot + THREAD_SIZE / sizeof(unsigned long);

        for (; slot < end; slot++) {
            if (*slot == (unsigned long)src_task)
                *slot = (unsigned long)p;
        }
    }

    /*
     * Rebase the frame-pointer (rbp) chain.
     *
     * Every saved rbp on the copied stack is an absolute address that
     * points into the SOURCE's stack.  When GCC compiles a function
     * with -fstack-protector + -fno-omit-frame-pointer it accesses the
     * stack canary (and sometimes restores rsp) via [rbp - N].  If the
     * source is thawed before the clone is scheduled, those rbp values
     * dereference live, mutating memory on the source's stack and the
     * canary check in __schedule's epilogue sees garbage → panic.
     *
     * Walk the chain starting from inactive_task_frame.bp (the rbp
     * that __switch_to_asm will pop) and adjust every link that falls
     * inside the source stack range so it points at the corresponding
     * byte in the destination stack.
     */
#ifdef CONFIG_FRAME_POINTER
    {
        long           delta  = (long)dst_stack - (long)src_stack;
        unsigned long  src_lo = (unsigned long)src_stack;
        unsigned long  src_hi = src_lo + THREAD_SIZE;
        unsigned long  dst_lo = (unsigned long)dst_stack;
        unsigned long  dst_hi = dst_lo + THREAD_SIZE;
        struct inactive_task_frame *frame =
            (struct inactive_task_frame *)p->thread.sp;
        unsigned long *bp_slot = &frame->bp;
        int            depth;

        for (depth = 0; depth < 64; depth++) {
            unsigned long val = *bp_slot;

            if (val < src_lo || val >= src_hi)
                break;

            val += delta;
            *bp_slot = val;

            if (val < dst_lo ||
                val + sizeof(unsigned long) > dst_hi)
                break;
            bp_slot = (unsigned long *)val;
        }
    }
#endif

    /*
     * Deliberately do NOT touch task_pt_regs(p) or the inactive_task_frame
     * ret_addr.  The return address points into kernel text (not the stack)
     * and is valid as-is.
     */

    /* Non-stack thread state. */
    p->thread.io_bitmap = NULL;
    p->thread.iopl_warn = 0;
    clear_tsk_thread_flag(p, TIF_IO_BITMAP);
    p->thread.pkru = pkru_get_init_value();
    memset(p->thread.ptrace_bps, 0, sizeof(p->thread.ptrace_bps));

    /*
     * Carry over segment state.  Kernel tasks don't use user segments at
     * runtime, but keeping the tracking coherent with src avoids surprises
     * if the clone ever takes a code path that consults them.
     */
    p->thread.fsindex = src_task->thread.fsindex;
    p->thread.fsbase  = src_task->thread.fsbase;
    p->thread.gsindex = src_task->thread.gsindex;
    p->thread.gsbase  = src_task->thread.gsbase;
    p->thread.es      = src_task->thread.es;
    p->thread.ds      = src_task->thread.ds;

    new_ssp = shstk_alloc_thread_stack(p, clone_flags, 0);
    if (IS_ERR_VALUE(new_ssp))
        return PTR_ERR((void *)new_ssp);

    /*
     * minimal=true is the kthread/user_worker convention: fpu_clone sets up
     * dst_fpu metadata (fpstate pointer, TIF_NEED_FPU_LOAD, last_cpu=-1)
     * and writes init_fpstate into the regs without touching current's FPU.
     * We then overwrite the regs blob with src_task's saved state, which is
     * authoritative because src is frozen off-CPU.
     */
    fpu_clone(p, clone_flags, true, new_ssp);

    dst_fpu   = x86_task_fpu(p);
    copy_size = dst_fpu->fpstate->size;
    if (src_fpu->fpstate->size < copy_size)
        copy_size = src_fpu->fpstate->size;
    memcpy(&dst_fpu->fpstate->regs, &src_fpu->fpstate->regs, copy_size);

    if (p->mm && (clone_flags & (CLONE_VM | CLONE_VFORK)) == CLONE_VM)
        set_bit(MM_CONTEXT_LOCK_LAM, &p->mm->context.flags);

    return 0;
}

int superfork_copy_thread(struct task_struct *p,
                          struct task_struct *src_task,
                          u64 clone_flags)
{
    struct pt_regs             *childregs;
    struct pt_regs             *srcregs;
    struct fork_frame          *fork_frame;
    struct inactive_task_frame *frame;
    unsigned long               new_ssp;

    /*
     * Kernel threads and vhost_task user-workers take a completely
     * different resume path — see superfork_copy_kthread() for details.
     * The original failure mode (kvm-nx-lpage-recovery) is a vhost_task,
     * so PF_USER_WORKER is the flag that actually fires here.
     */
    if (unlikely(src_task->flags & (PF_KTHREAD | PF_USER_WORKER)))
        return superfork_copy_kthread(p, src_task, clone_flags);

    childregs  = task_pt_regs(p);
    srcregs    = task_pt_regs(src_task);
    fork_frame = container_of(childregs, struct fork_frame, regs);
    frame      = &fork_frame->frame;

    frame->bp       = encode_frame_pointer(childregs);
    frame->ret_addr = (unsigned long)ret_from_fork_asm;
    frame->bx       = 0;

    p->thread.sp        = (unsigned long)fork_frame;
    p->thread.io_bitmap = NULL;
    p->thread.iopl_warn = 0;
    clear_tsk_thread_flag(p, TIF_IO_BITMAP);

    p->thread.fsindex = src_task->thread.fsindex;
    p->thread.fsbase  = src_task->thread.fsbase;
    p->thread.gsindex = src_task->thread.gsindex;
    p->thread.gsbase  = src_task->thread.gsbase;
    p->thread.es      = src_task->thread.es;
    p->thread.ds      = src_task->thread.ds;

    new_ssp = shstk_alloc_thread_stack(p, clone_flags, 0);
    if (IS_ERR_VALUE(new_ssp))
        return PTR_ERR((void *)new_ssp);

    /*
     * fpu_clone() initialises the dst FPU structure and copies FPU state
     * from `current`.  In superfork current != src_task, so the regs
     * it copies are wrong.  Let it run to set up the dst_fpu metadata
     * (fpstate pointer, last_cpu, TIF_NEED_FPU_LOAD, shadow stack), then
     * overwrite the register blob with src_task's saved state.
     *
     * src_task is frozen — its FPU state was saved by the scheduler on
     * context switch, so the fpstate regs are authoritative.
     */
    fpu_clone(p, clone_flags, false, new_ssp);
    {
        struct fpu *dst_fpu = x86_task_fpu(p);
        struct fpu *src_fpu = x86_task_fpu(src_task);
        unsigned int copy_size;

        /*
         * Copy the default-sized fpstate regs.  Both src and dst use the
         * default fpstate (no dynamically expanded features) in the common
         * QEMU case.  If the source had expanded fpstate we would need to
         * reallocate, but that only happens with AMX which QEMU under
         * superfork will not use.
         */
        copy_size = dst_fpu->fpstate->size;
        if (src_fpu->fpstate->size < copy_size)
            copy_size = src_fpu->fpstate->size;
        memcpy(&dst_fpu->fpstate->regs, &src_fpu->fpstate->regs, copy_size);
    }

    p->thread.pkru = src_task->thread.pkru;

    /*
     * If KVM captured the source vCPU's userspace pt_regs at the moment
     * the freezer signal kicked it out of KVM_RUN, use that frame so the
     * clone iret's back to the 'syscall' instruction and re-enters
     * ioctl(KVM_RUN). Otherwise the clone would resume at futex_wait
     * inside pthread_cond_wait, where QEMU masks SIGUSR1 and the guest
     * never runs. See superfork_kvm_vcpu_snapshot_entry().
     *
     * The snap already has ip rewound by 2 and ax restored to orig_ax,
     * so we just copy it in wholesale and do NOT zero ax.
     */
	    if (src_task->sf_vcpu_snap &&
	        READ_ONCE(src_task->sf_vcpu_snap->valid)) {
	        smp_rmb();
	        *childregs = src_task->sf_vcpu_snap->saved_regs;
	    } else {
	        *childregs = *srcregs;
	        superfork_rewrite_interrupted_syscall(p, childregs);
	    }

    memset(p->thread.ptrace_bps, 0, sizeof(p->thread.ptrace_bps));

    if (p->mm && (clone_flags & (CLONE_VM | CLONE_VFORK)) == CLONE_VM)
        set_bit(MM_CONTEXT_LOCK_LAM, &p->mm->context.flags);

    /* Copy IO bitmap from src_task if it was using one */
    if (unlikely(test_tsk_thread_flag(src_task, TIF_IO_BITMAP)))
        io_bitmap_share(p);

    return 0;
}
