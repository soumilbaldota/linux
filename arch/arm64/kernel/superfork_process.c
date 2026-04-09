#include <linux/sched.h>
#include <linux/hw_breakpoint.h>
#include <asm/processor.h>
#include <asm/fpsimd.h>
#include <asm/pointer_auth.h>
#include <linux/superfork.h>

asmlinkage void ret_from_fork(void) asm("ret_from_fork");

int superfork_copy_thread(struct task_struct *p,
                          struct task_struct *src_task,
                          u64 clone_flags)
{
    struct pt_regs *childregs = task_pt_regs(p);
    struct pt_regs *srcregs   = task_pt_regs(src_task);

    memset(&p->thread.cpu_context, 0, sizeof(struct cpu_context));

    /*
     * src_task is frozen — it was context-switched out before we got here,
     * so its FPU state is already saved in src_task->thread by the scheduler.
     * Do NOT call fpsimd_save_and_flush_cpu_state() here — that function is
     * only valid in hotplug/suspend contexts and will WARN if called during
     * a normal syscall.  Just copy the saved struct directly.
     */

    /* Copy base FPSIMD registers and FP type */
    p->thread.uw.fpsimd_state = src_task->thread.uw.fpsimd_state;
    p->thread.fp_type         = src_task->thread.fp_type;

    /* Copy SVE state if source was using it */
    if (test_tsk_thread_flag(src_task, TIF_SVE)) {
        set_tsk_thread_flag(p, TIF_SVE);
        task_set_vl(p, ARM64_VEC_SVE,
                    task_get_vl(src_task, ARM64_VEC_SVE));
        task_set_vl_onexec(p, ARM64_VEC_SVE,
                           task_get_vl_onexec(src_task, ARM64_VEC_SVE));
        if (src_task->thread.sve_state) {
            size_t sve_sz = sve_state_size(src_task);
            p->thread.sve_state = kzalloc(sve_sz, GFP_KERNEL);
            if (!p->thread.sve_state)
                return -ENOMEM;
            memcpy(p->thread.sve_state,
                   src_task->thread.sve_state, sve_sz);
        }
    }

    /* Copy SME state if source was using it */
    if (test_tsk_thread_flag(src_task, TIF_SME)) {
        set_tsk_thread_flag(p, TIF_SME);
        task_set_vl(p, ARM64_VEC_SME,
                    task_get_vl(src_task, ARM64_VEC_SME));
        task_set_vl_onexec(p, ARM64_VEC_SME,
                           task_get_vl_onexec(src_task, ARM64_VEC_SME));
    }

    /*
     * Mark p's FPU state as not live on any CPU. The state is valid in
     * p->thread but no CPU has it loaded yet. fpsimd_flush_task_state()
     * is the correct API for this — it just clears the "loaded on cpu N"
     * tracking without touching the saved state we just copied.
     */
    fpsimd_flush_task_state(p);

#ifdef CONFIG_ARM64_PTR_AUTH
    ptrauth_thread_init_kernel(p);
    p->thread.keys_user = src_task->thread.keys_user;
#endif

    /*
     * Superfork resumes a frozen task image, so preserve the full user
     * register state exactly instead of emulating fork() return semantics.
     */
    *childregs = *srcregs;

    *task_user_tls(p) = *task_user_tls(src_task);

    p->thread.cpu_context.x19 = 0;
    p->thread.cpu_context.x20 = 0;
    p->thread.cpu_context.pc  = (unsigned long)ret_from_fork;
    p->thread.cpu_context.sp  = (unsigned long)childregs;
    p->thread.cpu_context.fp  = (unsigned long)&childregs->stackframe;

    /* Match native arm64 copy_thread() debug-state initialization. */
    ptrace_hw_copy_thread(p);

    /* Sanity check the copied state before returning */
    {
        struct pt_regs *regs = task_pt_regs(p);
        pr_info("superfork: copy_thread pid=%d pc=0x%lx sp=0x%lx "
            "pstate=0x%lx x0=0x%lx tls=0x%lx fp_type=%d\n",
            p->pid,
            (unsigned long)regs->pc,
            (unsigned long)regs->sp,
            (unsigned long)regs->pstate,
            (unsigned long)regs->regs[0],
            (unsigned long)p->thread.uw.tp_value,
            p->thread.fp_type);

        /* src pt_regs for comparison */
        pr_info("superfork: src   pid=%d pc=0x%lx sp=0x%lx "
            "pstate=0x%lx x0=0x%lx tls=0x%lx\n",
                src_task->pid,
                (unsigned long)task_pt_regs(src_task)->pc,
                (unsigned long)task_pt_regs(src_task)->sp,
                (unsigned long)task_pt_regs(src_task)->pstate,
                (unsigned long)task_pt_regs(src_task)->regs[0],
                (unsigned long)src_task->thread.uw.tp_value);
    }

    return 0;
}
