#include <linux/sched.h>
#include <asm/processor.h>
#include <asm/fpu/api.h>
#include <asm/fpu/sched.h>
#include <asm/fpu/types.h>
#include <asm/shstk.h>
#include <asm/mmu_context.h>
#include <asm/io_bitmap.h>

int superfork_copy_thread(struct task_struct *p,
                          struct task_struct *src_task,
                          u64 clone_flags)
{
    struct pt_regs             *childregs = task_pt_regs(p);
    struct pt_regs             *srcregs   = task_pt_regs(src_task);
    struct fork_frame          *fork_frame;
    struct inactive_task_frame *frame;
    unsigned long               new_ssp;

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

    *childregs    = *srcregs;
    childregs->ax = 0;

    memset(p->thread.ptrace_bps, 0, sizeof(p->thread.ptrace_bps));

    if (p->mm && (clone_flags & (CLONE_VM | CLONE_VFORK)) == CLONE_VM)
        set_bit(MM_CONTEXT_LOCK_LAM, &p->mm->context.flags);

    /* Copy IO bitmap from src_task if it was using one */
    if (unlikely(test_tsk_thread_flag(src_task, TIF_IO_BITMAP)))
        io_bitmap_share(p);

    return 0;
}