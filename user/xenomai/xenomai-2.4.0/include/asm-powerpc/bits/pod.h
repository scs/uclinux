/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 *
 * 64-bit PowerPC adoption
 *   copyright (C) 2005 Taneli Vähäkangas and Heikki Lindholm
 *   
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _XENO_ASM_POWERPC_BITS_POD_H
#define _XENO_ASM_POWERPC_BITS_POD_H

#include <asm-generic/xenomai/bits/pod.h>

void xnpod_welcome_thread(struct xnthread *, int);

void xnpod_delete_thread(struct xnthread *);

#define xnarch_start_timer(tick_handler, cpu)	\
	({ int __tickval = rthal_timer_request(tick_handler, cpu) ?: \
			(1000000000UL/HZ); __tickval; })

#define xnarch_stop_timer(cpu)	rthal_timer_release(cpu)

static inline void xnarch_leave_root(xnarchtcb_t * rootcb)
{
	/* Remember the preempted Linux task pointer. */
	rootcb->user_task = rootcb->active_task = current;
	rootcb->tsp = &current->thread;
#ifdef CONFIG_XENO_HW_FPU
	rootcb->user_fpu_owner = rthal_get_fpu_owner(rootcb->user_task);
	/* So that xnarch_save_fpu() will operate on the right FPU area. */
	rootcb->fpup = (rootcb->user_fpu_owner
			? (rthal_fpenv_t *) & rootcb->user_fpu_owner->thread.
			fpr[0]
			: NULL);
#endif /* CONFIG_XENO_HW_FPU */
}

static inline void xnarch_enter_root(xnarchtcb_t * rootcb)
{
}

static inline void xnarch_switch_to(xnarchtcb_t * out_tcb, xnarchtcb_t * in_tcb)
{
	struct task_struct *prev = out_tcb->active_task;
	struct task_struct *next = in_tcb->user_task;

	if (likely(next != NULL)) {
		in_tcb->active_task = next;
		rthal_clear_foreign_stack(&rthal_domain);
	} else {
		in_tcb->active_task = prev;
		rthal_set_foreign_stack(&rthal_domain);
	}

	if (next && next != prev) {	/* Switch to new user-space thread? */
		struct mm_struct *mm = next->active_mm;
		/* Switch the mm context. */
#ifdef CONFIG_PPC64
#ifdef CONFIG_ALTIVEC
		asm volatile ("dssall;\n" :/*empty*/:);
#endif
		if (!cpu_isset(rthal_processor_id(), mm->cpu_vm_mask))
			cpu_set(rthal_processor_id(), mm->cpu_vm_mask);

		if (cpu_has_feature(CPU_FTR_SLB))
			switch_slb(next, mm);
		else
			switch_stab(next, mm);
        }
	rthal_thread_switch(out_tcb->tsp, in_tcb->tsp, next == NULL);
#else /* PPC32 */
#ifdef CONFIG_ALTIVEC
		asm volatile ("dssall;\n"
#ifndef CONFIG_POWER4
			      "sync;\n"
#endif
			      :/*empty*/:);
#endif /* CONFIG_ALTIVEC */
		next->thread.pgdir = mm->pgd;
		get_mmu_context(mm);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
		set_context(mm->context, mm->pgd);
#else /* !(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18))*/
		set_context(mm->context.id, mm->pgd);
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */
		current = prev;	/* Make sure r2 is valid. */
	}
	rthal_thread_switch(out_tcb->tsp, in_tcb->tsp);
#endif	/* PPC32 */

	barrier();
}

static inline void xnarch_finalize_and_switch(xnarchtcb_t * dead_tcb,
					      xnarchtcb_t * next_tcb)
{
	xnarch_switch_to(dead_tcb, next_tcb);
}

static inline void xnarch_finalize_no_switch(xnarchtcb_t * dead_tcb)
{
	/* Empty */
}

static inline void xnarch_init_root_tcb(xnarchtcb_t * tcb,
					struct xnthread *thread,
					const char *name)
{
	tcb->user_task = current;
	tcb->active_task = NULL;
	tcb->tsp = &tcb->ts;
#ifdef CONFIG_XENO_HW_FPU
	tcb->user_fpu_owner = NULL;
	tcb->fpup = NULL;
#endif /* CONFIG_XENO_HW_FPU */
	tcb->entry = NULL;
	tcb->cookie = NULL;
	tcb->self = thread;
	tcb->imask = 0;
	tcb->name = name;
}

asmlinkage static void xnarch_thread_trampoline(xnarchtcb_t * tcb)
{
	xnpod_welcome_thread(tcb->self, tcb->imask);
	tcb->entry(tcb->cookie);
	xnpod_delete_thread(tcb->self);
}

static inline void xnarch_init_thread(xnarchtcb_t * tcb,
				      void (*entry) (void *),
				      void *cookie,
				      int imask,
				      struct xnthread *thread, char *name)
{
	unsigned long *ksp, flags;
	struct pt_regs *childregs;

	rthal_local_irq_flags_hw(flags);

#ifdef CONFIG_PPC64
	ksp =
	    (unsigned long *)((unsigned long)tcb->stackbase + tcb->stacksize -
			      RTHAL_SWITCH_FRAME_SIZE - 32);
	childregs = (struct pt_regs *)ksp;
	memset(childregs, 0, sizeof(*childregs));
	childregs->nip = ((unsigned long *)&rthal_thread_trampoline)[0];
	childregs->gpr[2] = ((unsigned long *)&rthal_thread_trampoline)[1];
	childregs->gpr[14] = flags & ~(MSR_EE | MSR_FP);
	childregs->gpr[15] = ((unsigned long *)&xnarch_thread_trampoline)[0];	/* lr = entry addr. */
	childregs->gpr[16] = ((unsigned long *)&xnarch_thread_trampoline)[1];	/* r2 = TOC base. */
	childregs->gpr[17] = (unsigned long)tcb;
	tcb->ts.ksp = (unsigned long)childregs - STACK_FRAME_OVERHEAD;
	if (cpu_has_feature(CPU_FTR_SLB)) {	/* from process.c/copy_thread */
		unsigned long sp_vsid = get_kernel_vsid(tcb->ts.ksp);

		sp_vsid <<= SLB_VSID_SHIFT;
		sp_vsid |= SLB_VSID_KERNEL;
		if (cpu_has_feature(CPU_FTR_16M_PAGE))
			sp_vsid |= SLB_VSID_L;

		tcb->ts.ksp_vsid = sp_vsid;
	}
#else /* !CONFIG_PPC64 */
	ksp =
	    (unsigned long *)((unsigned long)tcb->stackbase + tcb->stacksize -
			      RTHAL_SWITCH_FRAME_SIZE - 4);
	childregs = (struct pt_regs *)ksp;
	memset(childregs, 0, sizeof(*childregs));
	childregs->nip = (unsigned long)&rthal_thread_trampoline;
	childregs->gpr[14] = flags & ~(MSR_EE | MSR_FP);
	childregs->gpr[15] = (unsigned long)&xnarch_thread_trampoline;
	childregs->gpr[16] = (unsigned long)tcb;
	tcb->ts.ksp = (unsigned long)childregs - STACK_FRAME_OVERHEAD;
#endif

	tcb->entry = entry;
	tcb->cookie = cookie;
	tcb->self = thread;
	tcb->imask = imask;
	tcb->name = name;
}

/* No lazy FPU init on PPC. */
#define xnarch_fpu_init_p(task) (1)

static inline void xnarch_enable_fpu(xnarchtcb_t * current_tcb)
{
#ifdef CONFIG_XENO_HW_FPU
	if (!current_tcb->user_task)
		rthal_enable_fpu();
#endif /* CONFIG_XENO_HW_FPU */
}

static inline void xnarch_init_fpu(xnarchtcb_t * tcb)
{
#ifdef CONFIG_XENO_HW_FPU
	/* Initialize the FPU for an emerging kernel-based RT thread. This
	   must be run on behalf of the emerging thread. */
	memset(&tcb->ts.fpr[0], 0, sizeof(rthal_fpenv_t));
	rthal_init_fpu((rthal_fpenv_t *) & tcb->ts.fpr[0]);
#endif /* CONFIG_XENO_HW_FPU */
}

static inline void xnarch_save_fpu(xnarchtcb_t * tcb)
{
#ifdef CONFIG_XENO_HW_FPU

	if (tcb->fpup) {
		rthal_save_fpu(tcb->fpup);

		if (tcb->user_fpu_owner && tcb->user_fpu_owner->thread.regs) {
			tcb->user_fpu_owner_prev_msr =
			    tcb->user_fpu_owner->thread.regs->msr;
			tcb->user_fpu_owner->thread.regs->msr &= ~MSR_FP;
		}
	}
#endif /* CONFIG_XENO_HW_FPU */
}

static inline void xnarch_restore_fpu(xnarchtcb_t * tcb)
{
#ifdef CONFIG_XENO_HW_FPU

	if (tcb->fpup) {
		rthal_restore_fpu(tcb->fpup);

		/* Note: Only enable FP in MSR, if it was enabled when we saved the
		 * fpu state. We might have preempted Linux when it had disabled FP
		 * for the thread, but not yet set last_task_used_math to NULL 
		 */
		if (tcb->user_fpu_owner &&
		    tcb->user_fpu_owner->thread.regs &&
		    ((tcb->user_fpu_owner_prev_msr & MSR_FP) != 0))
			tcb->user_fpu_owner->thread.regs->msr |= MSR_FP;
	}

	/* FIXME: We restore FPU "as it was" when Xenomai preempted Linux,
	   whereas we could be much lazier. */
	if (tcb->user_task)
		rthal_disable_fpu();

#endif /* CONFIG_XENO_HW_FPU */
}

static inline int xnarch_escalate(void)
{
	extern int xnarch_escalation_virq;

	if (rthal_current_domain == rthal_root_domain) {
		rthal_trigger_irq(xnarch_escalation_virq);
		return 1;
	}

	return 0;
}

#endif /* !_XENO_ASM_POWERPC_BITS_POD_H */
