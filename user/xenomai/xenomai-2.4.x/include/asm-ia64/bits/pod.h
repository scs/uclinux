/*
 * Copyright &copy; 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 * Copyright &copy; 2004 The HYADES project <http://www.hyades-itea.org>
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

#ifndef _XENO_ASM_IA64_BITS_POD_H
#define _XENO_ASM_IA64_BITS_POD_H

#include <asm-generic/xenomai/bits/pod.h>

void xnpod_welcome_thread(struct xnthread *, int);

void xnpod_delete_thread(struct xnthread *);

#define xnarch_start_timer(tick_handler, cpu)	\
	({ int __tickval = rthal_timer_request(tick_handler, cpu) ?: \
			(1000000000UL/HZ); __tickval; })

#define xnarch_stop_timer(cpu)	rthal_timer_release(cpu)

static inline void xnarch_leave_root(xnarchtcb_t * rootcb)
{
	struct task_struct *fpu_owner
	    = (struct task_struct *)ia64_get_kr(IA64_KR_FPU_OWNER);

	/* Remember the preempted Linux task pointer. */
	rootcb->user_task = rootcb->active_task = current;
	/* So that xnarch_save_fpu() will operate on the right FPU area. */
	rootcb->fpup = fpu_owner ? fpu_owner->thread.fph : NULL;
	rootcb->kspp = &current->thread.ksp;
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

	if (next && next != prev) {
		/* We are switching to a user task different from the last
		   preempted or running user task, so that we can use the
		   Linux context switch routine. */
		struct mm_struct *oldmm = prev->active_mm;

		switch_mm(oldmm, next->active_mm, next);

		if (!next->mm)
			enter_lazy_tlb(oldmm, next);

		if (IA64_HAS_EXTRA_STATE(prev))
			ia64_save_extra(prev);

		if (IA64_HAS_EXTRA_STATE(next))
			ia64_load_extra(next);

		ia64_psr(task_pt_regs(next))->dfh =
		    !ia64_is_local_fpu_owner(next);

		rthal_thread_switch(out_tcb->kspp, in_tcb->kspp, 1);
	} else {
		unsigned long gp;

		ia64_stop();
		gp = ia64_getreg(_IA64_REG_GP);
		ia64_stop();
		rthal_thread_switch(out_tcb->kspp, in_tcb->kspp, 0);
		ia64_stop();
		ia64_setreg(_IA64_REG_GP, gp);
		ia64_stop();

		/* fph will be enabled by xnarch_restore_fpu if needed, and
		   returns the root thread in its usual mode. */
		ia64_fph_disable();
	}
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

#define fph2task(faddr)                                 \
    ((struct task_struct *)((char *) (faddr) -          \
                            (size_t) &((struct task_struct *) 0)->thread.fph[0]))

#define xnarch_fpu_init_p(task) ((task)->thread.flags & IA64_THREAD_FPH_VALID)

static inline void xnarch_init_fpu(xnarchtcb_t * tcb)
{
	struct task_struct *task = tcb->user_task;
	/* Initialize the FPU for a task. This must be run on behalf of the
	   task. */
	ia64_fph_enable();
	__ia64_init_fpu();
	/* The mfh bit is automatically armed, since the init_fpu routine
	   modifies the FPH registers. */

	if (task)
		/* Real-time shadow FPU initialization: setting the mfh bit in saved
		   registers, xnarch_save_fpu will finish the work. Since tcb is the tcb
		   of a shadow, no need to check: task == fph2task(tcb->fpup). */
		ia64_psr(task_pt_regs(task))->mfh = 1;
}

static inline void xnarch_save_fpu(xnarchtcb_t * tcb)
{
	unsigned long lpsr = ia64_getreg(_IA64_REG_PSR);
	struct ia64_psr *current_psr = (struct ia64_psr *)&lpsr;

	if (current_psr->mfh) {
		if (tcb->user_task && tcb->fpup) {
			struct task_struct *linux_fpu_owner =
			    fph2task(tcb->fpup);
			struct ia64_psr *psr =
			    ia64_psr(task_pt_regs(linux_fpu_owner));

			/* Keep the FPU save zone in sync with what Linux expects. */
			psr->mfh = 0;
			linux_fpu_owner->thread.flags |= IA64_THREAD_FPH_VALID;
		}

		ia64_fph_enable();
		__ia64_save_fpu(tcb->fpup);
		ia64_rsm(IA64_PSR_MFH);
		ia64_srlz_d();
	}
}

static inline void xnarch_restore_fpu(xnarchtcb_t * tcb)
{
	struct task_struct *linux_fpu_owner;
	int need_disabled_fph;

	if (tcb->user_task && tcb->fpup) {
		linux_fpu_owner = fph2task(tcb->fpup);

		if (!xnarch_fpu_init_p(linux_fpu_owner))
			return;	/* Uninit fpu area -- do not restore. */

		/* Disable fph, if we are not switching back to the task which
		   owns the FPU. */
		need_disabled_fph = linux_fpu_owner != tcb->user_task;
	} else
		need_disabled_fph = 0;

	/* Restore the FPU hardware with valid fp registers from a
	   user-space or kernel thread. */
	ia64_fph_enable();
	__ia64_load_fpu(tcb->fpup);
	ia64_rsm(IA64_PSR_MFH);
	ia64_srlz_d();

	if (need_disabled_fph)
		ia64_fph_disable();
}

static inline void xnarch_enable_fpu(xnarchtcb_t * tcb)
{
	if (tcb->user_task && tcb->fpup
	    && fph2task(tcb->fpup) != tcb->user_task)
		return;

	ia64_fph_enable();
}

static inline void xnarch_init_root_tcb(xnarchtcb_t * tcb,
					struct xnthread *thread,
					const char *name)
{
	tcb->user_task = current;
	tcb->active_task = NULL;
	tcb->fpup = current->thread.fph;
	tcb->kspp = &current->thread.ksp;
	tcb->name = name;
}

static void xnarch_thread_trampoline(struct xnthread *self,
				     int imask,
				     void (*entry) (void *), void *cookie)
{
	/* xnpod_welcome_thread() will do ia64_fpu_enable() if needed. */
	ia64_fph_disable();
	xnpod_welcome_thread(self, imask);
	entry(cookie);
	xnpod_delete_thread(self);
}

static inline void xnarch_init_thread(xnarchtcb_t * tcb,
				      void (*entry) (void *),
				      void *cookie,
				      int imask,
				      struct xnthread *thread, const char *name)
{
	unsigned long rbs, bspstore, child_stack, child_rbs, rbs_size;
	unsigned long stackbase = (unsigned long)tcb->stackbase;
	struct switch_stack *swstack;

	tcb->ksp = 0;
	tcb->name = name;

	/* The stack should have already been allocated. */
	rthal_prepare_stack(stackbase + KERNEL_STACK_SIZE);

	/* The value of ksp is used as a marker to indicate whether we are
	   initializing a new task or we are back from the context
	   switch. */

	if (tcb->ksp != 0)
		/* The following statement must be first. */
		xnarch_thread_trampoline(thread, imask, entry, cookie);

	child_stack = stackbase + KERNEL_STACK_SIZE - IA64_SWITCH_STACK_SIZE;
	tcb->ksp = child_stack;
	swstack = (struct switch_stack *)child_stack;
	bspstore = swstack->ar_bspstore;

	rbs =
	    (ia64_getreg(_IA64_REG_SP) & ~(KERNEL_STACK_SIZE - 1)) +
	    IA64_RBS_OFFSET;
	child_rbs = stackbase + IA64_RBS_OFFSET;
	rbs_size = bspstore - rbs;

	memcpy((void *)child_rbs, (void *)rbs, rbs_size);
	swstack->ar_bspstore = child_rbs + rbs_size;
	tcb->ksp -= 16;		/* Provide for the (bloody) scratch area... */
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

#endif /* !_XENO_ASM_IA64_BITS_POD_H */
