/*
 * Copyright (C) 2001-2007 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004-2006 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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

#ifndef _XENO_ASM_X86_BITS_POD_64_H
#define _XENO_ASM_X86_BITS_POD_64_H
#define _XENO_ASM_X86_BITS_POD_H

unsigned xnarch_tsc_scale;
unsigned xnarch_tsc_shift;
unsigned xnarch_tsc_divide;

long long xnarch_tsc_to_ns(long long ts)
{
	return xnarch_llmulshft(ts, xnarch_tsc_scale, xnarch_tsc_shift);
}
#define XNARCH_TSC_TO_NS

long long xnarch_ns_to_tsc(long long ns)
{
	return xnarch_llimd(ns, xnarch_tsc_divide, xnarch_tsc_scale);
}
#define XNARCH_NS_TO_TSC

#include <asm-generic/xenomai/bits/pod.h>
#include <asm/xenomai/switch.h>

void xnpod_welcome_thread(struct xnthread *, int);

void xnpod_delete_thread(struct xnthread *);

#ifdef CONFIG_GENERIC_CLOCKEVENTS
#define xnarch_start_timer(tick_handler, cpu)	\
	rthal_timer_request(tick_handler, xnarch_switch_htick_mode, xnarch_next_htick_shot, cpu)
#else
#define xnarch_start_timer(tick_handler, cpu)	\
	rthal_timer_request(tick_handler, cpu)
#endif

#define xnarch_stop_timer(cpu)	rthal_timer_release(cpu)

static inline void xnarch_leave_root(xnarchtcb_t *rootcb)
{
	/* Remember the preempted Linux task pointer. */
	rootcb->user_task = rootcb->active_task = current;
	rootcb->rspp = &current->thread.x86reg_sp;
	rootcb->ripp = &current->thread.rip;
	rootcb->ts_usedfpu = !!(task_thread_info(current)->status & TS_USEDFPU);
	rootcb->cr0_ts = (read_cr0() & 8) != 0;
	/* So that xnarch_save_fpu() will operate on the right FPU area. */
	if (rootcb->cr0_ts || rootcb->ts_usedfpu)
		rootcb->fpup = x86_fpustate_ptr(&rootcb->user_task->thread);
	else
		/*
		 * The kernel is currently using fpu in kernel-space,
		 * do not clobber the user-space fpu backup area.
		 */
		rootcb->fpup = &rootcb->i387;
}

static inline void xnarch_enter_root(xnarchtcb_t * rootcb)
{
}

static inline void xnarch_switch_to(xnarchtcb_t * out_tcb, xnarchtcb_t * in_tcb)
{
	struct task_struct *prev = out_tcb->active_task;
	struct task_struct *next = in_tcb->user_task;

	if (likely(next != NULL)) {
		if (task_thread_info(prev)->status & TS_USEDFPU)
			/* __switch_to will try and use __unlazy_fpu, so we need to
			   clear the ts bit. */
			clts();
		in_tcb->active_task = next;
		rthal_clear_foreign_stack(&rthal_domain);
		next->fpu_counter = 0;
	} else {
		in_tcb->active_task = prev;
		rthal_set_foreign_stack(&rthal_domain);
	}

	if (next && next != prev) {
		struct mm_struct *oldmm = prev->active_mm;

		switch_mm(oldmm, next->active_mm, next);

		if (!next->mm)
			enter_lazy_tlb(oldmm, next);
	}

	xnarch_switch_threads(prev, next, out_tcb->rspp, in_tcb->rspp, out_tcb->ripp, in_tcb->ripp);

	stts();
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
	tcb->rspp = &tcb->rsp;
	tcb->ripp = &tcb->rip;
	tcb->fpup = NULL;
	tcb->entry = NULL;
	tcb->cookie = NULL;
	tcb->self = thread;
	tcb->imask = 0;
	tcb->name = name;
	tcb->is_root = 1;
}

asmlinkage void xnarch_thread_trampoline(xnarchtcb_t *tcb)
{
	/* xnpod_welcome_thread() will do clts() if needed. */
	stts();
	xnpod_welcome_thread(tcb->self, tcb->imask);
	tcb->entry(tcb->cookie);
	xnpod_delete_thread(tcb->self);

	xnarch_thread_head();
}

static inline void xnarch_init_thread(xnarchtcb_t *tcb,
				      void (*entry)(void *),
				      void *cookie,
				      int imask,
				      struct xnthread *thread, char *name)
{
	struct xnarch_x8664_initstack *childregs;
	unsigned long *rsp, flags;

	/* Prepare the bootstrap stack. */

	rthal_local_irq_flags_hw(flags);

	rsp = (unsigned long *)((unsigned long)tcb->stackbase + tcb->stacksize -
				sizeof(struct xnarch_x8664_initstack) - 8);

	childregs = (struct xnarch_x8664_initstack *)rsp;
	childregs->rbp = 0;
	childregs->eflags = flags & ~X86_EFLAGS_IF;
	childregs->arg = (unsigned long)tcb;
	childregs->entry = (unsigned long)&xnarch_thread_trampoline;

	tcb->rsp = (unsigned long)childregs;
	tcb->rip = (unsigned long)&__thread_head; /* Will branch there at startup. */
	tcb->entry = entry;
	tcb->cookie = cookie;
	tcb->self = thread;
	tcb->imask = imask;
	tcb->name = name;
}

#ifdef CONFIG_XENO_HW_FPU

#define xnarch_fpu_init_p(task)   tsk_used_math(task)
#define xnarch_set_fpu_init(task) set_stopped_child_used_math(task)

static inline void xnarch_init_fpu(xnarchtcb_t * tcb)
{
	struct task_struct *task = tcb->user_task;
	unsigned long __mxcsr;
	/* Initialize the FPU for a task. This must be run on behalf of the
	   task. */

	__asm__ __volatile__("clts; fninit");
	__mxcsr = 0x1f80UL & 0xffbfUL;
	__asm__ __volatile__("ldmxcsr %0"::"m"(__mxcsr));

	if (task) {
		/* Real-time shadow FPU initialization: tell Linux
		   that this thread initialized its FPU hardware. The
		   fpu usage bit is necessary for xnarch_save_fpu to
		   save the FPU state at next switch. */
		xnarch_set_fpu_init(task);
		task_thread_info(task)->status |= TS_USEDFPU;
	}
}

static inline int __save_i387_checking(struct i387_fxsave_struct __user *fx) 
{ 
	int err;

	asm volatile("1:  rex64/fxsave (%[fx])\n\t"
		     "2:\n"
		     ".section .fixup,\"ax\"\n"
		     "3:  movl $-1,%[err]\n"
		     "    jmp  2b\n"
		     ".previous\n"
		     ".section __ex_table,\"a\"\n"
		     "   .align 8\n"
		     "   .quad  1b,3b\n"
		     ".previous"
		     : [err] "=r" (err), "=m" (*fx)
		     : [fx] "cdaSDb" (fx), "0" (0));

	return err;
} 

static inline void xnarch_save_fpu(xnarchtcb_t *tcb)
{
	struct task_struct *task = tcb->user_task;

	if (!tcb->is_root) {
		if (task) {
			/* fpu not used or already saved by __switch_to. */
			if (!(task_thread_info(task)->status & TS_USEDFPU))
				return;

			/* Tell Linux that we already saved the state
			 * of the FPU hardware of this task. */
			task_thread_info(task)->status &= ~TS_USEDFPU;
		}
	} else {
		if (tcb->cr0_ts || 
		    (tcb->ts_usedfpu && !(task_thread_info(task)->status & TS_USEDFPU)))
			return;

		task_thread_info(task)->status &= ~TS_USEDFPU;
	}

	clts();

	__save_i387_checking(&tcb->fpup->fxsave);
}

static inline int __restore_i387_checking(struct i387_fxsave_struct *fx)
{ 
	int err;

	asm volatile("1:  rex64/fxrstor (%[fx])\n\t"
		     "2:\n"
		     ".section .fixup,\"ax\"\n"
		     "3:  movl $-1,%[err]\n"
		     "    jmp  2b\n"
		     ".previous\n"
		     ".section __ex_table,\"a\"\n"
		     "   .align 8\n"
		     "   .quad  1b,3b\n"
		     ".previous"
		     : [err] "=r" (err)
		     : [fx] "cdaSDb" (fx), "m" (*fx), "0" (0));

	return err;
} 

static inline void xnarch_restore_fpu(xnarchtcb_t * tcb)
{
	struct task_struct *task = tcb->user_task;

	if (!tcb->is_root) {
		if (task) {
			if (!xnarch_fpu_init_p(task)) {
				stts();
				return;	/* Uninit fpu area -- do not restore. */
			}

			/* Tell Linux that this task has altered the state of
			 * the FPU hardware. */
			task_thread_info(task)->status |= TS_USEDFPU;
		}
	} else {
		/* Restore state of FPU only if TS bit in cr0 was clear. */
		if (tcb->cr0_ts) {
			stts();
			return;
		}

		if (tcb->ts_usedfpu)
			task_thread_info(task)->status |= TS_USEDFPU;
	}

	/* Restore the FPU hardware with valid fp registers from a
	   user-space or kernel thread. */
	clts();

	__restore_i387_checking(&tcb->fpup->fxsave);
}

static inline void xnarch_enable_fpu(xnarchtcb_t * tcb)
{
	struct task_struct *task = tcb->user_task;

	if (!tcb->is_root) {
		if (task) {
			if (!xnarch_fpu_init_p(task))
				return;

			/* If "task" switched while in Linux domain, its FPU
			 * context may have been overriden, restore it. */
			if (!(task_thread_info(task)->status & TS_USEDFPU)) {
				xnarch_restore_fpu(tcb);
				return;
			}
		}
	} else {
		if (tcb->cr0_ts)
			return;

		if (!(task_thread_info(task)->status & TS_USEDFPU)) {
			xnarch_restore_fpu(tcb);
			return;
		}
	}

	clts();
}

#else /* !CONFIG_XENO_HW_FPU */

static inline void xnarch_init_fpu(xnarchtcb_t *tcb)
{
}

static inline void xnarch_save_fpu(xnarchtcb_t *tcb)
{
}

static inline void xnarch_restore_fpu(xnarchtcb_t *tcb)
{
}

static inline void xnarch_enable_fpu(xnarchtcb_t *tcb)
{
}

#endif /* CONFIG_XENO_HW_FPU */

static inline int xnarch_escalate(void)
{
	extern int xnarch_escalation_virq;

	if (rthal_current_domain == rthal_root_domain) {
		rthal_trigger_irq(xnarch_escalation_virq);
		return 1;
	}

	return 0;
}

#endif /* !_XENO_ASM_X86_BITS_POD_64_H */
