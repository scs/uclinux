/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004 The HYADES Project (http://www.hyades-itea.org).
 * Copyright (C) 2004,2005 Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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

#ifndef _XENO_ASM_X86_BITS_POD_32_H
#define _XENO_ASM_X86_BITS_POD_32_H
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

static inline void xnarch_leave_root(xnarchtcb_t * rootcb)
{
	/* Remember the preempted Linux task pointer. */
	rootcb->user_task = rootcb->active_task = current;
	rootcb->ts_usedfpu = wrap_test_fpu_used(current) != 0;
	rootcb->cr0_ts = (read_cr0() & 8) != 0;
	/* So that xnarch_save_fpu() will operate on the right FPU area. */
	if (rootcb->cr0_ts || rootcb->ts_usedfpu)
		rootcb->fpup = x86_fpustate_ptr(&rootcb->user_task->thread);
	else
		/*
		 * The kernel is currently using fpu in kernel-space,
		 * do not clobber the user-space fpu backup area.
		 */
		rootcb->fpup = &rootcb->fpuenv;
}

#define xnarch_enter_root(rootcb)  do { } while(0)

static inline void xnarch_switch_to(xnarchtcb_t * out_tcb, xnarchtcb_t * in_tcb)
{
	struct task_struct *prev = out_tcb->active_task;
	struct task_struct *next = in_tcb->user_task;
	unsigned long fs, gs;

	if (likely(next != NULL)) {
		if (wrap_test_fpu_used(prev))
			/* __switch_to will try and use __unlazy_fpu, so we need to
			   clear the ts bit. */
			clts();
		in_tcb->active_task = next;
		rthal_clear_foreign_stack(&rthal_domain);
	} else {
		in_tcb->active_task = prev;
		rthal_set_foreign_stack(&rthal_domain);
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
	if (next)
		next->fpu_counter = 0;
#endif /* Linux version >= 2.6.20 */

	if (next && next != prev) {
		struct mm_struct *oldmm = prev->active_mm;

		wrap_switch_mm(oldmm, next->active_mm, next);

		if (!next->mm)
			wrap_enter_lazy_tlb(oldmm, next);
	}

	if (out_tcb->user_task) {
		/* Make sure that __switch_to() will always reload the correct
		   %fs and %gs registers, even if we happen to migrate the task
		   across domains in the meantime. */
		asm volatile ("mov %%fs,%0":"=m" (fs));
		asm volatile ("mov %%gs,%0":"=m" (gs));
	}

	xnarch_switch_threads(out_tcb, in_tcb, prev, next);

	if (xnarch_shadow_p(out_tcb, prev)) {

		loadsegment(fs, fs);
		loadsegment(gs, gs);

		barrier();

		/* Eagerly reinstate the I/O bitmap of any incoming shadow
		   thread which has previously requested I/O permissions. We
		   don't want the unexpected latencies induced by lazy update
		   from the GPF handler to bite shadow threads that
		   explicitly told the kernel that they would need to perform
		   raw I/O ops. */

		wrap_switch_iobitmap(prev, rthal_processor_id());
	}

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
	tcb->esp = 0;
	tcb->espp = &tcb->esp;
	tcb->eipp = &tcb->eip;
	tcb->fpup = NULL;
	tcb->is_root = 1;
}

asmlinkage static void xnarch_thread_redirect(struct xnthread *self,
					      int imask,
					      void (*entry) (void *),
					      void *cookie)
{
	/* xnpod_welcome_thread() will do clts() if needed. */
	stts();
	xnpod_welcome_thread(self, imask);
	entry(cookie);
	xnpod_delete_thread(self);
}

static inline void xnarch_init_thread(xnarchtcb_t * tcb,
				      void (*entry) (void *),
				      void *cookie,
				      int imask,
				      struct xnthread *thread, char *name)
{
	unsigned long **psp = (unsigned long **)&tcb->esp;

	tcb->eip = (unsigned long)&xnarch_thread_redirect;
	tcb->esp = (unsigned long)tcb->stackbase;
	**psp = 0;		/* Commit bottom stack memory */
	*psp =
		(unsigned long *)(((unsigned long)*psp + tcb->stacksize - 0x10) &
				  ~0xf);
	*--(*psp) = (unsigned long)cookie;
	*--(*psp) = (unsigned long)entry;
	*--(*psp) = (unsigned long)imask;
	*--(*psp) = (unsigned long)thread;
	*--(*psp) = 0;
}

#ifdef CONFIG_XENO_HW_FPU

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 11)
#define xnarch_fpu_init_p(task)   ((task)->used_math)
#define xnarch_set_fpu_init(task) ((task)->used_math = 1)
#else
#define xnarch_fpu_init_p(task)   tsk_used_math(task)
#define xnarch_set_fpu_init(task) set_stopped_child_used_math(task)
#endif

static inline void xnarch_init_fpu(xnarchtcb_t * tcb)
{
	struct task_struct *task = tcb->user_task;
	/* Initialize the FPU for a task. This must be run on behalf of the
	   task. */

	__asm__ __volatile__("clts; fninit");

	if (cpu_has_xmm) {
		unsigned long __mxcsr = 0x1f80UL & 0xffbfUL;
		__asm__ __volatile__("ldmxcsr %0"::"m"(__mxcsr));
	}

	if (task) {
		/* Real-time shadow FPU initialization: tell Linux that this
		   thread initialized its FPU hardware. The fpu usage bit is
		   necessary for xnarch_save_fpu to save the FPU state at next
		   switch. */
		xnarch_set_fpu_init(task);
		wrap_set_fpu_used(task);
	}
}

static inline void xnarch_save_fpu(xnarchtcb_t * tcb)
{
	struct task_struct *task = tcb->user_task;

	if (!tcb->is_root) {
		if (task) {
			/* fpu not used or already saved by __switch_to. */
			if (!wrap_test_fpu_used(task))
				return;

			/* Tell Linux that we already saved the state of the FPU
		   	hardware of this task. */
			wrap_clear_fpu_used(task);
		}
	} else {
		if (tcb->cr0_ts || 
		    (tcb->ts_usedfpu && !wrap_test_fpu_used(task)))
			return;

		wrap_clear_fpu_used(task);
	}

	clts();

	if (cpu_has_fxsr)
		__asm__ __volatile__("fxsave %0; fnclex":"=m"(*tcb->fpup));
	else
		__asm__ __volatile__("fnsave %0; fwait":"=m"(*tcb->fpup));
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
			wrap_set_fpu_used(task);
		}
	} else {
		/* Restore state of FPU only if TS bit in cr0 was clear. */
		if (tcb->cr0_ts) {
			stts();
			return;
		}

		if (tcb->ts_usedfpu)
			wrap_set_fpu_used(task);
	}

	/* Restore the FPU hardware with valid fp registers from a
	   user-space or kernel thread. */
	clts();

	if (cpu_has_fxsr)
		__asm__ __volatile__("fxrstor %0": /* no output */
				     :"m"(*tcb->fpup));
	else
		__asm__ __volatile__("frstor %0": /* no output */ :"m"(*tcb->
								       fpup));
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
			if (!wrap_test_fpu_used(task)) {
				xnarch_restore_fpu(tcb);
				return;
			}
		}
	} else {
		if (tcb->cr0_ts)
			return;

		if (wrap_test_fpu_used(task)) {
			/* Fpu context was not even saved, do not restore */
			clts();
			return;
		}
		
		xnarch_restore_fpu(tcb);
		return;
	}

	clts();

	if (!cpu_has_fxsr && task)
		/* fnsave, called by switch_to, initialized the FPU state, so that on
		   cpus prior to PII (i.e. without fxsr), we need to restore the saved
		   state. */
		__asm__ __volatile__("frstor %0": /* no output */
				     :"m"(*tcb->fpup));
}

#else /* !CONFIG_XENO_HW_FPU */

static inline void xnarch_init_fpu(xnarchtcb_t * tcb)
{
}

static inline void xnarch_save_fpu(xnarchtcb_t * tcb)
{
}

static inline void xnarch_restore_fpu(xnarchtcb_t * tcb)
{
}

static inline void xnarch_enable_fpu(xnarchtcb_t * tcb)
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

#endif /* !_XENO_ASM_X86_BITS_POD_32_H */
