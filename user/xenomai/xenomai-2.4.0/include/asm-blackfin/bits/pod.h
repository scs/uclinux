/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_BLACKFIN_BITS_POD_H
#define _XENO_ASM_BLACKFIN_BITS_POD_H

unsigned xnarch_tsc_scale;
unsigned xnarch_tsc_shift;

long long xnarch_tsc_to_ns(long long ts)
{
	return xnarch_llmulshft(ts, xnarch_tsc_scale, xnarch_tsc_shift);
}
#define XNARCH_TSC_TO_NS

#include <asm-generic/xenomai/bits/pod.h>

void xnpod_welcome_thread(struct xnthread *, int);

void xnpod_delete_thread(struct xnthread *);

/*
 * The I-pipe frees the Blackfin core timer for us, therefore we don't
 * need any host tick relay service since the regular Linux time
 * source is still ticking in parallel at the normal pace through
 * TIMER0.
 */
#define xnarch_start_timer(tick_handler, cpu)	\
	({ int __tickval = rthal_timer_request(tick_handler, cpu); __tickval; })

#define xnarch_stop_timer(cpu)	rthal_timer_release(cpu)

static inline void xnarch_leave_root(xnarchtcb_t * rootcb)
{
	/* Remember the preempted Linux task pointer. */
	rootcb->user_task = current;
	rootcb->tsp = &current->thread;
}

static inline void xnarch_enter_root(xnarchtcb_t * rootcb)
{
}

static inline void xnarch_switch_to(xnarchtcb_t * out_tcb, xnarchtcb_t * in_tcb)
{
	if (in_tcb->user_task)
		rthal_clear_foreign_stack(&rthal_domain);
	else
		rthal_set_foreign_stack(&rthal_domain);

	rthal_thread_switch(out_tcb->tsp, in_tcb->tsp);
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
	tcb->tsp = &tcb->ts;
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
	unsigned long *ksp;

	ksp =
	    (unsigned long
	     *)(((unsigned long)tcb->stackbase + tcb->stacksize - 40) & ~0xf);
	ksp[0] = (unsigned long)tcb;	/* r0 */
	memset(&ksp[1], 0, sizeof(long) * 7);	/* ( R7:4, P5:3 ) */
	ksp[8] = 0;		/* fp */
	ksp[9] = (unsigned long)&xnarch_thread_trampoline;	/* rets */

	tcb->ts.ksp = (unsigned long)ksp;
	tcb->ts.pc = (unsigned long)&rthal_thread_trampoline;
	tcb->ts.usp = 0;

	tcb->entry = entry;
	tcb->cookie = cookie;
	tcb->self = thread;
	tcb->imask = imask;
	tcb->name = name;
}

#define xnarch_fpu_init_p(task) (0)

static inline void xnarch_enable_fpu(xnarchtcb_t * current_tcb)
{
}

static inline void xnarch_init_fpu(xnarchtcb_t * tcb)
{
}

static inline void xnarch_save_fpu(xnarchtcb_t * tcb)
{
}

static inline void xnarch_restore_fpu(xnarchtcb_t * tcb)
{
}

static inline int xnarch_escalate(void)
{
	extern int xnarch_escalation_virq;

	/* The following Blackfin-specific check is likely the most
	 * braindamage stuff we need to do for this arch, i.e. deferring
	 * Xenomai's rescheduling procedure whenever:

	 * 1. ILAT tells us that a deferred syscall (EVT15) is pending, so
	 * that we don't later execute this syscall over the wrong thread
	 * context. This could happen whenever a user-space task (plain or
	 * Xenomai) gets preempted by a high priority interrupt right
	 * after the deferred syscall event is raised (EVT15) but before
	 * the evt_system_call ISR could run. In case of deferred Xenomai
	 * rescheduling, the pending rescheduling opportunity will be
	 * checked at the beginning of Xenomai's do_hisyscall_event which
	 * intercepts any incoming syscall, and we know it will happen
	 * shortly after.
	 *
	 * 2. the context we will switch back to belongs to the Linux
	 * kernel code, so that we don't inadvertently cause the CPU to
	 * switch to user operating mode as a result of returning from an
	 * interrupt stack frame over the incoming thread through RTI. In
	 * the latter case, the preempted kernel code will be diverted
	 * shortly before resumption in order to run the rescheduling
	 * procedure (see __ipipe_irq_tail_hook).
	 */

	if (rthal_defer_switch_p()) {
		__ipipe_lock_root();
		return 1;
	}

	__ipipe_unlock_root();

	if (rthal_current_domain == rthal_root_domain) {
		rthal_trigger_irq(xnarch_escalation_virq);
		return 1;
	}

	return 0;
}

#endif /* !_XENO_ASM_BLACKFIN_BITS_POD_H */
