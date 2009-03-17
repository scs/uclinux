/*
 * Copyright &copy; 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_IA64_BITS_INIT_H
#define _XENO_ASM_IA64_BITS_INIT_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

#include <linux/init.h>
#include <asm/xenomai/calibration.h>

int xnarch_escalation_virq;

int xnpod_trap_fault(xnarch_fltinfo_t *fltinfo);

void xnpod_schedule_handler(void);

static rthal_trap_handler_t xnarch_old_trap_handler;

#ifdef CONFIG_SMP
static xnlock_t xnarch_stacks_lock = XNARCH_LOCK_UNLOCKED;
#endif
static atomic_counter_t xnarch_allocated_stacks;

static xnarch_stack_t xnarch_free_stacks_q;
static atomic_counter_t xnarch_free_stacks_count;

static int xnarch_trap_fault(unsigned event, unsigned domid, void *data)
{
	xnarch_fltinfo_t fltinfo;

	fltinfo.trap = event;
	fltinfo.ia64 = *(ia64trapinfo_t *) data;

	return xnpod_trap_fault(&fltinfo);
}

unsigned long xnarch_calibrate_timer(void)
{
	/* Compute the time needed to program the ITM in aperiodic
	   mode. The return value is expressed in CPU ticks. */
	return xnarch_ns_to_tsc(rthal_timer_calibrate())? : 1;
}

int xnarch_calibrate_sched(void)
{
	nktimerlat = xnarch_calibrate_timer();

	if (!nktimerlat)
		return -ENODEV;

	nklatency = xnarch_ns_to_tsc(xnarch_get_sched_latency()) + nktimerlat;

	return 0;
}

static inline void stacksq_push(xnarch_stack_t * q, xnarch_stack_t * stack)
{
	stack->next = q->next;
	q->next = stack;
}

static inline xnarch_stack_t *stacksq_pop(xnarch_stack_t * q)
{
	xnarch_stack_t *stack = q->next;

	if (stack)
		q->next = stack->next;

	return stack;
}

int xnarch_alloc_stack(xnarchtcb_t * tcb, unsigned stacksize)
{
	xnarch_stack_t *stack;
	spl_t s;

	if (stacksize > KERNEL_STACK_SIZE)
		return -EINVAL;

	tcb->stacksize = stacksize;

	if (stacksize == 0) {
		tcb->stackbase = NULL;
		return 0;
	}

	stacksize = KERNEL_STACK_SIZE;	/* No matter what, this is what you
					   will have on this arch. */

	if (rthal_current_domain == rthal_root_domain &&
	    atomic_read(&xnarch_free_stacks_count) <=
	    CONFIG_XENO_HW_IA64_STACK_POOL) {
		stack = (xnarch_stack_t *)
		    __get_free_pages(GFP_KERNEL, KERNEL_STACK_SIZE_ORDER);

		if (stack)
			atomic_inc(&xnarch_allocated_stacks);

		goto done;
	}

	xnlock_get_irqsave(&xnarch_stacks_lock, s);
	stack = stacksq_pop(&xnarch_free_stacks_q);
	xnlock_put_irqrestore(&xnarch_stacks_lock, s);

	if (stack)
		atomic_dec(&xnarch_free_stacks_count);

      done:

	tcb->stackbase = stack;

	return stack ? 0 : -ENOMEM;
}

void xnarch_free_stack(xnarchtcb_t * tcb)
{
	xnarch_stack_t *stack = tcb->stackbase;
	spl_t s;

	if (!stack)
		return;

	if (rthal_current_domain == rthal_root_domain
	    && atomic_read(&xnarch_free_stacks_count) >
	    CONFIG_XENO_HW_IA64_STACK_POOL) {
		atomic_dec(&xnarch_allocated_stacks);
		free_pages((unsigned long)stack, KERNEL_STACK_SIZE_ORDER);
		return;
	}

	xnlock_get_irqsave(&xnarch_stacks_lock, s);
	stacksq_push(&xnarch_free_stacks_q, stack);
	xnlock_put_irqrestore(&xnarch_stacks_lock, s);

	atomic_inc(&xnarch_free_stacks_count);
}

static int xnarch_stack_pool_init(void)
{
	while (atomic_read(&xnarch_free_stacks_count) <
	       CONFIG_XENO_HW_IA64_STACK_POOL) {
		xnarchtcb_t tcb;	/* Fake TCB only to allocate and recycle stacks. */

		if (xnarch_alloc_stack(&tcb, KERNEL_STACK_SIZE))
			return -ENOMEM;

		xnarch_free_stack(&tcb);
	}

	return 0;
}

static void xnarch_stack_pool_destroy(void)
{
	xnarch_stack_t *stack;

	stack = stacksq_pop(&xnarch_free_stacks_q);

	while (stack) {
		free_pages((unsigned long)stack, KERNEL_STACK_SIZE_ORDER);
		stack = stacksq_pop(&xnarch_free_stacks_q);

		if (atomic_dec_and_test(&xnarch_allocated_stacks))
			break;
	}

	if (atomic_read(&xnarch_allocated_stacks) != 0)
		xnarch_logwarn("leaked %u kernel threads stacks.\n",
			       atomic_read(&xnarch_allocated_stacks));

	if (xnarch_free_stacks_q.next)
		xnarch_logwarn("kernel threads stacks pool corrupted.\n");
}

static inline int xnarch_init(void)
{
	int err;

	err = rthal_init();

	if (err)
		return err;

#if defined(CONFIG_SMP) && defined(MODULE)
	/* Make sure the init sequence is kept on the same CPU when
	   running as a module. */
	set_cpus_allowed(current, cpumask_of_cpu(0));
#endif /* CONFIG_SMP && MODULE */

	err = xnarch_calibrate_sched();

	if (err)
		return err;

	xnarch_escalation_virq = rthal_alloc_virq();

	if (xnarch_escalation_virq == 0)
		return -ENOSYS;

	rthal_virtualize_irq(&rthal_domain,
			     xnarch_escalation_virq,
			     (rthal_irq_handler_t) & xnpod_schedule_handler,
			     NULL, NULL, IPIPE_HANDLE_MASK | IPIPE_WIRED_MASK);

	xnarch_old_trap_handler = rthal_trap_catch(&xnarch_trap_fault);

	err = xnarch_stack_pool_init();

	if (!err)
		return 0;

	rthal_trap_catch(xnarch_old_trap_handler);
	rthal_free_virq(xnarch_escalation_virq);

	return err;
}

static inline void xnarch_exit(void)
{
	rthal_trap_catch(xnarch_old_trap_handler);
	rthal_free_virq(xnarch_escalation_virq);
	xnarch_stack_pool_destroy();
	rthal_exit();
}

#endif /* !_XENO_ASM_IA64_BITS_INIT_H */
