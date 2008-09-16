/*!\file
 * \brief Interrupt management.
 * \author Philippe Gerum
 *
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2005,2006 Dmitry Adamushko <dmitry.adamushko@gmail.com>.
 * Copyright (C) 2007 Jan Kiszka <jan.kiszka@web.de>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
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
 *
 * \ingroup intr
 */

/*!
 * \ingroup nucleus
 * \defgroup intr Interrupt management.
 *
 * Interrupt management.
 *
 *@{*/

#include <nucleus/pod.h>
#include <nucleus/intr.h>
#include <nucleus/stat.h>
#include <asm/xenomai/bits/intr.h>

#define XNINTR_MAX_UNHANDLED	1000

DEFINE_PRIVATE_XNLOCK(intrlock);

#ifdef CONFIG_XENO_OPT_STATS
xnintr_t nkclock;	/* Only for statistics */
int xnintr_count = 1;	/* Number of attached xnintr objects + nkclock */
int xnintr_list_rev;	/* Modification counter of xnintr list */

/* Both functions update xnintr_list_rev at the very end.
 * This guarantees that module.c::stat_seq_open() won't get
 * an up-to-date xnintr_list_rev and old xnintr_count. */

static inline void xnintr_stat_counter_inc(void)
{
	xnintr_count++;
	xnarch_memory_barrier();
	xnintr_list_rev++;
}

static inline void xnintr_stat_counter_dec(void)
{
	xnintr_count--;
	xnarch_memory_barrier();
	xnintr_list_rev++;
}

static inline void xnintr_sync_stat_references(xnintr_t *intr)
{
	int cpu;

	for_each_online_cpu(cpu) {
		xnsched_t *sched = xnpod_sched_slot(cpu);

		/* Synchronize on all dangling references to go away. */
		while (sched->current_account == &intr->stat[cpu].account)
			cpu_relax();
	}
}
#else
static inline void xnintr_stat_counter_inc(void) {}
static inline void xnintr_stat_counter_dec(void) {}
static inline void xnintr_sync_stat_references(xnintr_t *intr) {}
#endif /* CONFIG_XENO_OPT_STATS */

static void xnintr_irq_handler(unsigned irq, void *cookie);

/* Low-level clock irq handler. */

void xnintr_clock_handler(void)
{
	xnsched_t *sched = xnpod_current_sched();
	xnstat_exectime_t *prev;
	xnticks_t start;

	prev  = xnstat_exectime_get_current(sched);
	start = xnstat_exectime_now();

	xnarch_announce_tick();

	trace_mark(xn_nucleus_irq_enter, "irq %d", XNARCH_TIMER_IRQ);
	trace_mark(xn_nucleus_tbase_tick, "base %s", nktbase.name);

	++sched->inesting;

	xnlock_get(&nklock);
	xntimer_tick_aperiodic();
	xnlock_put(&nklock);

	xnstat_counter_inc(&nkclock.stat[xnsched_cpu(sched)].hits);
	xnstat_exectime_lazy_switch(sched,
		&nkclock.stat[xnsched_cpu(sched)].account, start);

	if (--sched->inesting == 0 && xnsched_resched_p())
		xnpod_schedule();

	/* Since the host tick is low priority, we can wait for returning
	   from the rescheduling procedure before actually calling the
	   propagation service, if it is pending. */

	if (testbits(sched->status, XNHTICK)) {
		__clrbits(sched->status, XNHTICK);
		xnarch_relay_tick();
	}

	trace_mark(xn_nucleus_irq_exit, "irq %d", XNARCH_TIMER_IRQ);
	xnstat_exectime_switch(sched, prev);
}

/* Optional support for shared interrupts. */

#ifdef CONFIG_XENO_OPT_SHIRQ

typedef struct xnintr_irq {

	DECLARE_XNLOCK(lock);

	xnintr_t *handlers;
	int unhandled;

} ____cacheline_aligned_in_smp xnintr_irq_t;

static xnintr_irq_t xnirqs[XNARCH_NR_IRQS];

static inline xnintr_t *xnintr_shirq_first(unsigned irq)
{
	return xnirqs[irq].handlers;
}

static inline xnintr_t *xnintr_shirq_next(xnintr_t *prev)
{
	return prev->next;
}

/*
 * Low-level interrupt handler dispatching the user-defined ISRs for
 * shared interrupts -- Called with interrupts off.
 */
static void xnintr_shirq_handler(unsigned irq, void *cookie)
{
	xnsched_t *sched = xnpod_current_sched();
	xnstat_exectime_t *prev;
	xnticks_t start;
	xnintr_irq_t *shirq = &xnirqs[irq];
	xnintr_t *intr;
	int s = 0;

	prev  = xnstat_exectime_get_current(sched);
	start = xnstat_exectime_now();
	trace_mark(xn_nucleus_irq_enter, "irq %d", irq);

	++sched->inesting;

	xnlock_get(&shirq->lock);
	intr = shirq->handlers;

	while (intr) {
		int ret;

		ret = intr->isr(intr);
		s |= ret;

		if (ret & XN_ISR_HANDLED) {
			xnstat_counter_inc(
				&intr->stat[xnsched_cpu(sched)].hits);
			xnstat_exectime_lazy_switch(sched,
				&intr->stat[xnsched_cpu(sched)].account,
				start);
			start = xnstat_exectime_now();
		}

		intr = intr->next;
	}

	xnlock_put(&shirq->lock);

	if (unlikely(s == XN_ISR_NONE)) {
		if (++shirq->unhandled == XNINTR_MAX_UNHANDLED) {
			xnlogerr("%s: IRQ%d not handled. Disabling IRQ "
				 "line.\n", __FUNCTION__, irq);
			s |= XN_ISR_NOENABLE;
		}
	} else
		shirq->unhandled = 0;

	if (s & XN_ISR_PROPAGATE)
		xnarch_chain_irq(irq);
	else if (!(s & XN_ISR_NOENABLE))
		xnarch_end_irq(irq);

	if (--sched->inesting == 0 && xnsched_resched_p())
		xnpod_schedule();

	trace_mark(xn_nucleus_irq_exit, "irq %d", irq);
	xnstat_exectime_switch(sched, prev);
}

/*
 * Low-level interrupt handler dispatching the user-defined ISRs for
 * shared edge-triggered interrupts -- Called with interrupts off.
 */
static void xnintr_edge_shirq_handler(unsigned irq, void *cookie)
{
	const int MAX_EDGEIRQ_COUNTER = 128;

	xnsched_t *sched = xnpod_current_sched();
	xnstat_exectime_t *prev;
	xnticks_t start;
	xnintr_irq_t *shirq = &xnirqs[irq];
	xnintr_t *intr, *end = NULL;
	int s = 0, counter = 0;

	prev  = xnstat_exectime_get_current(sched);
	start = xnstat_exectime_now();
	trace_mark(xn_nucleus_irq_enter, "irq %d", irq);

	++sched->inesting;

	xnlock_get(&shirq->lock);
	intr = shirq->handlers;

	while (intr != end) {
		int ret, code;

		xnstat_exectime_switch(sched,
			&intr->stat[xnsched_cpu(sched)].account);

		ret = intr->isr(intr);
		code = ret & ~XN_ISR_BITMASK;
		s |= ret;

		if (code == XN_ISR_HANDLED) {
			end = NULL;
			xnstat_counter_inc(
				&intr->stat[xnsched_cpu(sched)].hits);
			xnstat_exectime_lazy_switch(sched,
				&intr->stat[xnsched_cpu(sched)].account,
				start);
			start = xnstat_exectime_now();
		} else if (end == NULL)
			end = intr;

		if (counter++ > MAX_EDGEIRQ_COUNTER)
			break;

		if (!(intr = intr->next))
			intr = shirq->handlers;
	}

	xnlock_put(&shirq->lock);

	if (counter > MAX_EDGEIRQ_COUNTER)
		xnlogerr
		    ("xnintr_edge_shirq_handler() : failed to get the IRQ%d line free.\n",
		     irq);

	if (unlikely(s == XN_ISR_NONE)) {
		if (++shirq->unhandled == XNINTR_MAX_UNHANDLED) {
			xnlogerr("%s: IRQ%d not handled. Disabling IRQ "
			         "line.\n", __FUNCTION__, irq);
			s |= XN_ISR_NOENABLE;
		}
	} else
		shirq->unhandled = 0;

	if (s & XN_ISR_PROPAGATE)
		xnarch_chain_irq(irq);
	else if (!(s & XN_ISR_NOENABLE))
		xnarch_end_irq(irq);

	if (--sched->inesting == 0 && xnsched_resched_p())
		xnpod_schedule();

	trace_mark(xn_nucleus_irq_exit, "irq %d", irq);
	xnstat_exectime_switch(sched, prev);
}

static inline int xnintr_irq_attach(xnintr_t *intr)
{
	xnintr_irq_t *shirq = &xnirqs[intr->irq];
	xnintr_t *prev, **p = &shirq->handlers;
	int err;

	if (intr->irq >= XNARCH_NR_IRQS)
		return -EINVAL;

	if (__testbits(intr->flags, XN_ISR_ATTACHED))
		return -EPERM;

	if ((prev = *p) != NULL) {
		/* Check on whether the shared mode is allowed. */
		if (!(prev->flags & intr->flags & XN_ISR_SHARED) ||
		    (prev->iack != intr->iack)
		    || ((prev->flags & XN_ISR_EDGE) !=
			(intr->flags & XN_ISR_EDGE)))
			return -EBUSY;

		/* Get a position at the end of the list to insert the new element. */
		while (prev) {
			p = &prev->next;
			prev = *p;
		}
	} else {
		/* Initialize the corresponding interrupt channel */
		void (*handler) (unsigned, void *) = &xnintr_irq_handler;

		if (intr->flags & XN_ISR_SHARED) {
			if (intr->flags & XN_ISR_EDGE)
				handler = &xnintr_edge_shirq_handler;
			else
				handler = &xnintr_shirq_handler;

		}
		shirq->unhandled = 0;

		err = xnarch_hook_irq(intr->irq, handler, intr->iack, intr);
		if (err)
			return err;
	}

	__setbits(intr->flags, XN_ISR_ATTACHED);

	intr->next = NULL;

	/* Add the given interrupt object. No need to synchronise with the IRQ
	   handler, we are only extending the chain. */
	*p = intr;

	return 0;
}

static inline int xnintr_irq_detach(xnintr_t *intr)
{
	xnintr_irq_t *shirq = &xnirqs[intr->irq];
	xnintr_t *e, **p = &shirq->handlers;
	int err = 0;

	if (intr->irq >= XNARCH_NR_IRQS)
		return -EINVAL;

	if (!__testbits(intr->flags, XN_ISR_ATTACHED))
		return -EPERM;

	__clrbits(intr->flags, XN_ISR_ATTACHED);

	while ((e = *p) != NULL) {
		if (e == intr) {
			/* Remove the given interrupt object from the list. */
			xnlock_get(&shirq->lock);
			*p = e->next;
			xnlock_put(&shirq->lock);

			xnintr_sync_stat_references(intr);

			/* Release the IRQ line if this was the last user */
			if (shirq->handlers == NULL)
				err = xnarch_release_irq(intr->irq);

			return err;
		}
		p = &e->next;
	}

	xnlogerr("attempted to detach a non previously attached interrupt "
		 "object.\n");
	return err;
}

#else /* !CONFIG_XENO_OPT_SHIRQ */

#ifdef CONFIG_SMP
typedef struct xnintr_irq {

	DECLARE_XNLOCK(lock);

} ____cacheline_aligned_in_smp xnintr_irq_t;

static xnintr_irq_t xnirqs[XNARCH_NR_IRQS];
#endif /* CONFIG_SMP */

static inline xnintr_t *xnintr_shirq_first(unsigned irq)
{
	return xnarch_get_irq_cookie(irq);
}

static inline xnintr_t *xnintr_shirq_next(xnintr_t *prev)
{
	return NULL;
}

static inline int xnintr_irq_attach(xnintr_t *intr)
{
	return xnarch_hook_irq(intr->irq, &xnintr_irq_handler, intr->iack, intr);
}

static inline int xnintr_irq_detach(xnintr_t *intr)
{
	int irq = intr->irq, err;

	xnlock_get(&xnirqs[irq].lock);
	err = xnarch_release_irq(irq);
	xnlock_put(&xnirqs[irq].lock);

	xnintr_sync_stat_references(intr);

	return err;
}

#endif /* !CONFIG_XENO_OPT_SHIRQ */

/*
 * Low-level interrupt handler dispatching non-shared ISRs -- Called with
 * interrupts off.
 */
static void xnintr_irq_handler(unsigned irq, void *cookie)
{
	xnsched_t *sched = xnpod_current_sched();
	xnintr_t *intr;
	xnstat_exectime_t *prev;
	xnticks_t start;
	int s;

	prev  = xnstat_exectime_get_current(sched);
	start = xnstat_exectime_now();
	trace_mark(xn_nucleus_irq_enter, "irq %d", irq);

	++sched->inesting;

	xnlock_get(&xnirqs[irq].lock);

#ifdef CONFIG_SMP
	/* In SMP case, we have to reload the cookie under the per-IRQ lock
	   to avoid racing with xnintr_detach. */
	intr = xnarch_get_irq_cookie(irq);
	if (unlikely(!intr)) {
		s = 0;
		goto unlock_and_exit;
	}
#else
	/* cookie always valid, attach/detach happens with IRQs disabled */
	intr = cookie;
#endif
	s = intr->isr(intr);

	if (unlikely(s == XN_ISR_NONE)) {
		if (++intr->unhandled == XNINTR_MAX_UNHANDLED) {
			xnlogerr("%s: IRQ%d not handled. Disabling IRQ "
				 "line.\n", __FUNCTION__, irq);
			s |= XN_ISR_NOENABLE;
		}
	} else {
		xnstat_counter_inc(&intr->stat[xnsched_cpu(sched)].hits);
		xnstat_exectime_lazy_switch(sched,
			&intr->stat[xnsched_cpu(sched)].account,
			start);
		intr->unhandled = 0;
	}

#ifdef CONFIG_SMP
 unlock_and_exit:
#endif
	xnlock_put(&xnirqs[irq].lock);

	if (s & XN_ISR_PROPAGATE)
		xnarch_chain_irq(irq);
	else if (!(s & XN_ISR_NOENABLE))
		xnarch_end_irq(irq);

	if (--sched->inesting == 0 && xnsched_resched_p())
		xnpod_schedule();

	trace_mark(xn_nucleus_irq_exit, "irq %d", irq);
	xnstat_exectime_switch(sched, prev);
}

int __init xnintr_mount(void)
{
	int i;
	for (i = 0; i < XNARCH_NR_IRQS; ++i)
		xnlock_init(&xnirqs[i].lock);
	return 0;
}

/*!
 * \fn int xnintr_init (xnintr_t *intr,const char *name,unsigned irq,xnisr_t isr,xniack_t iack,xnflags_t flags)
 * \brief Initialize an interrupt object.
 *
 * Associates an interrupt object with an IRQ line.
 *
 * When an interrupt occurs on the given @a irq line, the ISR is fired
 * in order to deal with the hardware event. The interrupt service
 * code may call any non-suspensive service from the nucleus.
 *
 * Upon receipt of an IRQ, the ISR is immediately called on behalf of
 * the interrupted stack context, the rescheduling procedure is
 * locked, and the interrupt source is masked at hardware level. The
 * status value returned by the ISR is then checked for the following
 * values:
 *
 * - XN_ISR_HANDLED indicates that the interrupt request has been fulfilled
 * by the ISR.
 *
 * - XN_ISR_NONE indicates the opposite to XN_ISR_HANDLED. The ISR must always
 * return this value when it determines that the interrupt request has not been
 * issued by the dedicated hardware device.
 *
 * In addition, one of the following bits may be set by the ISR :
 *
 * NOTE: use these bits with care and only when you do understand their effect
 * on the system.
 * The ISR is not encouraged to use these bits in case it shares the IRQ line
 * with other ISRs in the real-time domain.
 *
 * - XN_ISR_PROPAGATE tells the nucleus to require the real-time control
 * layer to forward the IRQ. For instance, this would cause the Adeos
 * control layer to propagate the interrupt down the interrupt
 * pipeline to other Adeos domains, such as Linux. This is the regular
 * way to share interrupts between the nucleus and the host system.
 *
 * - XN_ISR_NOENABLE causes the nucleus to ask the real-time control
 * layer _not_ to re-enable the IRQ line (read the following section).
 * xnarch_end_irq() must be called to re-enable the IRQ line later.
 *
 * The nucleus re-enables the IRQ line by default. Over some real-time
 * control layers which mask and acknowledge IRQs, this operation is
 * necessary to revalidate the interrupt channel so that more interrupts
 * can be notified.
 *
 * A count of interrupt receipts is tracked into the interrupt
 * descriptor, and reset to zero each time the interrupt object is
 * attached. Since this count could wrap around, it should be used as
 * an indication of interrupt activity only.
 *
 * @param intr The address of a interrupt object descriptor the
 * nucleus will use to store the object-specific data.  This
 * descriptor must always be valid while the object is active
 * therefore it must be allocated in permanent memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * interrupt object or NULL ("<unknown>" will be applied then).
 *
 * @param irq The hardware interrupt channel associated with the
 * interrupt object. This value is architecture-dependent. An
 * interrupt object must then be attached to the hardware interrupt
 * vector using the xnintr_attach() service for the associated IRQs
 * to be directed to this object.
 *
 * @param isr The address of a valid low-level interrupt service
 * routine if this parameter is non-zero. This handler will be called
 * each time the corresponding IRQ is delivered on behalf of an
 * interrupt context.  When called, the ISR is passed the descriptor
 * address of the interrupt object.
 *
 * @param iack The address of an optional interrupt acknowledge
 * routine, aimed at replacing the default one. Only very specific
 * situations actually require to override the default setting for
 * this parameter, like having to acknowledge non-standard PIC
 * hardware. @a iack should return a non-zero value to indicate that
 * the interrupt has been properly acknowledged. If @a iack is NULL,
 * the default routine will be used instead.
 *
 * @param flags A set of creation flags affecting the operation. The
 * valid flags are:
 *
 * - XN_ISR_SHARED enables IRQ-sharing with other interrupt objects.
 *
 * - XN_ISR_EDGE is an additional flag need to be set together with XN_ISR_SHARED
 * to enable IRQ-sharing of edge-triggered interrupts.
 *
 * @return No error condition being defined, 0 is always returned.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnintr_init(xnintr_t *intr,
		const char *name,
		unsigned irq, xnisr_t isr, xniack_t iack, xnflags_t flags)
{
	intr->irq = irq;
	intr->isr = isr;
	intr->iack = iack;
	intr->cookie = NULL;
	intr->name = name ? : "<unknown>";
	intr->flags = flags;
	intr->unhandled = 0;
	memset(&intr->stat, 0, sizeof(intr->stat));
#ifdef CONFIG_XENO_OPT_SHIRQ
	intr->next = NULL;
#endif

	return 0;
}

/*!
 * \fn int xnintr_destroy (xnintr_t *intr)
 * \brief Destroy an interrupt object.
 *
 * Destroys an interrupt object previously initialized by
 * xnintr_init(). The interrupt object is automatically detached by a
 * call to xnintr_detach(). No more IRQs will be dispatched by this
 * object after this service has returned.
 *
 * @param intr The descriptor address of the interrupt object to
 * destroy.
 *
 * @return 0 is returned on success. Otherwise, -EBUSY is returned if
 * an error occurred while detaching the interrupt (see
 * xnintr_detach()).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnintr_destroy(xnintr_t *intr)
{
	xnintr_detach(intr);
	return 0;
}

/*!
 * \fn int xnintr_attach (xnintr_t *intr, void *cookie);
 * \brief Attach an interrupt object.
 *
 * Attach an interrupt object previously initialized by
 * xnintr_init(). After this operation is completed, all IRQs received
 * from the corresponding interrupt channel are directed to the
 * object's ISR.
 *
 * @param intr The descriptor address of the interrupt object to
 * attach.
 *
 * @param cookie A user-defined opaque value which is stored into the
 * interrupt object descriptor for further retrieval by the ISR/ISR
 * handlers.
 *
 * @return 0 is returned on success. Otherwise, -EINVAL is returned if
 * a low-level error occurred while attaching the interrupt. -EBUSY is
 * specifically returned if the interrupt object was already attached.
 *
 * @note The caller <b>must not</b> hold nklock when invoking this service,
 * this would cause deadlocks.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 *
 * @note Attaching an interrupt resets the tracked number of receipts
 * to zero.
 */

int xnintr_attach(xnintr_t *intr, void *cookie)
{
	int err;
	spl_t s;

	trace_mark(xn_nucleus_irq_attach, "irq %u name %s",
		   intr->irq, intr->name);

	intr->cookie = cookie;
	memset(&intr->stat, 0, sizeof(intr->stat));

	xnlock_get_irqsave(&intrlock, s);

#ifdef CONFIG_SMP
	xnarch_set_irq_affinity(intr->irq, nkaffinity);
#endif /* CONFIG_SMP */
	err = xnintr_irq_attach(intr);

	if (!err)
		xnintr_stat_counter_inc();

	xnlock_put_irqrestore(&intrlock, s);

	return err;
}

/*!
 * \fn int xnintr_detach (xnintr_t *intr)
 * \brief Detach an interrupt object.
 *
 * Detach an interrupt object previously attached by
 * xnintr_attach(). After this operation is completed, no more IRQs
 * are directed to the object's ISR, but the interrupt object itself
 * remains valid. A detached interrupt object can be attached again by
 * a subsequent call to xnintr_attach().
 *
 * @param intr The descriptor address of the interrupt object to
 * detach.
 *
 * @return 0 is returned on success. Otherwise, -EINVAL is returned if
 * a low-level error occurred while detaching the interrupt. Detaching
 * a non-attached interrupt object leads to a null-effect and returns
 * 0.
 *
 * @note The caller <b>must not</b> hold nklock when invoking this service,
 * this would cause deadlocks.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnintr_detach(xnintr_t *intr)
{
	int err;
	spl_t s;

	trace_mark(xn_nucleus_irq_detach, "irq %u", intr->irq);

	xnlock_get_irqsave(&intrlock, s);

	err = xnintr_irq_detach(intr);

	if (!err)
		xnintr_stat_counter_dec();

	xnlock_put_irqrestore(&intrlock, s);

	return err;
}

/*!
 * \fn int xnintr_enable (xnintr_t *intr)
 * \brief Enable an interrupt object.
 *
 * Enables the hardware interrupt line associated with an interrupt
 * object. Over real-time control layers which mask and acknowledge
 * IRQs, this operation is necessary to revalidate the interrupt
 * channel so that more interrupts can be notified.

 * @param intr The descriptor address of the interrupt object to
 * enable.
 *
 * @return 0 is returned on success. Otherwise, -EINVAL is returned if
 * a low-level error occurred while enabling the interrupt.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnintr_enable(xnintr_t *intr)
{
	trace_mark(xn_nucleus_irq_enable, "irq %u", intr->irq);

	return xnarch_enable_irq(intr->irq);
}

/*!
 * \fn int xnintr_disable (xnintr_t *intr)
 * \brief Disable an interrupt object.
 *
 * Disables the hardware interrupt line associated with an interrupt
 * object. This operation invalidates further interrupt requests from
 * the given source until the IRQ line is re-enabled anew.
 *
 * @param intr The descriptor address of the interrupt object to
 * disable.
 *
 * @return 0 is returned on success. Otherwise, -EINVAL is returned if
 * a low-level error occurred while disabling the interrupt.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int xnintr_disable(xnintr_t *intr)
{
	trace_mark(xn_nucleus_irq_disable, "irq %u", intr->irq);

	return xnarch_disable_irq(intr->irq);
}

/*!
 * \fn xnarch_cpumask_t xnintr_affinity (xnintr_t *intr, xnarch_cpumask_t cpumask)
 * \brief Set interrupt's processor affinity.
 *
 * Causes the IRQ associated with the interrupt object @a intr to be
 * received only on processors which bits are set in @a cpumask.
 *
 * @param intr The descriptor address of the interrupt object which
 * affinity is to be changed.
 *
 * @param cpumask The new processor affinity of the interrupt object.
 *
 * @return the previous cpumask on success, or an empty mask on
 * failure.
 *
 * @note Depending on architectures, setting more than one bit in @a
 * cpumask could be meaningless.
 */

xnarch_cpumask_t xnintr_affinity(xnintr_t *intr, xnarch_cpumask_t cpumask)
{
	trace_mark(xn_nucleus_irq_affinity, "irq %u %lu",
		   intr->irq, *(unsigned long *)&cpumask);

	return xnarch_set_irq_affinity(intr->irq, cpumask);
}

#ifdef CONFIG_PROC_FS
int xnintr_irq_proc(unsigned int irq, char *str)
{
	xnintr_t *intr;
	char *p = str;
	spl_t s;

	if (rthal_virtual_irq_p(irq)) {
		p += sprintf(p, "         [virtual]");
		return p - str;
	} else if (irq == XNARCH_TIMER_IRQ) {
		p += sprintf(p, "         [timer]");
		return p - str;
#ifdef CONFIG_SMP
	} else if (irq == RTHAL_SERVICE_IPI0) {
		p += sprintf(p, "         [IPI]");
		return p - str;
	} else if (irq == RTHAL_CRITICAL_IPI) {
		p += sprintf(p, "         [critical sync]");
		return p - str;
#endif /* CONFIG_SMP */
	}

	xnlock_get_irqsave(&intrlock, s);

	intr = xnintr_shirq_first(irq);
	if (intr) {
		strcpy(p, "        "); p += 8;

		do {
			*p = ' '; p += 1;
			strcpy(p, intr->name); p += strlen(intr->name);

			intr = xnintr_shirq_next(intr);
		} while (intr);
	}

	xnlock_put_irqrestore(&intrlock, s);

	return p - str;
}
#endif /* CONFIG_PROC_FS */

#ifdef CONFIG_XENO_OPT_STATS
int xnintr_query(int irq, int *cpu, xnintr_t **prev, int revision, char *name,
		 unsigned long *hits, xnticks_t *exectime,
		 xnticks_t *account_period)
{
	xnintr_t *intr;
	xnticks_t last_switch;
	int head;
	int cpu_no = *cpu;
	int err = 0;
	spl_t s;

	head = snprintf(name, XNOBJECT_NAME_LEN, "IRQ%d: ", irq);
	name += head;

	xnlock_get_irqsave(&intrlock, s);

	if (revision != xnintr_list_rev) {
		err = -EAGAIN;
		goto unlock_and_exit;
	}

	if (*prev)
		intr = xnintr_shirq_next(*prev);
	else if (irq == XNARCH_TIMER_IRQ)
		intr = &nkclock;
	else
		intr = xnintr_shirq_first(irq);

	if (!intr) {
		err = -ENODEV;
		goto unlock_and_exit;
	}

	strncpy(name, intr->name, XNOBJECT_NAME_LEN-head);

	*hits = xnstat_counter_get(&intr->stat[cpu_no].hits);

	last_switch = xnpod_sched_slot(cpu_no)->last_account_switch;

	*exectime       = intr->stat[cpu_no].account.total;
	*account_period = last_switch - intr->stat[cpu_no].account.start;

	intr->stat[cpu_no].account.total  = 0;
	intr->stat[cpu_no].account.start = last_switch;

	if (++cpu_no == xnarch_num_online_cpus()) {
		cpu_no = 0;
		*prev  = intr;
	}
	*cpu = cpu_no;

     unlock_and_exit:
	xnlock_put_irqrestore(&intrlock, s);

	return err;
}
#endif /* CONFIG_XENO_OPT_STATS */

EXPORT_SYMBOL(xnintr_attach);
EXPORT_SYMBOL(xnintr_destroy);
EXPORT_SYMBOL(xnintr_detach);
EXPORT_SYMBOL(xnintr_disable);
EXPORT_SYMBOL(xnintr_enable);
EXPORT_SYMBOL(xnintr_affinity);
EXPORT_SYMBOL(xnintr_init);

/*@}*/
