/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <posix/internal.h>
#include <posix/thread.h>
#include <posix/intr.h>

/**
 * @ingroup posix
 * @defgroup posix_intr Interruptions management services.
 *
 * Interruptions management services.
 *
 * The services described here allow applications written using the POSIX skin
 * to handle interrupts, either in kernel-space or in user-space.
 *
 * Note however, that it is recommended to use the standardized driver API of
 * the RTDM skin (see @ref rtdm).
 *
 *@{*/

/**
 * Create and attach an interrupt object.
 *
 * This service creates and attaches an interrupt object.
 *
 * @par In kernel-space:
 *
 * This service installs @a isr as the handler for the interrupt @a irq. If @a
 * iack is not null it is a custom interrupt acknowledge routine.
 *
 * When called upon reception of an interrupt, the @a isr function is passed the
 * address of an underlying @b xnintr_t object, and should use the macro @a
 * PTHREAD_IDESC() to get the @b pthread_intr_t object. The meaning of the @a
 * isr and @a iack function and what they should return is explained in
 * xnintr_init() documentation.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param intrp address where the created interrupt object identifier will be
 * stored on success;
 *
 * @param irq IRQ channel;
 *
 * @param isr interrupt handling routine;
 *
 * @param iack if not @a NULL, optional interrupt acknowledge routine.
 *
 *
 * @par In user-space:
 *
 * The prototype of this service is :
 *
 * <b>int pthread_intr_attach_np (pthread_intr_t *intrp,
 *                                unsigned irq,
 *                                int mode);</b>
 *
 * This service causes the installation of a default interrupt handler which
 * unblocks any Xenomai user-space interrupt server thread blocked in a call to
 * pthread_intr_wait_np(), and returns a value depending on the @a mode
 * parameter.
 *
 * @par Parameters:
 * @a intrp and @a irq have the same meaning as in kernel-space;
 * @a mode is a bitwise OR of the following values:
 * - PTHREAD_IPROPAGATE, meaning that the interrupt should be propagated to
 *   lower priority domains;
 * - PTHREAD_INOAUTOENA, meaning that the interrupt should not be automatically
 *   re-enabled.
 *
 * This service is intended to be used in conjunction with the
 * pthread_intr_wait_np() service.
 *
 * The return values are identical in kernel-space and user-space.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - ENOSYS, kernel-space Xenomai POSIX skin was built without support for
 *   interrupts, use RTDM or enable CONFIG_XENO_OPT_POSIX_INTR in kernel
 *   configuration;
 * - ENOMEM, insufficient memory exists in the system heap to create the
 *   interrupt object, increase CONFIG_XENO_OPT_SYS_HEAPSZ;
 * - EINVAL, a low-level error occured while attaching the interrupt;
 * - EBUSY, an interrupt handler was already registered for the irq line @a irq.
 */
int pthread_intr_attach_np(pthread_intr_t * intrp,
			   unsigned irq,
			   int (*isr) (xnintr_t *), int (*iack) (unsigned irq))
{
	pthread_intr_t intr;
	int err;
	spl_t s;

	intr = (pthread_intr_t) xnmalloc(sizeof(*intr));
	if (!intr) {
		err = ENOMEM;
		goto error;
	}

	xnintr_init(&intr->intr_base, NULL, irq, isr, iack, 0);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	xnsynch_init(&intr->synch_base, XNSYNCH_PRIO);
	intr->pending = 0;
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	intr->magic = PSE51_INTR_MAGIC;
	inith(&intr->link);
	intr->owningq = pse51_kqueues(0);
	xnlock_get_irqsave(&nklock, s);
	appendq(&pse51_kqueues(0)->intrq, &intr->link);
	xnlock_put_irqrestore(&nklock, s);

	err = -xnintr_attach(&intr->intr_base, intr);

	if (!err) {
		*intrp = intr;
		return 0;
	}

	pthread_intr_detach_np(intr);
      error:
	thread_set_errno(err);
	return -1;
}

static int pse51_intr_detach_inner(pthread_intr_t intr, pse51_kqueues_t *q, int force)
{
	int rc = XNSYNCH_DONE;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(intr, PSE51_INTR_MAGIC, struct pse51_interrupt)) {
		xnlock_put_irqrestore(&nklock, s);
		thread_set_errno(EINVAL);
		return -1;
	}
	if (!force && intr->owningq != pse51_kqueues(0)) {
		xnlock_put_irqrestore(&nklock, s);
		thread_set_errno(EPERM);
		return -1;
	}
#ifdef CONFIG_XENO_OPT_PERVASIVE
	rc = xnsynch_destroy(&intr->synch_base);
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	pse51_mark_deleted(intr);

	removeq(&q->intrq, &intr->link);

	xnlock_put_irqrestore(&nklock, s);

	xnintr_detach(&intr->intr_base);
	xnintr_destroy(&intr->intr_base);

	if (rc == XNSYNCH_RESCHED)
		xnpod_schedule();

	xnfree(intr);

	return 0;
}

/**
 * Destroy an interrupt object.
 *
 * This service destroys the interrupt object @a intr. The memory allocated for
 * this object is returned to the system heap, so further references using the
 * same object identifier are not guaranteed to fail.
 *
 * If a user-space interrupt server is blocked in a call to
 * pthread_intr_wait_np(), it is unblocked and the blocking service returns
 * with an error of EIDRM.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param intr identifier of the interrupt object to be destroyed.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - ENOSYS, kernel-space Xenomai POSIX skin was built without support for
 *   interrupts, use RTDM or enable CONFIG_XENO_OPT_POSIX_INTR in kernel
 *   configuration;
 * - EINVAL, the interrupt object @a intr is invalid;
 * - EPERM, the interrupt @a intr does not belong to the current process.
 */
int pthread_intr_detach_np(pthread_intr_t intr)
{
	return pse51_intr_detach_inner(intr, pse51_kqueues(0), 0);
}

/**
 * Control the state of an interrupt channel.
 *
 * This service allow to enable or disable an interrupt channel.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param intr identifier of the interrupt to be enabled or disabled.
 *
 * @param cmd one of PTHREAD_IENABLE or PTHREAD_IDISABLE.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - ENOSYS, kernel-space Xenomai POSIX skin was built without support for
 *   interrupts, use RTDM or enable CONFIG_XENO_OPT_POSIX_INTR in kernel
 *   configuration;
 * - EINVAL, the identifier @a intr or @a cmd is invalid;
 * - EPERM, the interrupt @a intr does not belong to the current process.
 */
int pthread_intr_control_np(pthread_intr_t intr, int cmd)
{
	int err;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	if (!pse51_obj_active(intr, PSE51_INTR_MAGIC, struct pse51_interrupt)) {
		xnlock_put_irqrestore(&nklock, s);
		thread_set_errno(EINVAL);
		return -1;
	}

	if (intr->owningq != pse51_kqueues(0)) {
		xnlock_put_irqrestore(&nklock, s);
		thread_set_errno(EPERM);
		return -1;
	}

	switch (cmd) {
	case PTHREAD_IENABLE:

		err = xnintr_enable(&intr->intr_base);
		break;

	case PTHREAD_IDISABLE:

		err = xnintr_disable(&intr->intr_base);
		break;

	default:

		err = EINVAL;
	}

	xnlock_put_irqrestore(&nklock, s);

	if (!err)
		return 0;

	thread_set_errno(err);
	return -1;
}

void pse51_intrq_cleanup(pse51_kqueues_t *q)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	while ((holder = getheadq(&q->intrq)) != NULL) {
		pse51_intr_detach_inner(link2intr(holder), pse51_kqueues(0), 1);
		xnlock_put_irqrestore(&nklock, s);
#if XENO_DEBUG(POSIX)
		xnprintf("Posix interruption handler %p was not destroyed, "
			 "destroying now.\n", link2intr(holder));
#endif /* XENO_DEBUG(POSIX) */
		xnlock_get_irqsave(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);
}

void pse51_intr_pkg_init(void)
{
	initq(&pse51_global_kqueues.intrq);
}

void pse51_intr_pkg_cleanup(void)
{
	pse51_intrq_cleanup(&pse51_global_kqueues);
}

#ifdef DOXYGEN_CPP
/**
 * Wait for the next interruption.
 *
 * This service is used by user-space interrupt server threads, to
 * wait, if no interrupt is pending, for the next interrupt.
 *
 * This service is a cancelation point. If a thread is canceled while blocked in
 * a call to this service, no interruption notification is lost.
 *
 * This service is a non-portable extension of the POSIX interface.
 *
 * @param intr interrupt object identifier;
 *
 * @param to if not @a NULL, timeout, expressed as a time interval.
 *
 * @return the number of interrupt received on success;
 * @return -1 with @a errno set if:
 * - ENOSYS, kernel-space Xenomai POSIX skin was built without support for
 *   interrupts, use RTDM or enable CONFIG_XENO_OPT_POSIX_INTR in kernel
 *   configuration;
 * - EIDRM, the interrupt object was deleted;
 * - EPERM, the interrupt @a intr does not belong to the current process;
 * - ETIMEDOUT, the timeout specified by @a to expired;
 * - EINTR, pthread_intr_wait_np() was interrupted by a signal.
 */
int pthread_intr_wait_np(pthread_intr_t intr, const struct timespec *to);
#endif /* Doxygen */

/*@}*/

EXPORT_SYMBOL(pthread_intr_attach_np);
EXPORT_SYMBOL(pthread_intr_detach_np);
EXPORT_SYMBOL(pthread_intr_control_np);
