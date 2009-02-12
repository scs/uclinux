/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org> 
 *
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
 *
 * \ingroup interrupt
 */

/*!
 * \ingroup native
 * \defgroup interrupt Interrupt management services.
 *
 *@{*/

/** @example user_irq.c */

#include <nucleus/pod.h>
#include <nucleus/registry.h>
#include <nucleus/heap.h>
#include <native/task.h>
#include <native/intr.h>

int __native_intr_pkg_init(void)
{
	return 0;
}

void __native_intr_pkg_cleanup(void)
{
	__native_intr_flush_rq(&__native_global_rholder.intrq);
}

static unsigned long __intr_get_hits(RT_INTR *intr)
{
	unsigned long sum = 0;
	int cpu;

	for (cpu = 0; cpu < XNARCH_NR_CPUS; cpu++)
		sum += xnstat_counter_get(&intr->intr_base.stat[cpu].hits);

	return sum;
}

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static int __intr_read_proc(char *page,
			    char **start,
			    off_t off, int count, int *eof, void *data)
{
	RT_INTR *intr = (RT_INTR *)data;
	char *p = page;
	int len;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	{
		xnpholder_t *holder;

		p += sprintf(p, "hits=%lu, pending=%u, mode=0x%x\n",
			     __intr_get_hits(intr), intr->pending,
			     intr->mode);

		/* Pended interrupt -- dump waiters. */

		holder = getheadpq(xnsynch_wait_queue(&intr->synch_base));

		while (holder) {
			xnthread_t *sleeper = link2thread(holder, plink);
			p += sprintf(p, "+%s\n", xnthread_name(sleeper));
			holder =
			    nextpq(xnsynch_wait_queue(&intr->synch_base),
				   holder);
		}
	}
#else /* !CONFIG_XENO_OPT_PERVASIVE */
	p += sprintf(p, "hits=%lu\n", __intr_get_hits(intr));
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	xnlock_put_irqrestore(&nklock, s);

	len = (p - page) - off;
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;

	return len;
}

extern xnptree_t __native_ptree;

static xnpnode_t __intr_pnode = {

	.dir = NULL,
	.type = "interrupts",
	.entries = 0,
	.read_proc = &__intr_read_proc,
	.write_proc = NULL,
	.root = &__native_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __intr_pnode = {

	.type = "interrupts"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

/*! 
 * \fn int rt_intr_create (RT_INTR *intr,const char *name,unsigned irq,rt_isr_t isr,rt_iack_t iack,int mode)
 * \brief Create an interrupt object from kernel space.
 *
 * Initializes and associates an interrupt object with an IRQ line. In
 * kernel space, interrupts are immediately notified to a user-defined
 * handler or ISR (interrupt service routine).
 *
 * When an interrupt occurs on the given @a irq line, the ISR is fired
 * in order to deal with the hardware event. The interrupt service
 * code may call any non-suspensive Xenomai service.
 *
 * Upon receipt of an IRQ, the ISR is immediately called on behalf of
 * the interrupted stack context, the rescheduling procedure is
 * locked, and the interrupt source is masked at hardware level. The
 * status value returned by the ISR is then checked for the following
 * values:
 *
 * - RT_INTR_HANDLED indicates that the interrupt request has been fulfilled
 * by the ISR.
 *
 * - RT_INTR_NONE indicates the opposite to RT_INTR_HANDLED. The ISR must always
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
 * - RT_INTR_PROPAGATE tells Xenomai to require the real-time control
 * layer to forward the IRQ. For instance, this would cause the Adeos
 * control layer to propagate the interrupt down the interrupt
 * pipeline to other Adeos domains, such as Linux. This is the regular
 * way to share interrupts between Xenomai and the Linux kernel.
 *
 * - RT_INTR_NOENABLE asks Xenomai not to re-enable the IRQ line upon return
 * of the interrupt service routine.
 *
 * A count of interrupt receipts is tracked into the interrupt
 * descriptor, and reset to zero each time the interrupt object is
 * attached. Since this count could wrap around, it should be used as
 * an indication of interrupt activity only.
 *
 * @param intr The address of a interrupt object descriptor Xenomai will
 * use to store the object-specific data.  This descriptor must always
 * be valid while the object is active therefore it must be allocated
 * in permanent memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * interrupt object. When non-NULL and non-empty, this string is copied
 * to a safe place into the descriptor, and passed to the registry package
 * if enabled for indexing the created interrupt objects.
 *
 * @param irq The hardware interrupt channel associated with the
 * interrupt object. This value is architecture-dependent.
 *
 * @param isr The address of a valid interrupt service routine in
 * kernel space. This handler will be called each time the
 * corresponding IRQ is delivered on behalf of an interrupt context.
 * A pointer to an internal information is passed to the routine which
 * can use it to retrieve the descriptor address of the associated
 * interrupt object through the I_DESC() macro.
 *
 * @param iack The address of an optional interrupt acknowledge
 * routine, aimed at replacing the default one. Only very specific
 * situations actually require to override the default setting for
 * this parameter, like having to acknowledge non-standard PIC
 * hardware. @a iack should return a non-zero value to indicate that
 * the interrupt has been properly acknowledged. If @a iack is NULL,
 * the default routine will be used instead.
 *
 * @param mode The interrupt object creation mode. The following flags can be
 * OR'ed into this bitmask, each of them affecting the new interrupt object:
 *
 * - I_SHARED enables IRQ-sharing with other interrupt objects.
 *
 * - I_EDGE is an additional flag need to be set together with I_SHARED
 * to enable IRQ-sharing of edge-triggered interrupts.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * interrupt object.
 *
 * - -EBUSY is returned if the interrupt line is already in use by
 * another interrupt object. Only a single interrupt object can be
 * associated to any given interrupt line using rt_intr_create() at
 * any time.
 *
 * - -EEXIST is returned if @a irq is already associated to an
 * existing interrupt object.
 *
 * - -EPERM is returned if this service was called from an
 * asynchronous context.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task (note that in user-space the interface is different,
 *   see rt_intr_create())
 *
 * Rescheduling: possible.
 *
 * @note The interrupt source associated to the interrupt descriptor
 * remains masked upon creation. rt_intr_enable() should be called for
 * the new interrupt object to unmask it.
 */

int rt_intr_create(RT_INTR *intr,
		   const char *name,
		   unsigned irq, rt_isr_t isr, rt_iack_t iack, int mode)
{
	int err;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	if (name)
		xnobject_copy_name(intr->name, name);
	else
		/* Kernel-side "anonymous" objects (name == NULL) get unique names.
		 * Nevertheless, they will not be exported via the registry. */
		xnobject_create_name(intr->name, sizeof(intr->name), isr);

	xnintr_init(&intr->intr_base, intr->name, irq, isr, iack, mode);
#ifdef CONFIG_XENO_OPT_PERVASIVE
	xnsynch_init(&intr->synch_base, XNSYNCH_PRIO);
	intr->pending = 0;
	intr->cpid = 0;
	intr->mode = 0;
#endif /* CONFIG_XENO_OPT_PERVASIVE */
	intr->magic = XENO_INTR_MAGIC;
	intr->handle = 0;	/* i.e. (still) unregistered interrupt. */
	inith(&intr->rlink);
	intr->rqueue = &xeno_get_rholder()->intrq;
	xnlock_get_irqsave(&nklock, s);
	appendq(intr->rqueue, &intr->rlink);
	xnlock_put_irqrestore(&nklock, s);

	err = xnintr_attach(&intr->intr_base, intr);

#ifdef CONFIG_XENO_OPT_REGISTRY
	/* <!> Since xnregister_enter() may reschedule, only register
	   complete objects, so that the registry cannot return handles to
	   half-baked objects... */
	if (!err && name) {
		xnpnode_t *pnode = &__intr_pnode;

		if (!*name) {
			/* Since this is an anonymous object (empty name on entry)
			 * from user-space, it gets registered under an unique
			 * internal name but is not exported through /proc. */
			xnobject_create_name(intr->name, sizeof(intr->name),
				(void *)intr);
			pnode = NULL;
		}

		err = xnregistry_enter(intr->name, intr, &intr->handle, pnode);
	}	
	
#endif /* CONFIG_XENO_OPT_REGISTRY */

	if (err)
		rt_intr_delete(intr);

	return err;
}

/**
 * @fn int rt_intr_delete(RT_INTR *intr)
 * @brief Delete an interrupt object.
 *
 * Destroys an interrupt object.  An interrupt exists in the system
 * since rt_intr_create() has been called to create it, so this
 * service must be called in order to destroy it afterwards.
 *
 * Any user-space task which might be currently pending on the
 * interrupt object through the rt_intr_wait() service will be awaken
 * as a result of the deletion, and return with the -EIDRM status.
 *
 * @param intr The descriptor address of the affected interrupt object.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a intr is not a interrupt object
 * descriptor.
 *
 * - -EIDRM is returned if @a intr is a deleted interrupt object
 * descriptor.
 *
 * - -EPERM is returned if this service was called from an
 * asynchronous context.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: possible.
 */

int rt_intr_delete(RT_INTR *intr)
{
	int err = 0, rc = XNSYNCH_DONE;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	intr = xeno_h2obj_validate(intr, XENO_INTR_MAGIC, RT_INTR);

	if (!intr) {
		err = xeno_handle_error(intr, XENO_INTR_MAGIC, RT_INTR);
		xnlock_put_irqrestore(&nklock, s);
		return err;
	}

	removeq(intr->rqueue, &intr->rlink);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	rc = xnsynch_destroy(&intr->synch_base);
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (intr->handle)
		xnregistry_remove(intr->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	xeno_mark_deleted(intr);

	xnlock_put_irqrestore(&nklock, s);

	err = xnintr_detach(&intr->intr_base);
	xnintr_destroy(&intr->intr_base);

	if (rc == XNSYNCH_RESCHED)
		/* Some task has been woken up as a result of the deletion:
		   reschedule now. */
		xnpod_schedule();

	return err;
}

/*! 
 * \fn int rt_intr_enable (RT_INTR *intr)
 * \brief Enable an interrupt object.
 *
 * Enables the hardware interrupt line associated with an interrupt
 * object. Over Adeos-based systems which mask and acknowledge IRQs
 * upon receipt, this operation is necessary to revalidate the
 * interrupt channel so that more interrupts from the same source can
 * be notified.

 * @param intr The descriptor address of the interrupt object to
 * enable.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a intr is not a interrupt object
 * descriptor.
 *
 * - -EIDRM is returned if @a intr is a deleted interrupt object
 * descriptor.
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

int rt_intr_enable(RT_INTR *intr)
{
	int err;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	intr = xeno_h2obj_validate(intr, XENO_INTR_MAGIC, RT_INTR);

	if (!intr) {
		err = xeno_handle_error(intr, XENO_INTR_MAGIC, RT_INTR);
		goto unlock_and_exit;
	}

	err = xnintr_enable(&intr->intr_base);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*! 
 * \fn int rt_intr_disable (RT_INTR *intr)
 * \brief Disable an interrupt object.
 *
 * Disables the hardware interrupt line associated with an interrupt
 * object. This operation invalidates further interrupt requests from
 * the given source until the IRQ line is re-enabled anew through
 * rt_intr_enable().
 *
 * @param intr The descriptor address of the interrupt object to
 * enable.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a intr is not a interrupt object
 * descriptor.
 *
 * - -EIDRM is returned if @a intr is a deleted interrupt object
 * descriptor.
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

int rt_intr_disable(RT_INTR *intr)
{
	int err;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	intr = xeno_h2obj_validate(intr, XENO_INTR_MAGIC, RT_INTR);

	if (!intr) {
		err = xeno_handle_error(intr, XENO_INTR_MAGIC, RT_INTR);
		goto unlock_and_exit;
	}

	err = xnintr_disable(&intr->intr_base);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * @fn int rt_intr_inquire(RT_INTR *intr, RT_INTR_INFO *info)
 * @brief Inquire about an interrupt object.
 *
 * Return various information about the status of a given interrupt
 * object.
 *
 * @param intr The descriptor address of the inquired interrupt
 * object.
 *
 * @param info The address of a structure the interrupt object
 * information will be written to.

 * @return 0 is returned and status information is written to the
 * structure pointed at by @a info upon success. Otherwise:
 *
 * - -EINVAL is returned if @a intr is not a interrupt object
 * descriptor.
 *
 * - -EIDRM is returned if @a intr is a deleted interrupt object
 * descriptor.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 */

int rt_intr_inquire(RT_INTR *intr, RT_INTR_INFO *info)
{
	int err = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	intr = xeno_h2obj_validate(intr, XENO_INTR_MAGIC, RT_INTR);

	if (!intr) {
		err = xeno_handle_error(intr, XENO_INTR_MAGIC, RT_INTR);
		goto unlock_and_exit;
	}

	strcpy(info->name, intr->name);
	info->hits = __intr_get_hits(intr);
	info->irq = intr->intr_base.irq;

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/*! 
 * \fn int rt_intr_create (RT_INTR *intr,const char *name,unsigned irq,int mode)
 * \brief Create an interrupt object from user-space.
 *
 * Initializes and associates an interrupt object with an IRQ line
 * from a user-space application. In this mode, the basic principle is
 * to define some interrupt server task which routinely waits for the
 * next incoming IRQ event through the rt_intr_wait() syscall.
 *
 * When an interrupt occurs on the given @a irq line, any task pending
 * on the interrupt object through rt_intr_wait() is imediately awaken
 * in order to deal with the hardware event. The interrupt service
 * code may then call any Xenomai service available from user-space.
 *
 * @param intr The address of a interrupt object descriptor Xenomai will
 * use to store the object-specific data.  This descriptor must always
 * be valid while the object is active therefore it must be allocated
 * in permanent memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * interrupt object. When non-NULL and non-empty, this string is copied
 * to a safe place into the descriptor, and passed to the registry package
 * if enabled for indexing the created interrupt objects.
 * 
 * @param irq The hardware interrupt channel associated with the
 * interrupt object. This value is architecture-dependent.
 *
 * @param mode The interrupt object creation mode. The following flags
 * can be OR'ed into this bitmask:
 *
 * - I_NOAUTOENA asks Xenomai not to re-enable the IRQ line before awakening
 * the interrupt server task. This flag is functionally equivalent as
 * always returning RT_INTR_NOENABLE from a kernel space interrupt
 * handler.
 *
 * - I_PROPAGATE asks Xenomai to propagate the IRQ down the pipeline; in
 * other words, the interrupt occurrence is chained to Linux after it
 * has been processed by the Xenomai task. This flag is functionally
 * equivalent as always returning RT_INTR_PROPAGATE from a kernel space
 * interrupt handler.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * interrupt object.
 *
 * - -EBUSY is returned if the interrupt line is already in use by
 * another interrupt object. Only a single interrupt object can be
 * associated to any given interrupt line using rt_intr_create() at
 * any time, regardless of the caller's execution space (kernel or
 * user).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - User-space task
 *
 * Rescheduling: possible.
 *
 * @note The interrupt source associated to the interrupt descriptor
 * remains masked upon creation. rt_intr_enable() should be called for
 * the new interrupt object to unmask it.
 */

/**
 * @fn int rt_intr_wait(RT_INTR *intr, RTIME timeout)
 * @brief Wait for the next interrupt.
 *
 * This user-space only call allows the current task to suspend
 * execution until the associated interrupt event triggers. The
 * priority of the current task is raised above all other Xenomai tasks -
 * except those also undergoing an interrupt or alarm wait (see
 * rt_alarm_wait()) - so that it would preempt any of them under
 * normal circumstances (i.e. no scheduler lock).
 *
 * Interrupt receipts are logged if they cannot be delivered
 * immediately to some interrupt server task, so that a call to
 * rt_intr_wait() might return immediately if an IRQ is already
 * pending on entry of the service.
 *
 * @param intr The descriptor address of the awaited interrupt.
 *
 * @param timeout The number of clock ticks to wait for an interrupt
 * to occur (see note). Passing TM_INFINITE causes the caller to block
 * indefinitely until an interrupt triggers. Passing TM_NONBLOCK is
 * invalid.
 *
 * @return A positive value is returned upon success, representing the
 * number of pending interrupts to process. Otherwise:
 *
 * - -ETIMEDOUT is returned if no interrupt occurred within the
 * specified amount of time.
 *
 * - -EINVAL is returned if @a intr is not an interrupt object
 * descriptor, or @a timeout is equal to TM_NONBLOCK.
 *
 * - -EIDRM is returned if @a intr is a deleted interrupt object
 * descriptor, including if the deletion occurred while the caller was
 * waiting for its next interrupt.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * current task before the next interrupt occurrence.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - User-space task
 *
 * Rescheduling: always, unless an interrupt is already pending on
 * entry.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

/**
 * @fn int rt_intr_bind(RT_INTR *intr,const char *name,RTIME timeout)
 * @brief Bind to an interrupt object.
 *
 * This user-space only service retrieves the uniform descriptor of a
 * given Xenomai interrupt object identified by its IRQ number. If the
 * object does not exist on entry, this service blocks the caller
 * until an interrupt object of the given number is created. An
 * interrupt is registered whenever a kernel-space task invokes the
 * rt_intr_create() service successfully for the given IRQ line.
 *
 * @param intr The address of an interrupt object descriptor retrieved
 * by the operation. Contents of this memory is undefined upon
 * failure.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * interrupt object to search for.
 *
 * @param timeout The number of clock ticks to wait for the
 * registration to occur (see note). Passing TM_INFINITE causes the
 * caller to block indefinitely until the object is
 * registered. Passing TM_NONBLOCK causes the service to return
 * immediately without waiting if the object is not registered on
 * entry.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EFAULT is returned if @a intr is referencing invalid memory.
 *
 * - -EINVAL is returned if @a irq is invalid.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before the retrieval has completed.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to TM_NONBLOCK
 * and the searched object is not registered on entry.
 *
 * - -ETIMEDOUT is returned if the object cannot be retrieved within
 * the specified amount of time.
 *
 * - -EPERM is returned if this service should block, but was called
 * from a context which cannot sleep (e.g. interrupt, non-realtime or
 * scheduler locked).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - User-space task (switches to primary mode)
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

/**
 * @fn int rt_intr_unbind(RT_INTR *intr)
 *
 * @brief Unbind from an interrupt object.
 *
 * This user-space only service unbinds the calling task from the
 * interrupt object previously retrieved by a call to rt_intr_bind().
 *
 * @param intr The address of a interrupt object descriptor to unbind
 * from.
 *
 * @return 0 is always returned.
 *
 * This service can be called from:
 *
 * - User-space task.
 *
 * Rescheduling: never.
 */

/*@}*/

EXPORT_SYMBOL(rt_intr_create);
EXPORT_SYMBOL(rt_intr_delete);
EXPORT_SYMBOL(rt_intr_enable);
EXPORT_SYMBOL(rt_intr_disable);
EXPORT_SYMBOL(rt_intr_inquire);
