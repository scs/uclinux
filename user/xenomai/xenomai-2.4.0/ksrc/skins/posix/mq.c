/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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
 */

/**
 * @ingroup posix
 * @defgroup posix_mq Message queues services.
 *
 * Message queues services.
 *
 * A message queue allow exchanging data between real-time threads. For a POSIX
 * message queue, maximum message length and maximum number of messages are
 * fixed when it is created with mq_open().
 *
 *@{*/

#include <stdarg.h>

#include <nucleus/queue.h>

#include <posix/registry.h>
#include <posix/internal.h>	/* Magics, time conversion */
#include <posix/thread.h>	/* errno. */
#include <posix/sig.h>		/* pse51_siginfo_t. */

#include "mq.h"

/* Temporary definitions. */
struct pse51_mq {
	pse51_node_t nodebase;

#define node2mq(naddr) \
    ((pse51_mq_t *) (((char *)naddr) - offsetof(pse51_mq_t, nodebase)))

	xnpqueue_t queued;
	xnsynch_t receivers;
	xnsynch_t senders;
	size_t memsize;
	char *mem;
	xnqueue_t avail;

	/* mq_notify */
	pse51_siginfo_t si;
	pthread_t target;

	struct mq_attr attr;

	xnholder_t link;	/* link in mqq */

#define link2mq(laddr) \
    ((pse51_mq_t *) (((char *)laddr) - offsetof(pse51_mq_t, link)))
};

typedef struct pse51_mq pse51_mq_t;

typedef struct pse51_msg {
	xnpholder_t link;
	size_t len;

#define any2msg(addr, member)							\
    ((pse51_msg_t *)(((char *)addr) - offsetof(pse51_msg_t, member)))

	char data[0];
} pse51_msg_t;

static xnqueue_t pse51_mqq;

static struct mq_attr default_attr = {
      mq_maxmsg:128,
      mq_msgsize:128,
};

static pse51_msg_t *pse51_mq_msg_alloc(pse51_mq_t * mq)
{
	xnpholder_t *holder = (xnpholder_t *)getq(&mq->avail);

	if (!holder)
		return NULL;

	initph(holder);
	return any2msg(holder, link);
}

static void pse51_mq_msg_free(pse51_mq_t * mq, pse51_msg_t * msg)
{
	xnholder_t *holder = (xnholder_t *)(&msg->link);
	inith(holder);
	prependq(&mq->avail, holder);	/* For earliest re-use of the block. */
}

static int pse51_mq_init(pse51_mq_t * mq, const struct mq_attr *attr)
{
	unsigned i, msgsize, memsize;
	char *mem;

	if (xnpod_asynch_p() || !xnpod_root_p())
		return EPERM;

	if (!attr)
		attr = &default_attr;
	else if (attr->mq_maxmsg <= 0 || attr->mq_msgsize <= 0)
		return EINVAL;

	msgsize = attr->mq_msgsize + sizeof(pse51_msg_t);

	/* Align msgsize on natural boundary. */
	if ((msgsize % sizeof(unsigned long)))
		msgsize +=
		    sizeof(unsigned long) - (msgsize % sizeof(unsigned long));

	memsize = msgsize * attr->mq_maxmsg;
	memsize = PAGE_ALIGN(memsize);

	mem = (char *)xnarch_alloc_host_mem(memsize);

	if (!mem)
		return ENOSPC;

	mq->memsize = memsize;
	initpq(&mq->queued);
	xnsynch_init(&mq->receivers, XNSYNCH_PRIO | XNSYNCH_NOPIP);
	xnsynch_init(&mq->senders, XNSYNCH_PRIO | XNSYNCH_NOPIP);
	mq->mem = mem;

	/* Fill the pool. */
	initq(&mq->avail);
	for (i = 0; i < attr->mq_maxmsg; i++) {
		pse51_msg_t *msg = (pse51_msg_t *) (mem + i * msgsize);
		pse51_mq_msg_free(mq, msg);
	}

	mq->attr = *attr;
	mq->target = NULL;

	return 0;
}

static void pse51_mq_destroy(pse51_mq_t * mq)
{
	int need_resched;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	need_resched = (xnsynch_destroy(&mq->receivers) == XNSYNCH_RESCHED);
	need_resched =
	    (xnsynch_destroy(&mq->senders) == XNSYNCH_RESCHED) || need_resched;
	removeq(&pse51_mqq, &mq->link);
	xnlock_put_irqrestore(&nklock, s);
	xnarch_free_host_mem(mq->mem, mq->memsize);

	if (need_resched)
		xnpod_schedule();
}

/**
 * Open a message queue.
 *
 * This service establishes a connection between the message queue named @a name
 * and the calling context (kernel-space as a whole, or user-space process).
 *
 * One of the following values should be set in @a oflags:
 * - O_RDONLY, meaning that the returned queue descriptor may only be used for
 *   receiving messages;
 * - O_WRONLY, meaning that the returned queue descriptor may only be used for
 *   sending messages;
 * - O_RDWR, meaning that the returned queue descriptor may be used for both
 *   sending and receiving messages.
 *
 * If no message queue named @a name exists, and @a oflags has the @a O_CREAT
 * bit set, the message queue is created by this function, taking two more
 * arguments:
 * - a @a mode argument, of type @b mode_t, currently ignored;
 * - an @a attr argument, pointer to an @b mq_attr structure, specifying the
 *   attributes of the new message queue.
 *
 * If @a oflags has the two bits @a O_CREAT and @a O_EXCL set and the message
 * queue alread exists, this service fails.
 *
 * If the O_NONBLOCK bit is set in @a oflags, the mq_send(), mq_receive(),
 * mq_timedsend() and mq_timedreceive() services return @a -1 with @a errno set
 * to EAGAIN instead of blocking their caller.
 *
 * The following arguments of the @b mq_attr structure at the address @a attr
 * are used when creating a message queue:
 * - @a mq_maxmsg is the maximum number of messages in the queue (128 by
 *   default);
 * - @a mq_msgsize is the maximum size of each message (128 by default).
 *
 * @a name may be any arbitrary string, in which slashes have no particular
 * meaning. However, for portability, using a name which starts with a slash and
 * contains no other slash is recommended.
 *
 * @param name name of the message queue to open;
 *
 * @param oflags flags.
 *
 * @return a message queue descriptor on success;
 * @return -1 with @a errno set if:
 * - ENAMETOOLONG, the length of the @a name argument exceeds 64 characters;
 * - EEXIST, the bits @a O_CREAT and @a O_EXCL were set in @a oflags and the
 *   message queue already exists;
 * - ENOENT, the bit @a O_CREAT is not set in @a oflags and the message queue
 *   does not exist;
 * - ENOSPC, allocation of system memory failed, or insufficient memory exists
 *   in the system heap to create the queue, try increasing
 *   CONFIG_XENO_OPT_SYS_HEAPSZ;
 * - EPERM, attempting to create a message queue from an invalid context;
 * - EINVAL, the @a attr argument is invalid;
 * - EMFILE, too many descriptors are currently open.
 *
 * @par Valid contexts:
 * When creating a message queue, only the following contexts are valid:
 * - kernel module initialization or cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_open.html">
 * Specification.</a>
 * 
 */
mqd_t mq_open(const char *name, int oflags, ...)
{
	struct mq_attr *attr;
	pse51_node_t *node;
	pse51_desc_t *desc;
	pse51_mq_t *mq;
	mode_t mode;
	va_list ap;
	spl_t s;
	int err;

	xnlock_get_irqsave(&nklock, s);
	err = pse51_node_get(&node, name, PSE51_MQ_MAGIC, oflags);
	xnlock_put_irqrestore(&nklock, s);
	if (err)
		goto error;

	if (node) {
		mq = node2mq(node);
		goto got_mq;
	}

	/* Here, we know that we must create a message queue. */
	mq = (pse51_mq_t *) xnmalloc(sizeof(*mq));
	if (!mq) {
		err = ENOSPC;
		goto error;
	}

	va_start(ap, oflags);
	mode = va_arg(ap, int);	/* unused */
	attr = va_arg(ap, struct mq_attr *);
	va_end(ap);

	err = pse51_mq_init(mq, attr);
	if (err)
		goto err_free_mq;

	inith(&mq->link);

	xnlock_get_irqsave(&nklock, s);

	appendq(&pse51_mqq, &mq->link);

	err = pse51_node_add(&mq->nodebase, name, PSE51_MQ_MAGIC);
	if (err && err != EEXIST)
		goto err_put_mq;

	if (err == EEXIST) {
		err = pse51_node_get(&node, name, PSE51_MQ_MAGIC, oflags);
		if (err)
			goto err_put_mq;

		/* The same mq was created in the meantime, rollback. */
		xnlock_put_irqrestore(&nklock, s);
		pse51_mq_destroy(mq);
		xnfree(mq);
		mq = node2mq(node);
		goto got_mq;
	}

	xnlock_put_irqrestore(&nklock, s);

	/* Whether found or created, here we have a valid message queue. */
  got_mq:
	err = pse51_desc_create(&desc, &mq->nodebase,
				oflags & (O_NONBLOCK | PSE51_PERMS_MASK));
	if (err)
		goto err_lock_put_mq;

	return (mqd_t) pse51_desc_fd(desc);

  err_lock_put_mq:
	xnlock_get_irqsave(&nklock, s);
  err_put_mq:
	pse51_node_put(&mq->nodebase);

	if (pse51_node_removed_p(&mq->nodebase)) {
		/* mq is no longer referenced, we may destroy it. */

		xnlock_put_irqrestore(&nklock, s);
		pse51_mq_destroy(mq);
	  err_free_mq:
		xnfree(mq);
	} else
		xnlock_put_irqrestore(&nklock, s);
  error:
	thread_set_errno(err);

	return (mqd_t) - 1;
}

/**
 * Close a message queue.
 *
 * This service closes the message queue descriptor @a fd. The message queue is
 * destroyed only when all open descriptors are closed, and when unlinked with a
 * call to the mq_unlink() service.
 *
 * @param fd message queue descriptor.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EBADF, @a fd is an invalid message queue descriptor;
 * - EPERM, the caller context is invalid.
 *
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - kernel-space cancellation cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode);
 * - user-space cancellation cleanup routine.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_close.html">
 * Specification.</a>
 * 
 */
int mq_close(mqd_t fd)
{
	pse51_desc_t *desc;
	pse51_mq_t *mq;
	spl_t s;
	int err;

	if (xnpod_interrupt_p() || !xnpod_root_p()) {
		err = EPERM;
		goto error;
	}

	xnlock_get_irqsave(&nklock, s);

	err = pse51_desc_get(&desc, fd, PSE51_MQ_MAGIC);

	if (err)
		goto err_unlock;

	mq = node2mq(pse51_desc_node(desc));

	err = pse51_node_put(&mq->nodebase);

	if (err)
		goto err_unlock;

	if (pse51_node_removed_p(&mq->nodebase)) {
		xnlock_put_irqrestore(&nklock, s);

		pse51_mq_destroy(mq);
		xnfree(mq);
	} else
		xnlock_put_irqrestore(&nklock, s);

	err = pse51_desc_destroy(desc);

	if (err)
		goto error;

	return 0;

      err_unlock:
	xnlock_put_irqrestore(&nklock, s);
      error:
	thread_set_errno(err);
	return -1;
}

/**
 * Unlink a message queue.
 *
 * This service unlinks the message queue named @a name. The message queue is
 * not destroyed until all queue descriptors obtained with the mq_open() service
 * are closed with the mq_close() service. However, after a call to this
 * service, the unlinked queue may no longer be reached with the mq_open()
 * service.
 *
 * @param name name of the message queue to be unlinked.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EPERM, the caller context is invalid;
 * - ENAMETOOLONG, the length of the @a name argument exceeds 64 characters;
 * - ENOENT, the message queue does not exist.
 * 
 * @par Valid contexts:
 * - kernel module initialization or cleanup routine;
 * - kernel-space cancellation cleanup routine;
 * - user-space thread (Xenomai threads switch to secondary mode);
 * - user-space cancellation cleanup routine.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_unlink.html">
 * Specification.</a>
 * 
 */
int mq_unlink(const char *name)
{
	pse51_node_t *node;
	pse51_mq_t *mq;
	spl_t s;
	int err;

	if (xnpod_interrupt_p() || !xnpod_root_p()) {
		err = EPERM;
		goto error;
	}

	xnlock_get_irqsave(&nklock, s);

	err = pse51_node_remove(&node, name, PSE51_MQ_MAGIC);

	if (!err && pse51_node_removed_p(node)) {
		xnlock_put_irqrestore(&nklock, s);

		mq = node2mq(node);
		pse51_mq_destroy(mq);
		xnfree(mq);
	} else
		xnlock_put_irqrestore(&nklock, s);

	if (err) {
	      error:
		thread_set_errno(err);
		return -1;
	}

	return 0;
}

static int
pse51_mq_trysend(pse51_direct_msg_t *msgp, pse51_desc_t *desc, size_t len)
{
	xnthread_t *reader;
	pthread_t thread;
	pse51_mq_t *mq;
	unsigned flags;

	mq = node2mq(pse51_desc_node(desc));
	flags = pse51_desc_getflags(desc) & PSE51_PERMS_MASK;

	if (flags != O_WRONLY && flags != O_RDWR)
		return EBADF;

	if (len > mq->attr.mq_msgsize)
		return EMSGSIZE;

	reader = xnsynch_peek_pendq(&mq->receivers);
	thread = thread2pthread(reader);

	if (thread && !xnthread_test_state(reader, XNSHADOW)) {
		pse51_direct_msg_t *msg = (pse51_direct_msg_t *)thread->arg;
		msg->flags |= PSE51_MSG_DIRECT;
		*msgp = *msg;
	} else {
		pse51_msg_t *msg = pse51_mq_msg_alloc(mq);
		if (!msg)
			return EAGAIN;

		msgp->buf = &msg->data[0];
		msgp->lenp = &msg->len;
		msgp->priop = &msg->link.prio;
		msgp->flags = reader ? PSE51_MSG_RESCHED : 0;
	}

	return 0;
}

static int
pse51_mq_tryrcv(pse51_direct_msg_t *msgp, pse51_desc_t *desc, size_t len)
{
	xnpholder_t *holder;
	pse51_msg_t *msg;
	pse51_mq_t *mq;
	unsigned flags;

	mq = node2mq(pse51_desc_node(desc));
	flags = pse51_desc_getflags(desc) & PSE51_PERMS_MASK;

	if (flags != O_RDONLY && flags != O_RDWR)
		return EBADF;

	if (len < mq->attr.mq_msgsize)
		return EMSGSIZE;

	if (!(holder = getpq(&mq->queued)))
		return EAGAIN;

	msg = any2msg(holder, link);
	msgp->buf = &msg->data[0];
	msgp->lenp = &msg->len;
	msgp->priop = &msg->link.prio;
	msgp->flags = 0;

	return 0;	
}

int pse51_mq_timedsend_inner(pse51_direct_msg_t *msgp, mqd_t fd,
			     size_t len, const struct timespec *abs_timeoutp)
{
	int rc;

	for (;;) {
		pse51_desc_t *desc;
		xnthread_t *cur;
		pse51_mq_t *mq;
		xnticks_t to = XN_INFINITE;

		if ((rc = pse51_desc_get(&desc, fd, PSE51_MQ_MAGIC)))
			return rc;

		if ((rc = pse51_mq_trysend(msgp, desc, len)) != EAGAIN)
			return rc;

		if ((pse51_desc_getflags(desc) & O_NONBLOCK))
			return rc;

		if (xnpod_unblockable_p())
			return EPERM;

		if (abs_timeoutp) {
			if ((unsigned long)abs_timeoutp->tv_nsec >= ONE_BILLION)
				return EINVAL;

			to = ts2ticks_ceil(abs_timeoutp) + 1;
		}

		mq = node2mq(pse51_desc_node(desc));

		cur = xnpod_current_thread();

		thread_cancellation_point(cur);

		if (abs_timeoutp)
			xnsynch_sleep_on(&mq->senders, to, XN_REALTIME);
		else
			xnsynch_sleep_on(&mq->senders, to, XN_RELATIVE);

		thread_cancellation_point(cur);

		if (xnthread_test_info(cur, XNBREAK))
			return EINTR;

		if (xnthread_test_info(cur, XNTIMEO))
			return ETIMEDOUT;

		if (xnthread_test_info(cur, XNRMID))
			return EBADF;
	}
}

void pse51_mq_finish_send(mqd_t fd, pse51_direct_msg_t *msgp)
{
	pse51_desc_t *desc;
	pse51_mq_t *mq;

	pse51_desc_get(&desc, fd, PSE51_MQ_MAGIC);
	mq = node2mq(pse51_desc_node(desc));

	if (!(msgp->flags & PSE51_MSG_DIRECT)) {
		pse51_msg_t *msg;
	
		msg = any2msg(msgp->lenp, len);

		insertpqf(&mq->queued, &msg->link, msg->link.prio);

		if (!(msgp->flags & PSE51_MSG_RESCHED)) {
			if (mq->target && countpq(&mq->queued) == 1) {
				/* First message ? no pending reader ? attempt
				   to send a signal if mq_notify was called. */
				pse51_sigqueue_inner(mq->target, &mq->si);
				mq->target = NULL;
			}
			return;	/* Do not reschedule */
		}
	}
	if (xnsynch_wakeup_one_sleeper(&mq->receivers))
		xnpod_schedule();
}

int pse51_mq_timedrcv_inner(pse51_direct_msg_t *msgp, mqd_t fd,
			    size_t len, const struct timespec *abs_timeoutp)
{
	xnthread_t *cur = xnpod_current_thread();
	int rc;

	for (;;) {
		xnticks_t to = XN_INFINITE;
		pse51_desc_t *desc;
		pthread_t thread;
		pse51_mq_t *mq;
		int direct = 0;

		if ((rc = pse51_desc_get(&desc, fd, PSE51_MQ_MAGIC)))
			return rc;

		if ((rc = pse51_mq_tryrcv(msgp, desc, len)) != EAGAIN)
			return rc;

		if ((pse51_desc_getflags(desc) & O_NONBLOCK))
			return rc;

		if (xnpod_unblockable_p())
			return EPERM;

		if (abs_timeoutp) {
			if ((unsigned long)abs_timeoutp->tv_nsec >= ONE_BILLION)
				return EINVAL;

			to = ts2ticks_ceil(abs_timeoutp) + 1;
		}

		mq = node2mq(pse51_desc_node(desc));

		thread = thread2pthread(cur);

		if (thread && !xnthread_test_state(cur, XNSHADOW)) {
			msgp->flags &= ~PSE51_MSG_DIRECT;
			thread->arg = msgp;
			direct = 1;
		}

		thread_cancellation_point(cur);

		if (abs_timeoutp)
			xnsynch_sleep_on(&mq->receivers, to, XN_REALTIME);
		else
			xnsynch_sleep_on(&mq->receivers, to, XN_RELATIVE);

		thread_cancellation_point(cur);

		if (direct && (msgp->flags & PSE51_MSG_DIRECT))
			return 0;

		if (xnthread_test_info(cur, XNRMID))
			return EBADF;

		if (xnthread_test_info(cur, XNTIMEO))
			return ETIMEDOUT;

		if (xnthread_test_info(cur, XNBREAK))
			return EINTR;
	}
}

void pse51_mq_finish_rcv(mqd_t fd, pse51_direct_msg_t *msgp)
{

	if (!(msgp->flags & PSE51_MSG_DIRECT)) {
		pse51_desc_t *desc;
		pse51_msg_t *msg;
		pse51_mq_t *mq;

		pse51_desc_get(&desc, fd, PSE51_MQ_MAGIC);
		mq = node2mq(pse51_desc_node(desc));
		msg = any2msg(msgp->lenp, len);

		pse51_mq_msg_free(mq, msg);

		if (xnsynch_wakeup_one_sleeper(&mq->senders))
			xnpod_schedule();
	}
}

/**
 * Send a message to a message queue.
 *
 * If the message queue @a fd is not full, this service sends the message of
 * length @a len pointed to by the argument @a buffer, with priority @a prio. A
 * message with greater priority is inserted in the queue before a message with
 * lower priority.
 *
 * If the message queue is full and the flag @a O_NONBLOCK is not set, the
 * calling thread is suspended until the queue is not full. If the message queue
 * is full and the flag @a O_NONBLOCK is set, the message is not sent and the
 * service returns immediately a value of -1 with @a errno set to EAGAIN.
 *
 * @param fd message queue descriptor;
 *
 * @param buffer pointer to the message to be sent;
 *
 * @param len length of the message;
 *
 * @param prio priority of the message.
 *
 * @return 0 and send a message on success;
 * @return -1 with no message sent and @a errno set if:
 * - EBADF, @a fd is not a valid message queue descriptor open for writing;
 * - EMSGSIZE, the message length @a len exceeds the @a mq_msgsize attribute of
 *   the message queue;
 * - EAGAIN, the flag O_NONBLOCK is set for the descriptor @a fd and the message
 *   queue is full;
 * - EPERM, the caller context is invalid;
 * - EINTR, the service was interrupted by a signal.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space thread,
 * - Xenomai user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_send.html">
 * Specification.</a>
 * 
 */
int mq_send(mqd_t fd, const char *buffer, size_t len, unsigned prio)
{
	pse51_direct_msg_t msg;
	spl_t s;
	int err;

	xnlock_get_irqsave(&nklock, s);
	err = pse51_mq_timedsend_inner(&msg, fd, len, NULL);
	if (err) {
		xnlock_put_irqrestore(&nklock, s);

		thread_set_errno(err);
		return -1;
	}

	memcpy(msg.buf, buffer, len);
	*(msg.lenp) = len;
	if (msg.priop)
		*(msg.priop) = prio;
	
	pse51_mq_finish_send(fd, &msg);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Attempt, during a bounded time, to send a message to a message queue.
 *
 * This service is equivalent to mq_send(), except that if the message queue is
 * full and the flag @a O_NONBLOCK is not set for the descriptor @a fd, the
 * calling thread is only suspended until the timeout specified by @a
 * abs_timeout expires.
 *
 * @param fd message queue descriptor;
 *
 * @param buffer pointer to the message to be sent;
 *
 * @param len length of the message;
 *
 * @param prio priority of the message;
 *
 * @param abs_timeout the timeout, expressed as an absolute value of the
 * CLOCK_REALTIME clock.
 *
 * @return 0 and send a message on success;
 * @return -1 with no message sent and @a errno set if:
 * - EBADF, @a fd is not a valid message queue descriptor open for writing;
 * - EMSGSIZE, the message length exceeds the @a mq_msgsize attribute of the
 *   message queue;
 * - EAGAIN, the flag O_NONBLOCK is set for the descriptor @a fd and the message
 *   queue is full;
 * - EPERM, the caller context is invalid;
 * - ETIMEDOUT, the specified timeout expired;
 * - EINTR, the service was interrupted by a signal.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space thread,
 * - Xenomai user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_timedsend.html">
 * Specification.</a>
 * 
 */
int mq_timedsend(mqd_t fd,
		 const char *buffer,
		 size_t len, unsigned prio, const struct timespec *abs_timeout)
{
	pse51_direct_msg_t msg;
	spl_t s;
	int err;

	xnlock_get_irqsave(&nklock, s);
	err = pse51_mq_timedsend_inner(&msg, fd, len, abs_timeout);
	if (err) {
		xnlock_put_irqrestore(&nklock, s);

		thread_set_errno(err);
		return -1;
	}

	memcpy(msg.buf, buffer, len);
	*(msg.lenp) = len;
	if (msg.priop)
		*(msg.priop) = prio;
	
	pse51_mq_finish_send(fd, &msg);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Receive a message from a message queue.
 *
 * If the message queue @a fd is not empty and if @a len is greater than the @a
 * mq_msgsize of the message queue, this service copies, at the address
 * @a buffer, the queued message with the highest priority.
 *
 * If the queue is empty and the flag @a O_NONBLOCK is not set for the
 * descriptor @a fd, the calling thread is suspended until some message is sent
 * to the queue. If the queue is empty and the flag @a O_NONBLOCK is set for the
 * descriptor @a fd, this service returns immediately a value of -1 with @a
 * errno set to EAGAIN.
 *
 * @param fd the queue descriptor;
 *
 * @param buffer the address where the received message will be stored on
 * success;
 *
 * @param len @a buffer length;
 *
 * @param priop address where the priority of the received message will be
 * stored on success.
 *
 * @return the message length, and copy a message at the address @a buffer on
 * success;
 * @return -1 with no message unqueued and @a errno set if:
 * - EBADF, @a fd is not a valid descriptor open for reading;
 * - EMSGSIZE, the length @a len is lesser than the message queue @a mq_msgsize
 *   attribute;
 * - EAGAIN, the queue is empty, and the flag @a O_NONBLOCK is set for the
 *   descriptor @a fd;
 * - EPERM, the caller context is invalid;
 * - EINTR, the service was interrupted by a signal.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space thread,
 * - Xenomai user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_receive.html">
 * Specification.</a>
 * 
 */
ssize_t mq_receive(mqd_t fd, char *buffer, size_t len, unsigned *priop)
{
	pse51_direct_msg_t msg;
	spl_t s;
	int err;

	msg.buf = buffer;
	msg.lenp = &len;
	msg.priop = priop;
	msg.flags = 0;

	xnlock_get_irqsave(&nklock, s);
	err = pse51_mq_timedrcv_inner(&msg, fd, len, NULL);
	if (err) {
		xnlock_put_irqrestore(&nklock, s);

		thread_set_errno(err);
		return -1;
	}

	if (!(msg.flags & PSE51_MSG_DIRECT)) {
		memcpy(buffer, msg.buf, *(msg.lenp));
		len = *(msg.lenp);
		if (priop)
			*priop = *(msg.priop);
	}
	pse51_mq_finish_rcv(fd, &msg);
	xnlock_put_irqrestore(&nklock, s);

	return len;
}

/**
 * Attempt, during a bounded time, to receive a message from a message queue.
 *
 * This service is equivalent to mq_receive(), except that if the flag @a
 * O_NONBLOCK is not set for the descriptor @a fd and the message queue is
 * empty, the calling thread is only suspended until the timeout @a abs_timeout
 * expires.
 *
 * @param fd the queue descriptor;
 *
 * @param buffer the address where the received message will be stored on
 * success;
 *
 * @param len @a buffer length;
 *
 * @param priop address where the priority of the received message will be
 * stored on success.
 *
 * @param abs_timeout the timeout, expressed as an absolute value of the
 * CLOCK_REALTIME clock.
 *
 * @return the message length, and copy a message at the address @a buffer on
 * success;
 * @return -1 with no message unqueued and @a errno set if:
 * - EBADF, @a fd is not a valid descriptor open for reading;
 * - EMSGSIZE, the length @a len is lesser than the message queue @a mq_msgsize
 *   attribute;
 * - EAGAIN, the queue is empty, and the flag @a O_NONBLOCK is set for the
 *   descriptor @a fd;
 * - EPERM, the caller context is invalid;
 * - EINTR, the service was interrupted by a signal;
 * - ETIMEDOUT, the specified timeout expired.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space thread,
 * - Xenomai user-space thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_timedreceive.html">
 * Specification.</a>
 * 
 */
ssize_t mq_timedreceive(mqd_t fd,
			char *__restrict__ buffer,
			size_t len,
			unsigned *__restrict__ priop,
			const struct timespec * __restrict__ abs_timeout)
{
	pse51_direct_msg_t msg;
	spl_t s;
	int err;

	msg.buf = buffer;
	msg.lenp = &len;
	msg.priop = priop;
	msg.flags = 0;

	xnlock_get_irqsave(&nklock, s);
	err = pse51_mq_timedrcv_inner(&msg, fd, len, abs_timeout);
	if (err) {
		xnlock_put_irqrestore(&nklock, s);

		thread_set_errno(err);
		return -1;
	}

	if (!(msg.flags & PSE51_MSG_DIRECT)) {
		memcpy(buffer, msg.buf, *(msg.lenp));
		len = *(msg.lenp);
		if (priop)
			*priop = *(msg.priop);
	}
	pse51_mq_finish_rcv(fd, &msg);
	xnlock_put_irqrestore(&nklock, s);

	return len;
}

/**
 * Get the attributes object of a message queue.
 *
 * This service stores, at the address @a attr, the attributes of the messages
 * queue descriptor @a fd.
 *
 * The following attributes are set:
 * - @a mq_flags, flags of the message queue descriptor @a fd;
 * - @a mq_maxmsg, maximum number of messages in the message queue;
 * - @a mq_msgsize, maximum message size;
 * - @a mq_curmsgs, number of messages currently in the queue.
 *
 * @param fd message queue descriptor;
 *
 * @param attr address where the message queue attributes will be stored on
 * success.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EBADF, @a fd is not a valid descriptor.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_getattr.html">
 * Specification.</a>
 * 
 */
int mq_getattr(mqd_t fd, struct mq_attr *attr)
{
	pse51_desc_t *desc;
	pse51_mq_t *mq;
	spl_t s;
	int err;

	xnlock_get_irqsave(&nklock, s);

	err = pse51_desc_get(&desc, fd, PSE51_MQ_MAGIC);

	if (err) {
		xnlock_put_irqrestore(&nklock, s);
		thread_set_errno(err);
		return -1;
	}

	mq = node2mq(pse51_desc_node(desc));
	*attr = mq->attr;
	attr->mq_flags = pse51_desc_getflags(desc);
	attr->mq_curmsgs = countpq(&mq->queued);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Set flags of a message queue.
 *
 * This service sets the flags of the @a fd descriptor to the value of the
 * member @a mq_flags of the @b mq_attr structure pointed to by @a attr.
 *
 * The previous value of the message queue attributes are stored at the address
 * @a oattr if it is not @a NULL.
 *
 * Only setting or clearing the O_NONBLOCK flag has an effect.
 *
 * @param fd message queue descriptor;
 *
 * @param attr pointer to new attributes (only @a mq_flags is used);
 *
 * @param oattr if not @a NULL, address where previous message queue attributes
 * will be stored on success.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EBADF, @a fd is not a valid message queue descriptor.
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_setattr.html">
 * Specification.</a>
 * 
 */
int mq_setattr(mqd_t fd,
	       const struct mq_attr *__restrict__ attr,
	       struct mq_attr *__restrict__ oattr)
{
	pse51_desc_t *desc;
	pse51_mq_t *mq;
	long flags;
	spl_t s;
	int err;

	xnlock_get_irqsave(&nklock, s);

	err = pse51_desc_get(&desc, fd, PSE51_MQ_MAGIC);

	if (err) {
		xnlock_put_irqrestore(&nklock, s);
		thread_set_errno(err);
		return -1;
	}

	mq = node2mq(pse51_desc_node(desc));
	if (oattr) {
		*oattr = mq->attr;
		oattr->mq_flags = pse51_desc_getflags(desc);
		oattr->mq_curmsgs = countpq(&mq->queued);
	}
	flags = (pse51_desc_getflags(desc) & PSE51_PERMS_MASK)
	    | (attr->mq_flags & ~PSE51_PERMS_MASK);
	pse51_desc_setflags(desc, flags);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/**
 * Register the current thread to be notified of message arrival at an empty
 * message queue.
 *
 * If @a evp is not @a NULL and is the address of a @b sigevent structure with
 * the @a sigev_notify member set to SIGEV_SIGNAL, the current thread will be
 * notified by a signal when a message is sent to the message queue @a fd, the
 * queue is empty, and no thread is blocked in call to mq_receive() or
 * mq_timedreceive(). After the notification, the thread is unregistered.
 *
 * If @a evp is @a NULL or the @a sigev_notify member is SIGEV_NONE, the current
 * thread is unregistered.
 *
 * Only one thread may be registered at a time.
 *
 * If the current thread is not a Xenomai POSIX skin thread (created with
 * pthread_create()), this service fails.
 *
 * Note that signals sent to user-space Xenomai POSIX skin threads will cause
 * them to switch to secondary mode.
 *
 * @param fd message queue descriptor;
 *
 * @param evp pointer to an event notification structure.
 *
 * @retval 0 on success;
 * @retval -1 with @a errno set if:
 * - EINVAL, @a evp is invalid;
 * - EPERM, the caller context is invalid;
 * - EBADF, @a fd is not a valid message queue descriptor;
 * - EBUSY, another thread is already registered.
 *
 * @par Valid contexts:
 * - Xenomai kernel-space POSIX skin thread,
 * - Xenomai user-space POSIX skin thread (switches to primary mode).
 *
 * @see
 * <a href="http://www.opengroup.org/onlinepubs/000095399/functions/mq_notify.html">
 * Specification.</a>
 * 
 */
int mq_notify(mqd_t fd, const struct sigevent *evp)
{
	pthread_t thread = pse51_current_thread();
	pse51_desc_t *desc;
	pse51_mq_t *mq;
	int err;
	spl_t s;

	if (evp && ((evp->sigev_notify != SIGEV_SIGNAL &&
		     evp->sigev_notify != SIGEV_NONE) ||
		    (unsigned)(evp->sigev_signo - 1) > SIGRTMAX - 1)) {
		err = EINVAL;
		goto error;
	}

	if (xnpod_asynch_p() || !thread) {
		err = EPERM;
		goto error;
	}

	xnlock_get_irqsave(&nklock, s);

	err = pse51_desc_get(&desc, fd, PSE51_MQ_MAGIC);

	if (err)
		goto unlock_and_error;

	mq = node2mq(pse51_desc_node(desc));

	if (mq->target && mq->target != thread) {
		err = EBUSY;
		goto unlock_and_error;
	}

	if (!evp || evp->sigev_notify == SIGEV_NONE)
		/* Here, mq->target == pse51_current_thread() or NULL. */
		mq->target = NULL;
	else {
		mq->target = thread;
		mq->si.info.si_signo = evp->sigev_signo;
		mq->si.info.si_code = SI_MESGQ;
		mq->si.info.si_value = evp->sigev_value;
	}

	xnlock_put_irqrestore(&nklock, s);
	return 0;

      unlock_and_error:
	xnlock_put_irqrestore(&nklock, s);
      error:
	thread_set_errno(err);
	return -1;
}

#ifdef CONFIG_XENO_OPT_PERVASIVE
static void uqd_cleanup(pse51_assoc_t *assoc)
{
	pse51_ufd_t *ufd = assoc2ufd(assoc);
#if XENO_DEBUG(POSIX)
	xnprintf("Posix: closing message queue descriptor %lu.\n",
		 pse51_assoc_key(assoc));
#endif /* XENO_DEBUG(POSIX) */
	mq_close(ufd->kfd);
	xnfree(ufd);
}

void pse51_mq_uqds_cleanup(pse51_queues_t *q)
{
	pse51_assocq_destroy(&q->uqds, &uqd_cleanup);
}
#endif /* CONFIG_XENO_OPT_PERVASIVE */

int pse51_mq_pkg_init(void)
{
	initq(&pse51_mqq);

	return 0;
}

void pse51_mq_pkg_cleanup(void)
{
	xnholder_t *holder;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	while ((holder = getheadq(&pse51_mqq))) {
		pse51_mq_t *mq = link2mq(holder);
		pse51_node_t *node;
		pse51_node_remove(&node, mq->nodebase.name, PSE51_MQ_MAGIC);
		xnlock_put_irqrestore(&nklock, s);
		pse51_mq_destroy(mq);
#if XENO_DEBUG(POSIX)
		xnprintf("Posix: unlinking message queue \"%s\".\n",
			 mq->nodebase.name);
#endif /* XENO_DEBUG(POSIX) */
		xnfree(mq);
		xnlock_get_irqsave(&nklock, s);
	}
	xnlock_put_irqrestore(&nklock, s);
}

/*@}*/

EXPORT_SYMBOL(mq_open);
EXPORT_SYMBOL(mq_getattr);
EXPORT_SYMBOL(mq_setattr);
EXPORT_SYMBOL(mq_send);
EXPORT_SYMBOL(mq_timedsend);
EXPORT_SYMBOL(mq_receive);
EXPORT_SYMBOL(mq_timedreceive);
EXPORT_SYMBOL(mq_close);
EXPORT_SYMBOL(mq_unlink);
