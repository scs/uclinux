/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
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
 * \ingroup pipe
 */

/*!
 * \ingroup native
 * \defgroup pipe Message pipe services.
 *
 * Message pipe services.
 *
 * A message pipe is a two-way communication channel between Xenomai
 * tasks and standard Linux processes using regular file I/O
 * operations on a pseudo-device. Pipes can be operated in a
 * message-oriented fashion so that message boundaries are preserved,
 * and also in byte streaming mode from real-time to standard Linux
 * processes for optimal throughput.
 *
 * Xenomai tasks open their side of the pipe using the
 * rt_pipe_create() service; standard Linux processes do the same by
 * opening one of the /dev/rtpN special devices, where N is the minor
 * number agreed upon between both ends of each pipe. Additionally,
 * named pipes are available through the registry support, which
 * automatically creates a symbolic link from entries under
 * /proc/xenomai/registry/native/pipes/ to the corresponding special
 * device file.
 *
 *@{*/

/** @example pipe.c */

#include <nucleus/pod.h>
#include <nucleus/heap.h>
#include <nucleus/registry.h>
#include <native/pipe.h>

#ifdef CONFIG_XENO_EXPORT_REGISTRY

static ssize_t __pipe_link_proc(char *buf, int count, void *data)
{
	RT_PIPE *pipe = (RT_PIPE *)data;
	return snprintf(buf, count, "/dev/rtp%d", pipe->minor);
}

extern xnptree_t __native_ptree;

static xnpnode_t __pipe_pnode = {

	.dir = NULL,
	.type = "pipes",
	.entries = 0,
	.link_proc = &__pipe_link_proc,
	.root = &__native_ptree,
};

#elif defined(CONFIG_XENO_OPT_REGISTRY)

static xnpnode_t __pipe_pnode = {

	.type = "pipes"
};

#endif /* CONFIG_XENO_EXPORT_REGISTRY */

static void __pipe_flush_pool(xnheap_t *heap,
			      void *poolmem, u_long poolsize, void *cookie)
{
	xnarch_free_host_mem(poolmem, poolsize);
}

static void *__pipe_alloc_handler(size_t size, void *xstate) /* nklock free */
{
	RT_PIPE *pipe = xstate;
	void *buf;

	/* Try to allocate memory for the incoming message. */
	buf = xnheap_alloc(pipe->bufpool, size);
	if (unlikely(buf == NULL)) {
		if (size > xnheap_max_contiguous(pipe->bufpool))
			buf = (void *)-1; /* Will never succeed. */
	}

	return buf;
}

static void __pipe_free_handler(void *buf, void *xstate) /* nklock free */
{
	RT_PIPE *pipe = xstate;
	spl_t s;
	
	if (buf == pipe->buffer) {
		/* Reset the streaming buffer. */
		xnlock_get_irqsave(&nklock, s);
		pipe->fillsz = 0;
		__clear_bit(P_SYNCWAIT, &pipe->status);
		__clear_bit(P_ATOMIC, &pipe->status);
		xnlock_put_irqrestore(&nklock, s);
	} else
		xnheap_free(pipe->bufpool, buf);
}

static void __pipe_release_handler(void *xstate) /* nklock free */
{
	RT_PIPE *pipe = xstate;

	if (pipe->bufpool == &pipe->privpool)
		xnheap_destroy(&pipe->privpool, __pipe_flush_pool, NULL);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	if (pipe->cpid)
		xnfree(pipe);
#endif
}

int __native_pipe_pkg_init(void)
{
	return 0;
}

void __native_pipe_pkg_cleanup(void)
{
	__native_pipe_flush_rq(&__native_global_rholder.pipeq);
}

/**
 * @fn int rt_pipe_create(RT_PIPE *pipe,const char *name,int minor, size_t poolsize)
 * @brief Create a message pipe.
 *
 * This service opens a bi-directional communication channel allowing
 * data exchange between Xenomai tasks and standard Linux
 * processes. Pipes natively preserve message boundaries, but can also
 * be used in byte stream mode from Xenomai tasks to standard Linux
 * processes.
 *
 * rt_pipe_create() always returns immediately, even if no Linux
 * process has opened the associated special device file yet. On the
 * contrary, the non real-time side could block upon attempt to open
 * the special device file until rt_pipe_create() is issued on the
 * same pipe from a Xenomai task, unless O_NONBLOCK has been specified to
 * the open(2) system call.
 *
 * @param pipe The address of a pipe descriptor Xenomai will use to store
 * the pipe-related data.  This descriptor must always be valid while
 * the pipe is active therefore it must be allocated in permanent
 * memory.
 *
 * @param name An ASCII string standing for the symbolic name of the
 * message pipe. When non-NULL and non-empty, this string is copied to
 * a safe place into the descriptor, and passed to the registry
 * package if enabled for indexing the created pipe.
 *
 * Named pipes are supported through the use of the registry. When the
 * registry support is enabled, passing a valid @a name parameter when
 * creating a message pipe subsequently allows standard Linux
 * processes to follow a symbolic link from
 * /proc/xenomai/registry/pipes/@a name in order to reach the
 * associated special device (i.e. /dev/rtp*), so that the specific @a
 * minor information does not need to be known from those processes
 * for opening the proper device file. In such a case, both sides of
 * the pipe only need to agree upon a symbolic name to refer to the
 * same data path, which is especially useful whenever the @a minor
 * number is picked up dynamically using an adaptive algorithm, such
 * as passing P_MINOR_AUTO as @a minor value.
 *
 * @param minor The minor number of the device associated with the
 * pipe.  Passing P_MINOR_AUTO causes the minor number to be
 * auto-allocated. In such a case, the @a name parameter must be valid
 * so that user-space processes may subsequently follow the symbolic
 * link that will be automatically created from
 * /proc/xenomai/registry/pipes/@a name to the allocated pipe device
 * entry (i.e. /dev/rtp*).
 *
 * @param poolsize Specifies the size of a dedicated buffer pool for the
 * pipe. Passing 0 means that all message allocations for this pipe are
 * performed on the system heap.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -ENOMEM is returned if the system fails to get enough dynamic
 * memory from the global real-time heap in order to register the
 * pipe, or if not enough memory could be obtained from the selected
 * buffer pool for allocating the internal streaming buffer.
 *
 * - -EEXIST is returned if the @a name is already in use by some
 * registered object.
 *
 * - -ENODEV is returned if @a minor is different from P_MINOR_AUTO
 * and is not a valid minor number for the pipe special device either
 * (i.e. /dev/rtp*).
 *
 * - -EBUSY is returned if @a minor is already open.
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

int rt_pipe_create(RT_PIPE *pipe, const char *name, int minor, size_t poolsize)
{
#if CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ > 0
	/* XNCORE_PAGE_SIZE is guaranteed to be significantly greater
	 * than sizeof(RT_PIPE_MSG), so that we could store a message
	 * header along with a useful buffer space into the local
	 * pool. */
	size_t streamsz = CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ < XNCORE_PAGE_SIZE ?
		XNCORE_PAGE_SIZE : CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ;
#else
#define streamsz  0
#endif
	struct xnpipe_operations ops;
	void *poolmem;
	int err = 0;
	spl_t s;

	if (!xnpod_root_p())
		return -EPERM;

	pipe->buffer = NULL;
	pipe->bufpool = &kheap;
	pipe->fillsz = 0;
	pipe->status = 0;
	pipe->handle = 0;	/* i.e. (still) unregistered pipe. */
	pipe->magic = XENO_PIPE_MAGIC;
	xnobject_copy_name(pipe->name, name);

	if (poolsize > 0) {
		/* Make sure we won't hit trivial argument errors when calling
		   xnheap_init(). */

		poolsize += streamsz;

		/* Account for the minimum heap size and overhead so
		   that the actual free space is large enough to match
		   the requested size. */

		poolsize = xnheap_rounded_size(poolsize, XNCORE_PAGE_SIZE);
		poolmem = xnarch_alloc_host_mem(poolsize);

		if (!poolmem)
			return -ENOMEM;

		/* Use natural page size */
		err = xnheap_init(&pipe->privpool, poolmem, poolsize, XNCORE_PAGE_SIZE);
		if (err) {
			xnarch_free_host_mem(poolmem, poolsize);
			return err;
		}

		pipe->bufpool = &pipe->privpool;
	}

#if CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ > 0
	pipe->buffer = xnheap_alloc(pipe->bufpool, streamsz);
	if (pipe->buffer == NULL) {
		if (pipe->bufpool == &pipe->privpool)
			xnheap_destroy(&pipe->privpool, __pipe_flush_pool,
				       NULL);
		return -ENOMEM;
	}
	inith(&pipe->buffer->link);
	pipe->buffer->size = streamsz - sizeof(RT_PIPE_MSG);
#endif /* CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ > 0 */

	ops.output = NULL;
	ops.input = NULL;
	ops.alloc_ibuf = &__pipe_alloc_handler;
	ops.free_ibuf = &__pipe_free_handler;
	ops.free_obuf = &__pipe_free_handler;
	ops.release = &__pipe_release_handler;

	minor = xnpipe_connect(minor, &ops, pipe);
	if (minor < 0) {
		if (pipe->bufpool == &pipe->privpool)
			xnheap_destroy(&pipe->privpool, __pipe_flush_pool,
				       NULL);
		return minor;
	}

	pipe->minor = minor;
	inith(&pipe->rlink);
	pipe->rqueue = &xeno_get_rholder()->pipeq;
	xnlock_get_irqsave(&nklock, s);
	appendq(pipe->rqueue, &pipe->rlink);
	xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_XENO_OPT_PERVASIVE
	pipe->cpid = 0;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_REGISTRY
	/* <!> Since xnregister_enter() may reschedule, only register
	   complete objects, so that the registry cannot return handles to
	   half-baked objects... */

	if (name) {
		xnpnode_t *pnode = &__pipe_pnode;

		if (!*name) {
			/* Since this is an anonymous object (empty name on entry)
			   from user-space, it gets registered under an unique
			   internal name but is not exported through /proc. */
			xnobject_create_name(pipe->name, sizeof(pipe->name),
					     (void *)pipe);
			pnode = NULL;
		}

		err = xnregistry_enter(pipe->name, pipe, &pipe->handle, pnode);

		if (err)
			rt_pipe_delete(pipe);
	}
#endif /* CONFIG_XENO_OPT_REGISTRY */

	return err;
}

/**
 * @fn int rt_pipe_delete(RT_PIPE *pipe)
 *
 * @brief Delete a message pipe.
 *
 * This service deletes a pipe previously created by rt_pipe_create().
 * Data pending for transmission to non real-time processes are lost.
 *
 * @param pipe The descriptor address of the affected pipe.
 *
 * @return 0 is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a pipe is not a pipe descriptor.
 *
 * - -EIDRM is returned if @a pipe is a closed pipe descriptor.
 *
 * - -ENODEV or -EBADF can be returned if @a pipe is scrambled.
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

int rt_pipe_delete(RT_PIPE *pipe)
{
	int err;
	spl_t s;

	if (xnpod_asynch_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	pipe = xeno_h2obj_validate(pipe, XENO_PIPE_MAGIC, RT_PIPE);
	if (pipe == NULL) {
		err = xeno_handle_error(pipe, XENO_PIPE_MAGIC, RT_PIPE);
		xnlock_put_irqrestore(&nklock, s);
		return err;
	}

	removeq(pipe->rqueue, &pipe->rlink);
	pipe->buffer = NULL;

#ifdef CONFIG_XENO_OPT_REGISTRY
	if (pipe->handle)
		xnregistry_remove(pipe->handle);
#endif /* CONFIG_XENO_OPT_REGISTRY */

	xeno_mark_deleted(pipe);

	xnlock_put_irqrestore(&nklock, s);
	/*
	 * We must not hold the nklock when disconnecting a channel,
	 * so that the release handler may run regular kernel code safely.
	 */
	return xnpipe_disconnect(pipe->minor);
}

/**
 * @fn ssize_t rt_pipe_receive(RT_PIPE *pipe,RT_PIPE_MSG **msgp,RTIME timeout)
 *
 * @brief Receive a message from a pipe.
 *
 * This service retrieves the next message written to the associated
 * special device in user-space. rt_pipe_receive() always preserves
 * message boundaries, which means that all data sent through the same
 * write(2) operation to the special device will be gathered in a
 * single message by this service. This service differs from
 * rt_pipe_read() in that it returns a pointer to the internal buffer
 * holding the message, which improves performances by saving a data
 * copy to a user-provided buffer, especially when large messages are
 * involved.
 *
 * Unless otherwise specified, the caller is blocked for a given
 * amount of time if no data is immediately available on entry.
 *
 * @param pipe The descriptor address of the pipe to receive from.
 *
 * @param msgp A pointer to a memory location which will be written
 * upon success with the address of the received message. Once
 * consumed, the message space should be freed using rt_pipe_free().
 * The application code can retrieve the actual data and size carried
 * by the message by respectively using the P_MSGPTR() and P_MSGSIZE()
 * macros. *msgp is set to NULL and zero is returned to the caller, in
 * case the peer closed the channel while rt_pipe_receive() was
 * reading from it.
 *
 * @param timeout The number of clock ticks to wait for some message
 * to arrive (see note). Passing TM_INFINITE causes the caller to
 * block indefinitely until some data is eventually available. Passing
 * TM_NONBLOCK causes the service to return immediately without
 * waiting if no data is available on entry.
 *
 * @return The number of read bytes available from the received
 * message is returned upon success; this value will be equal to
 * P_MSGSIZE(*msgp). Otherwise:
 *
 * - 0 is returned and *msgp is set to NULL if the peer closed the
 * channel while rt_pipe_receive() was reading from it. This is to be
 * distinguished from an empty message return, where *msgp points to a
 * valid - albeit empty - message block (i.e. P_MSGSIZE(*msgp) == 0).
 *
 * - -EINVAL is returned if @a pipe is not a pipe descriptor.
 *
 * - -ENODEV or -EBADF are returned if @a pipe is scrambled.
 *
 * - -ETIMEDOUT is returned if @a timeout is different from
 * TM_NONBLOCK and no data is available within the specified amount of
 * time.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to TM_NONBLOCK
 * and no data is immediately available on entry.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before any data was available.
 *
 * - -EPERM is returned if this service should block, but was called
 * from a context which cannot sleep (e.g. interrupt, non-realtime or
 * scheduler locked).
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 *   only if @a timeout is equal to TM_NONBLOCK.
 *
 * - Kernel-based task
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

ssize_t rt_pipe_receive(RT_PIPE *pipe, RT_PIPE_MSG **msgp, RTIME timeout)
{
	ssize_t n;
	spl_t s;

	if (timeout != TM_NONBLOCK && xnpod_unblockable_p())
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	pipe = xeno_h2obj_validate(pipe, XENO_PIPE_MAGIC, RT_PIPE);

	if (!pipe) {
		n = xeno_handle_error(pipe, XENO_PIPE_MAGIC, RT_PIPE);
		goto unlock_and_exit;
	}

	n = xnpipe_recv(pipe->minor, msgp, timeout);

	if (n == -EIDRM) {
		*msgp = NULL;
		n = 0;	/* Remap to POSIX semantics. */
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return n;
}

/**
 * @fn ssize_t rt_pipe_read(RT_PIPE *pipe,void *buf,size_t size,RTIME timeout)
 *
 * @brief Read a message from a pipe.
 *
 * This service retrieves the next message written to the associated
 * special device in user-space. rt_pipe_read() always preserves
 * message boundaries, which means that all data sent through the same
 * write(2) operation to the special device will be gathered in a
 * single message by this service. This services differs from
 * rt_pipe_receive() in that it copies back the payload data to a
 * user-defined memory area, instead of returning a pointer to the
 * internal message buffer holding such data.
 *
 * Unless otherwise specified, the caller is blocked for a given
 * amount of time if no data is immediately available on entry.
 *
 * @param pipe The descriptor address of the pipe to read from.
 *
 * @param buf A pointer to a memory location which will be written
 * upon success with the read message contents.
 *
 * @param size The count of bytes from the received message to read up
 * into @a buf. If @a size is lower than the actual message size,
 * -ENOBUFS is returned since the incompletely received message would
 * be lost. If @a size is zero, this call returns immediately with no
 * other action.
 *
 * @param timeout The number of clock ticks to wait for some message
 * to arrive (see note). Passing TM_INFINITE causes the caller to
 * block indefinitely until some data is eventually available. Passing
 * TM_NONBLOCK causes the service to return immediately without
 * waiting if no data is available on entry.
 *
 * @return The number of read bytes copied to the @a buf is returned
 * upon success. Otherwise:
 *
 * - 0 is returned if the peer closed the channel while rt_pipe_read()
 * was reading from it. There is no way to distinguish this situation
 * from an empty message return using rt_pipe_read(). One should
 * rather call rt_pipe_receive() whenever this information is
 * required.
 *
 * - -EINVAL is returned if @a pipe is not a pipe descriptor.
 *
 * - -EIDRM is returned if @a pipe is a closed pipe descriptor.
 *
 * - -ENODEV or -EBADF are returned if @a pipe is scrambled.
 *
 * - -ETIMEDOUT is returned if @a timeout is different from
 * TM_NONBLOCK and no data is available within the specified amount of
 * time.
 *
 * - -EWOULDBLOCK is returned if @a timeout is equal to TM_NONBLOCK
 * and no data is immediately available on entry.
 *
 * - -EINTR is returned if rt_task_unblock() has been called for the
 * waiting task before any data was available.
 *
 * - -EPERM is returned if this service should block, but was called
 * from a context which cannot sleep (e.g. interrupt, non-realtime or
 * scheduler locked).
 *
 * - -ENOBUFS is returned if @a size is not large enough to collect the
 * message data.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 *   only if @a timeout is equal to TM_NONBLOCK.
 *
 * - Kernel-based task
 * - User-space task (switches to primary mode)
 *
 * Rescheduling: always unless the request is immediately satisfied or
 * @a timeout specifies a non-blocking operation.
 *
 * @note The @a timeout value will be interpreted as jiffies if the
 * native skin is bound to a periodic time base (see
 * CONFIG_XENO_OPT_NATIVE_PERIOD), or nanoseconds otherwise.
 */

ssize_t rt_pipe_read(RT_PIPE *pipe, void *buf, size_t size, RTIME timeout)
{
	RT_PIPE_MSG *msg;
	ssize_t nbytes;

	if (size == 0)
		return 0;

	nbytes = rt_pipe_receive(pipe, &msg, timeout);

	if (nbytes < 0)
		return nbytes;

	if (msg == NULL)	/* Closed by peer? */
		return 0;

	if (size < P_MSGSIZE(msg))
		nbytes = -ENOBUFS;
	else if (P_MSGSIZE(msg) > 0)
		memcpy(buf, P_MSGPTR(msg), P_MSGSIZE(msg));

	/* Zero-sized messages are allowed, so we still need to free the
	   message buffer even if no data copy took place. */

	rt_pipe_free(pipe, msg);

	return nbytes;
}

 /**
 * @fn ssize_t rt_pipe_send(RT_PIPE *pipe,RT_PIPE_MSG *msg,size_t size,int mode)
 *
 * @brief Send a message through a pipe.
 *
 * This service writes a complete message to be received from the
 * associated special device. rt_pipe_send() always preserves message
 * boundaries, which means that all data sent through a single call of
 * this service will be gathered in a single read(2) operation from
 * the special device. This service differs from rt_pipe_write() in
 * that it accepts a canned message buffer, instead of a pointer to
 * the raw data to be sent. This call is useful whenever the caller
 * wants to prepare the message contents separately from its sending,
 * which does not require to have all the data to be sent available at
 * once but allows for incremental updates of the message, and also
 * saves a message copy, since rt_pipe_send() deals internally with
 * message buffers.
 *
 * @param pipe The descriptor address of the pipe to send to.
 *
 * @param msg The address of the message to be sent.  The message
 * space must have been allocated using the rt_pipe_alloc() service.
 * Once passed to rt_pipe_send(), the memory pointed to by @a msg is
 * no more under the control of the application code and thus should
 * not be referenced by it anymore; deallocation of this memory will
 * be automatically handled as needed. As a special exception, @a msg
 * can be NULL and will not be dereferenced if @a size is zero.
 *
 * @param size The size in bytes of the message (payload data
 * only). Zero is a valid value, in which case the service returns
 * immediately without sending any message. This parameter allows
 * you to actually send less data than you reserved using the
 * rt_pipe_alloc() service, which may be the case if you did not
 * know how much space you needed at the time of allocation. In all
 * other cases it may be more convenient to just pass P_MSGSIZE(msg).
 *
 * @param mode A set of flags affecting the operation:
 *
 * - P_URGENT causes the message to be prepended to the output
 * queue, ensuring a LIFO ordering.
 *
 * - P_NORMAL causes the message to be appended to the output
 * queue, ensuring a FIFO ordering.
 *
 * @return Upon success, this service returns @a size.  Upon error,
 * one of the following error codes is returned:
 *
 * - -EINVAL is returned if @a pipe is not a pipe descriptor.
 *
 * - -EPIPE is returned if the associated special device is not yet
 * open.
 *
 * - -EIDRM is returned if @a pipe is a closed pipe descriptor.
 *
 * - -ENODEV or -EBADF are returned if @a pipe is scrambled.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 *
 * Rescheduling: possible.
 */

ssize_t rt_pipe_send(RT_PIPE *pipe, RT_PIPE_MSG *msg, size_t size, int mode)
{
	ssize_t n = 0;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pipe = xeno_h2obj_validate(pipe, XENO_PIPE_MAGIC, RT_PIPE);

	if (!pipe) {
		n = xeno_handle_error(pipe, XENO_PIPE_MAGIC, RT_PIPE);
		goto unlock_and_exit;
	}

	if (size > 0)
		/* We need to add the size of the message header here. */
		n = xnpipe_send(pipe->minor, msg, size + sizeof(RT_PIPE_MSG),
				mode);

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return n <= 0 ? n : n - sizeof(RT_PIPE_MSG);
}

 /**
 * @fn ssize_t rt_pipe_write(RT_PIPE *pipe,const void *buf,size_t size,int mode)
 *
 * @brief Write a message to a pipe.
 *
 * This service writes a complete message to be received from the
 * associated special device. rt_pipe_write() always preserves message
 * boundaries, which means that all data sent through a single call of
 * this service will be gathered in a single read(2) operation from
 * the special device. This service differs from rt_pipe_send() in
 * that it accepts a pointer to the raw data to be sent, instead of a
 * canned message buffer. This call is useful whenever the caller does
 * not need to prepare the message contents separately from its
 * sending.
 *
 * @param pipe The descriptor address of the pipe to write to.
 *
 * @param buf The address of the first data byte to send. The
 * data will be copied to an internal buffer before transmission.
 *
 * @param size The size in bytes of the message (payload data
 * only). Zero is a valid value, in which case the service returns
 * immediately without sending any message.
 *
 * @param mode A set of flags affecting the operation:
 *
 * - P_URGENT causes the message to be prepended to the output
 * queue, ensuring a LIFO ordering.
 *
 * - P_NORMAL causes the message to be appended to the output
 * queue, ensuring a FIFO ordering.
 *
 * @return Upon success, this service returns @a size. Upon error, one
 * of the following error codes is returned:
 *
 * - -EINVAL is returned if @a pipe is not a pipe descriptor.
 *
 * - -EPIPE is returned if the associated special device is not yet
 * open.
 *
 * - -ENOMEM is returned if not enough buffer space is available to
 * complete the operation.
 *
 * - -EIDRM is returned if @a pipe is a closed pipe descriptor.
 *
 * - -ENODEV or -EBADF are returned if @a pipe is scrambled.
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
 * Rescheduling: possible.
 */

ssize_t rt_pipe_write(RT_PIPE *pipe, const void *buf, size_t size, int mode)
{
	RT_PIPE_MSG *msg;
	ssize_t nbytes;

	if (size == 0)
		return 0;

	msg = rt_pipe_alloc(pipe, size);

	if (!msg)
		return -ENOMEM;

	memcpy(P_MSGPTR(msg), buf, size);

	nbytes = rt_pipe_send(pipe, msg, size, mode);

	if (nbytes != size)
		/* If the operation failed, we need to free the message buffer
		   by ourselves. */
		rt_pipe_free(pipe, msg);

	return nbytes;
}

/**
 * @fn ssize_t rt_pipe_stream(RT_PIPE *pipe,const void *buf,size_t size)
 *
 * @brief Stream bytes to a pipe.
 *
 * This service writes a sequence of bytes to be received from the
 * associated special device. Unlike rt_pipe_send(), this service does
 * not preserve message boundaries. Instead, an internal buffer is
 * filled on the fly with the data, which will be consumed as soon as
 * the receiver wakes up.
 *
 * Data buffers sent by the rt_pipe_stream() service are always
 * transmitted in FIFO order (i.e. P_NORMAL mode).
 *
 * @param pipe The descriptor address of the pipe to write to.
 *
 * @param buf The address of the first data byte to send. The
 * data will be copied to an internal buffer before transmission.
 *
 * @param size The size in bytes of the buffer. Zero is a valid value,
 * in which case the service returns immediately without buffering any
 * data.
 *
 * @return The number of bytes sent upon success; this value may be
 * lower than @a size, depending on the available space in the
 * internal buffer. Otherwise:
 *
 * - -EINVAL is returned if @a pipe is not a pipe descriptor.
 *
 * - -EPIPE is returned if the associated special device is not yet
 * open.
 *
 * - -EIDRM is returned if @a pipe is a closed pipe descriptor.
 *
 * - -ENODEV or -EBADF are returned if @a pipe is scrambled.
 *
 * - -ENOSYS is returned if the byte streaming mode has been disabled
 * at configuration time by nullifying the size of the pipe buffer
 * (see CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ).
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
 * Rescheduling: possible.
 */

ssize_t rt_pipe_stream(RT_PIPE *pipe, const void *buf, size_t size)
{
	ssize_t outbytes;
 	size_t fillptr;
	spl_t s;

#if CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ <= 0
	return -ENOSYS;
#else /* CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ > 0 */

	xnlock_get_irqsave(&nklock, s);

	pipe = xeno_h2obj_validate(pipe, XENO_PIPE_MAGIC, RT_PIPE);

	if (!pipe) {
		outbytes = xeno_handle_error(pipe, XENO_PIPE_MAGIC, RT_PIPE);
		goto unlock_and_exit;
	}

	if (size > CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ - pipe->fillsz)
		outbytes = CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ - pipe->fillsz;
	else
		outbytes = size;

	if (outbytes > 0) {
repeat:
		/* Mark a beginning of should-be-atomic section. */
		__set_bit(P_ATOMIC, &pipe->status);

		fillptr = pipe->fillsz;
		pipe->fillsz += outbytes;

		xnlock_put_irqrestore(&nklock, s);

		memcpy(P_MSGPTR(pipe->buffer) + fillptr,
		       (caddr_t) buf, outbytes);

		xnlock_get_irqsave(&nklock, s);

		/* We haven't been atomic, let's try again. */
		if (!__test_and_clear_bit(P_ATOMIC, &pipe->status))
			goto repeat;

		if (__test_and_set_bit(P_SYNCWAIT, &pipe->status))
			outbytes = xnpipe_mfixup(pipe->minor, pipe->buffer, outbytes);
		else {
			outbytes = xnpipe_send(pipe->minor, pipe->buffer,
					       outbytes + sizeof(RT_PIPE_MSG), XNPIPE_NORMAL);
			if (outbytes > 0)
				outbytes -= sizeof(RT_PIPE_MSG);
		}
	}

      unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);

	return outbytes;
#endif /* CONFIG_XENO_OPT_NATIVE_PIPE_BUFSZ <= 0 */
}

/**
 * @fn RT_PIPE_MSG *rt_pipe_alloc(RT_PIPE *pipe,size_t size)
 *
 * @brief Allocate a message pipe buffer.
 *
 * This service allocates a message buffer from the pipe's heap which
 * can be subsequently filled by the caller then passed to
 * rt_pipe_send() for sending. The beginning of the available data
 * area of @a size contiguous bytes is accessible from P_MSGPTR(msg).
 *
 * @param pipe The descriptor address of the affected pipe.
 *
 * @param size The requested size in bytes of the buffer. This value
 * should represent the size of the payload data.
 *
 * @return The address of the allocated message buffer upon success,
 * or NULL if the allocation fails.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 *
 * Rescheduling: never.
 */

RT_PIPE_MSG *rt_pipe_alloc(RT_PIPE *pipe, size_t size)
{
	RT_PIPE_MSG *msg;

	msg = xnheap_alloc(pipe->bufpool, size + sizeof(RT_PIPE_MSG));
	if (likely(msg)) {
		inith(&msg->link);
		msg->size = size;
	}

	return msg;
}

/**
 * @fn int rt_pipe_free(RT_PIPE *pipe,RT_PIPE_MSG *msg)
 *
 * @brief Free a message pipe buffer.
 *
 * This service releases a message buffer returned by
 * rt_pipe_receive() to the pipe's heap.
 *
 * @param pipe The descriptor address of the affected pipe.
 *
 * @param msg The address of the message buffer to free.
 *
 * @return 0 is returned upon success, or -EINVAL if @a msg is not a
 * valid message buffer previously allocated by the rt_pipe_alloc()
 * service.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 *
 * Rescheduling: never.
 */

int rt_pipe_free(RT_PIPE *pipe, RT_PIPE_MSG *msg)
{
	return xnheap_free(pipe->bufpool, msg);
}

/**
 * @fn int rt_pipe_flush(RT_PIPE *pipe, int mode)
 *
 * @brief Flush the i/o queues associated with the kernel endpoint of
 * a message pipe.
 *
 * This service flushes all data pending for consumption by the remote
 * side in user-space for the given message pipe. Upon success, no
 * data remains to be read from the remote side of the connection.
 *
 * The user-space equivalent is a call to:
 * ioctl(pipefd, XNPIPEIOC_FLUSH, 0).
 *
 * @param pipe The descriptor address of the pipe to flush.
 *
 * @param mode A mask indicating which queues need to be flushed; the
 * following flags may be combined in a single flush request:
 *
 * - XNPIPE_IFLUSH causes the input queue to be flushed (i.e. data
 * coming from user-space to the kernel endpoint will be discarded).
 *
 * - XNPIPE_OFLUSH causes the output queue to be flushed (i.e. data
 * going to user-space from the kernel endpoint will be discarded).
 *
 * @return Zero is returned upon success. Otherwise:
 *
 * - -EINVAL is returned if @a pipe is not a pipe descriptor.
 *
 * - -EIDRM is returned if @a pipe is a closed pipe descriptor.
 *
 * - -ENODEV or -EBADF are returned if @a pipe is scrambled.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 *
 * Rescheduling: never.
 */

int rt_pipe_flush(RT_PIPE *pipe, int mode)
{
	int minor;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	pipe = xeno_h2obj_validate(pipe, XENO_PIPE_MAGIC, RT_PIPE);

	if (!pipe) {
		int err = xeno_handle_error(pipe, XENO_PIPE_MAGIC, RT_PIPE);
		xnlock_put_irqrestore(&nklock, s);
		return err;
	}

	minor = pipe->minor;

	xnlock_put_irqrestore(&nklock, s);

	return xnpipe_flush(minor, mode);
}

/*@}*/

EXPORT_SYMBOL(rt_pipe_create);
EXPORT_SYMBOL(rt_pipe_delete);
EXPORT_SYMBOL(rt_pipe_receive);
EXPORT_SYMBOL(rt_pipe_send);
EXPORT_SYMBOL(rt_pipe_read);
EXPORT_SYMBOL(rt_pipe_write);
EXPORT_SYMBOL(rt_pipe_stream);
EXPORT_SYMBOL(rt_pipe_alloc);
EXPORT_SYMBOL(rt_pipe_free);
EXPORT_SYMBOL(rt_pipe_flush);
