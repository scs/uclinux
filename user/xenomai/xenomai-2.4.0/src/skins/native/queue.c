/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <sys/types.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <native/syscall.h>
#include <native/task.h>
#include <native/queue.h>

extern int __native_muxid;

static int __map_queue_memory(RT_QUEUE *q, RT_QUEUE_PLACEHOLDER * php)
{
	int err, heapfd;

	/* Open the heap device to share the message pool memory with the
	   in-kernel skin and bound clients. */
	heapfd = open(XNHEAP_DEV_NAME, O_RDWR);

	if (heapfd < 0)
		return -ENOENT;

	/* Bind this file instance to the shared heap. */
	err = ioctl(heapfd, 0, php->opaque2);

	if (err)
		goto close_and_exit;

	/* Map the heap memory into our address space. */
	php->mapbase = (caddr_t) mmap(NULL,
				      php->mapsize,
				      PROT_READ | PROT_WRITE,
				      MAP_SHARED, heapfd, 0L);

	if (php->mapbase != MAP_FAILED)
		/* Copy back a complete placeholder only if all is ok. */
		*q = *php;
	else
		err = -ENOMEM;

      close_and_exit:

	close(heapfd);

	return err;
}

int rt_queue_create(RT_QUEUE *q,
		    const char *name, size_t poolsize, size_t qlimit, int mode)
{
	RT_QUEUE_PLACEHOLDER ph;
	int err;

	err = XENOMAI_SKINCALL5(__native_muxid,
				__native_queue_create,
				&ph, name, poolsize, qlimit, mode | Q_SHARED);
	if (err)
		return err;

	err = __map_queue_memory(q, &ph);

	if (err)
		/* If the mapping fails, make sure we don't leave a dandling
		   queue in kernel space -- remove it. */
		XENOMAI_SKINCALL1(__native_muxid, __native_queue_delete, &ph);
	return err;
}

int rt_queue_bind(RT_QUEUE *q, const char *name, RTIME timeout)
{
	RT_QUEUE_PLACEHOLDER ph;
	int err;

	err = XENOMAI_SKINCALL3(__native_muxid,
				__native_queue_bind, &ph, name, &timeout);

	return err ? : __map_queue_memory(q, &ph);
}

int rt_queue_unbind(RT_QUEUE *q)
{
	int err = munmap(q->mapbase, q->mapsize);

	if (err)	/* Most likely already deleted or unbound. */
		return -EINVAL;

	q->opaque = XN_NO_HANDLE;
	q->mapbase = NULL;
	q->mapsize = 0;

	return 0;
}

int rt_queue_delete(RT_QUEUE *q)
{
	int err;

	err = munmap(q->mapbase, q->mapsize);

	if (err)
		return -EINVAL;

	err = XENOMAI_SKINCALL1(__native_muxid, __native_queue_delete, q);

	if (err)
		return err;

	q->opaque = XN_NO_HANDLE;
	q->mapbase = NULL;
	q->mapsize = 0;

	return 0;
}

void *rt_queue_alloc(RT_QUEUE *q, size_t size)
{
	void *buf;

	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_queue_alloc, q, size,
				 &buf) ? NULL : buf;
}

int rt_queue_free(RT_QUEUE *q, void *buf)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_queue_free, q, buf);
}

int rt_queue_send(RT_QUEUE *q, void *buf, size_t size, int mode)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_queue_send, q, buf, size, mode);
}

int rt_queue_write(RT_QUEUE *q, const void *buf, size_t size, int mode)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_queue_write, q, buf, size, mode);
}

ssize_t rt_queue_receive(RT_QUEUE *q, void **bufp, RTIME timeout)
{
	return XENOMAI_SKINCALL3(__native_muxid,
				 __native_queue_receive, q, bufp, &timeout);
}

ssize_t rt_queue_read(RT_QUEUE *q, void *buf, size_t size, RTIME timeout)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_queue_read, q, buf, size, &timeout);
}

int rt_queue_inquire(RT_QUEUE *q, RT_QUEUE_INFO *info)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_queue_inquire, q,
				 info);
}
