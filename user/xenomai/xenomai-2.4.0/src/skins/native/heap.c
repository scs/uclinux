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
#include <native/heap.h>

extern int __native_muxid;

static int __map_heap_memory(RT_HEAP *heap, RT_HEAP_PLACEHOLDER * php)
{
	int err, heapfd;

	/* Open the heap device to share the heap memory with the
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
		*heap = *php;
	else
		err = -ENOMEM;

      close_and_exit:

	close(heapfd);

	return err;
}

int rt_heap_create(RT_HEAP *heap, const char *name, size_t heapsize, int mode)
{
	RT_HEAP_PLACEHOLDER ph;
	int err;

	err = XENOMAI_SKINCALL4(__native_muxid,
				__native_heap_create,
				&ph, name, heapsize, mode | H_MAPPABLE);
	if (err)
		return err;

	err = __map_heap_memory(heap, &ph);

	if (err)
		/* If the mapping fails, make sure we don't leave a dandling
		   heap in kernel space -- remove it. */
		XENOMAI_SKINCALL1(__native_muxid, __native_heap_delete, &ph);
	return err;
}

int rt_heap_bind(RT_HEAP *heap, const char *name, RTIME timeout)
{
	RT_HEAP_PLACEHOLDER ph;
	int err;

	err = XENOMAI_SKINCALL3(__native_muxid,
				__native_heap_bind, &ph, name, &timeout);

	return err ? : __map_heap_memory(heap, &ph);
}

int rt_heap_unbind(RT_HEAP *heap)
{
	int err = munmap(heap->mapbase, heap->mapsize);

	if (err == -1)
		err = -errno;

	heap->opaque = XN_NO_HANDLE;
	heap->mapbase = NULL;
	heap->mapsize = 0;

	return err;
}

int rt_heap_delete(RT_HEAP *heap)
{
	int err;

	err = munmap(heap->mapbase, heap->mapsize);

	if (err == -1)
		err = -errno;

	if (!err)
		err =
		    XENOMAI_SKINCALL1(__native_muxid, __native_heap_delete,
				      heap);

	/* If the deletion fails, there is likely something fishy about
	   this heap descriptor, so we'd better clean it up anyway so
	   that it could not be further used. */

	heap->opaque = XN_NO_HANDLE;
	heap->mapbase = NULL;
	heap->mapsize = 0;

	return err;
}

int rt_heap_alloc(RT_HEAP *heap, size_t size, RTIME timeout, void **bufp)
{
	return XENOMAI_SKINCALL4(__native_muxid,
				 __native_heap_alloc, heap, size, &timeout,
				 bufp);
}

int rt_heap_free(RT_HEAP *heap, void *buf)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_heap_free, heap, buf);
}

int rt_heap_inquire(RT_HEAP *heap, RT_HEAP_INFO *info)
{
	return XENOMAI_SKINCALL2(__native_muxid, __native_heap_inquire, heap,
				 info);
}
