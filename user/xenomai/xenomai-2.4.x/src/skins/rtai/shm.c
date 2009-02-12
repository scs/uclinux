/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2005 Nextream France S.A.
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
#include <rtai/syscall.h>
#include <rtai/task.h>
#include <rtai/shm.h>

extern int __rtai_muxid;

static void *__map_shm_heap_memory(unsigned long opaque, int mapsize)
{
	int err, heapfd;
	void *mapbase = 0;

	/* Open the heap device to share the heap memory with the
	   in-kernel skin and bound clients. */
	heapfd = open(XNHEAP_DEV_NAME, O_RDWR);

	if (heapfd < 0)
		return 0;

	/* Bind this file instance to the shared heap. */
	err = ioctl(heapfd, 0, opaque);

	if (err)
		goto close_and_exit;

	/* Map the heap memory into our address space. */
	mapbase = (caddr_t) mmap(NULL,
				 mapsize,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED, heapfd, 0L);
	if (mapbase == MAP_FAILED)
		mapbase = 0;

      close_and_exit:

	close(heapfd);

	return mapbase;
}

#if 0

static int __unmap_shm_heap_memory(unsigned long opaque, void *mapbase,
				   int mapsize)
{
	int err, heapfd;

	/* Open the heap device to share the heap memory with the
	   in-kernel skin and bound clients. */
	heapfd = open(XNHEAP_DEV_NAME, O_RDWR);

	if (heapfd < 0)
		return 0;

	/* Bind this file instance to the shared heap. */
	err = ioctl(heapfd, 0, opaque);

	if (err)
		goto close_and_exit;

	err = munmap(mapbase, mapsize);

      close_and_exit:

	close(heapfd);

	return err;
}

#endif

static void *_compat_shm_alloc(unsigned long name, int size, int suprt,
			       int isheap)
{
	void *addr;
	unsigned long opaque;
	unsigned long off;

	int err;

	err = XENOMAI_SKINCALL5(__rtai_muxid,
				__rtai_shm_heap_open,
				name, &size, suprt, !isheap, &off);
	if (err == 0)
		return NULL;

	opaque = err;

	/* TODO: if (!isheap) map_once_gobal_heap and fix_addr otherwise else */

	if ((addr = __map_shm_heap_memory(opaque, size)) == 0) {
		XENOMAI_SKINCALL1(__rtai_muxid, __rtai_shm_heap_close, name);
		return NULL;
	}

	addr += off;

	/* TODO: if (isheap) ioctl(shmfd, HEAP_SET, &arg); */

	return addr;
}

void *rt_heap_open(unsigned long name, int size, int suprt)
{
	return _compat_shm_alloc(name, size, suprt, 1);
}

void *rt_shm_alloc(unsigned long name, int size, int suprt)
{
	return _compat_shm_alloc(name, size, suprt, 0);
}

int rt_shm_free(unsigned long name)
{
#if 0
	/* TODO: make kernel side return user opaque,mapbase,mapsize
	 * so __unmap_shm_heap_memory (opaque, mapbase, mapsize) can be called
	 */
#endif

	/*
	 * returns size
	 */
	return XENOMAI_SKINCALL1(__rtai_muxid, __rtai_shm_heap_close, name);
}
