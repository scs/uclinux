/*
 * Copyright (C) 2006 Philippe Gerum <rpm@xenomai.org>.
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
#include <stdio.h>
#include <nucleus/heap.h>
#include <vrtx/vrtx.h>

extern int __vrtx_muxid;

static int __map_heap_memory(const vrtx_hdesc_t *hdesc)
{
	int err = 0, heapfd;
	caddr_t mapbase;

	/* Open the heap device to share the heap memory with the
	   in-kernel skin. */
	heapfd = open(XNHEAP_DEV_NAME, O_RDWR);

	if (heapfd < 0)
		return -ENOENT;

	/* Bind this file instance to the shared heap. */
	err = ioctl(heapfd, 0, hdesc->hcb);

	if (err)
		goto close_and_exit;

	/* Map the heap memory into our address space. */
	mapbase = (caddr_t) mmap(NULL,
				 hdesc->hsize,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED, heapfd, 0L);

	if (mapbase == MAP_FAILED)
		err = -ENOMEM;
	else
		err =
		    XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_hbind, hdesc->hid,
				      mapbase);

      close_and_exit:

	close(heapfd);

	return err;
}

int sc_hcreate(char *heapaddr,
	       unsigned long heapsize, unsigned log2psize, int *errp)
{
	vrtx_hdesc_t hdesc;
	int hid;

	if (heapaddr)
		fprintf(stderr,
			"sc_hcreate() - heapaddr parameter ignored from user-space context\n");

	*errp = XENOMAI_SKINCALL3(__vrtx_muxid,
				  __vrtx_hcreate, heapsize, log2psize, &hdesc);
	if (*errp)
		return 0;

	hid = hdesc.hid;
	*errp = __map_heap_memory(&hdesc);

	if (*errp)
		/* If the mapping fails, make sure we don't leave a dandling
		   heap in kernel space -- remove it. */
		XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_hdelete, hid, 1);

	return hid;
}

void sc_hdelete(int hid, int opt, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_hdelete, hid, opt);
}

char *sc_halloc(int hid, unsigned long size, int *errp)
{
	char *buf = NULL;
	*errp = XENOMAI_SKINCALL3(__vrtx_muxid, __vrtx_halloc, hid, size, &buf);
	return buf;
}

void sc_hfree(int hid, char *buf, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_hfree, hid, buf);
}

void sc_hinquiry(int info[3], int hid, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_hinquiry, info, hid);
}
