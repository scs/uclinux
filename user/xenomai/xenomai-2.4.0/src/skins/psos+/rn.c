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
#include <psos+/psos.h>

extern int __psos_muxid;

struct rninfo {
	u_long rnid;
	u_long allocsz;
	void *rncb;
	u_long mapsize;
};

static int __map_heap_memory(const struct rninfo *rnip)
{
	int err = 0, rnfd;
	caddr_t mapbase;

	/* Open the heap device to share the region memory with the
	   in-kernel skin. */
	rnfd = open(XNHEAP_DEV_NAME, O_RDWR);

	if (rnfd < 0)
		return -ENOENT;

	/* Bind this file instance to the shared heap. */
	err = ioctl(rnfd, 0, rnip->rncb);

	if (err)
		goto close_and_exit;

	/* Map the region memory into our address space. */
	mapbase = (caddr_t) mmap(NULL,
				 rnip->mapsize,
				 PROT_READ | PROT_WRITE,
				 MAP_SHARED, rnfd, 0L);

	if (mapbase == MAP_FAILED)
		err = -ENOMEM;
	else
		err =
		    XENOMAI_SKINCALL2(__psos_muxid, __psos_rn_bind, rnip->rnid,
				      mapbase);

      close_and_exit:

	close(rnfd);

	return err;
}

u_long rn_create(const char name[4],
		 void *rnaddr,
		 u_long rnsize,
		 u_long usize, u_long flags, u_long *rnid, u_long *allocsz)
{
	struct rninfo rninfo;
	struct {
		u_long rnsize;
		u_long usize;
		u_long flags;
	} sizeopt;
	u_long err;

	if (rnaddr)
		fprintf(stderr,
			"rn_create() - rnaddr parameter ignored from user-space context\n");

	sizeopt.rnsize = rnsize;
	sizeopt.usize = usize;
	sizeopt.flags = flags;

	err = XENOMAI_SKINCALL3(__psos_muxid,
				__psos_rn_create, name, &sizeopt, &rninfo);
	if (err)
		return err;

	err = __map_heap_memory(&rninfo);

	if (err) {
		/* If the mapping fails, make sure we don't leave a dandling
		   heap in kernel space -- remove it. */
		XENOMAI_SKINCALL1(__psos_muxid, __psos_rn_delete, rninfo.rnid);
		return err;
	}

	*rnid = rninfo.rnid;
	*allocsz = rninfo.allocsz;

	return SUCCESS;
}

u_long rn_delete(u_long rnid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_rn_delete, rnid);
}

u_long rn_getseg(u_long rnid,
		 u_long size, u_long flags, u_long timeout, void **segaddr)
{
	return XENOMAI_SKINCALL5(__psos_muxid, __psos_rn_getseg,
				 rnid, size, flags, timeout, segaddr);
}

u_long rn_retseg(u_long rnid, void *chunk)
{
	return XENOMAI_SKINCALL2(__psos_muxid, __psos_rn_retseg,
				 rnid, chunk);
}

u_long rn_ident(const char name[4], u_long *rnid_r)
{
	return XENOMAI_SKINCALL2(__psos_muxid, __psos_rn_ident, name, rnid_r);
}
