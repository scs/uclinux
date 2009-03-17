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

#include <malloc.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <vxworks/vxworks.h>
#include <asm-generic/bits/bind.h>
#include <asm-generic/bits/mlock_alert.h>

pthread_key_t __vxworks_tskey;

int __vxworks_muxid = -1;

static void __flush_tsd(void *tsd)
{
	/* Free the task descriptor allocated by taskIdSelf(). */
	free(tsd);
}

static __attribute__ ((constructor))
void __init_xeno_interface(void)
{
	__vxworks_muxid = xeno_bind_skin(VXWORKS_SKIN_MAGIC,
					 "vxworks", "xeno_vxworks");
	__vxworks_muxid = __xn_mux_shifted_id(__vxworks_muxid);

	/* Allocate a TSD key for indexing self task pointers. */

	if (pthread_key_create(&__vxworks_tskey, &__flush_tsd) != 0) {
		fprintf(stderr, "Xenomai: failed to allocate new TSD key?!\n");
		exit(1);
	}
}
