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
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <vrtx/vrtx.h>
#include <asm-generic/bits/bind.h>
#include <asm-generic/bits/mlock_alert.h>

pthread_key_t __vrtx_tskey;

int __vrtx_muxid = -1;

static void __flush_tsd(void *tsd)
{
	/* Free the TCB struct. */
	free(tsd);
}

static __attribute__ ((constructor))
void __init_xeno_interface(void)
{
	TCB *tcb;

	__vrtx_muxid =
	    xeno_bind_skin(VRTX_SKIN_MAGIC, "vrtx", "xeno_vrtx");
	__vrtx_muxid = __xn_mux_shifted_id(__vrtx_muxid);

	/* Allocate a TSD key for indexing self task pointers. */

	if (pthread_key_create(&__vrtx_tskey, &__flush_tsd) != 0) {
		fprintf(stderr, "Xenomai: failed to allocate new TSD key?!\n");
		exit(1);
	}

	tcb = (TCB *) malloc(sizeof(*tcb));

	if (!tcb) {
		fprintf(stderr, "Xenomai: failed to allocate local TCB?!\n");
		exit(1);
	}

	pthread_setspecific(__vrtx_tskey, tcb);
}
