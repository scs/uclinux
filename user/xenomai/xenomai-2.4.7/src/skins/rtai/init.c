/*
 * Copyright (C) 2001-2005 Philippe Gerum <rpm@xenomai.org>.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rtai/syscall.h>
#include <asm-generic/bits/bind.h>
#include <asm-generic/bits/mlock_alert.h>

int __rtai_muxid = -1;

static __attribute__ ((constructor))
void __init_rtai_interface(void)
{
	__rtai_muxid = xeno_bind_skin(RTAI_SKIN_MAGIC, "RTAI", "xeno_rtai");
	__rtai_muxid = __xn_mux_shifted_id(__rtai_muxid);
}
