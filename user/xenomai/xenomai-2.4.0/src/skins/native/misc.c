/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#include <native/syscall.h>
#include <native/misc.h>

extern int __native_muxid;

int rt_io_get_region(RT_IOREGION *iorn, const char *name,
		     uint64_t start, uint64_t len, int flags)
{
	return XENOMAI_SKINCALL5(__native_muxid,
				 __native_io_get_region, iorn, name,
				 &start, &len, flags);
}

int rt_io_put_region(RT_IOREGION *iorn)
{
	return XENOMAI_SKINCALL1(__native_muxid,
				 __native_io_put_region, iorn);
}
