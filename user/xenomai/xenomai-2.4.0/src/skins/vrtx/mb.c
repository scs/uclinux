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

#include <vrtx/vrtx.h>

extern int __vrtx_muxid;

void sc_post(char **mboxp, char *msg, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_post, mboxp, msg);
}

char *sc_accept(char **mboxp, int *errp)
{
	char *msg = NULL;

	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_accept, mboxp, &msg);
	return msg;
}

char *sc_pend(char **mboxp, long timeout, int *errp)
{
	char *msg = NULL;

	*errp = XENOMAI_SKINCALL3(__vrtx_muxid,
				  __vrtx_pend, mboxp, timeout, &msg);
	return msg;
}
