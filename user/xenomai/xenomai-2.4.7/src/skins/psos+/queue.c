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

#include <psos+/psos.h>

extern int __psos_muxid;

u_long q_create(const char *name, u_long maxnum, u_long flags, u_long *qid_r)
{
	return XENOMAI_SKINCALL4(__psos_muxid, __psos_q_create,
				 name, maxnum, flags, qid_r);
}

u_long q_delete(u_long qid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_q_delete, qid);
}

u_long q_ident(const char *name, u_long nodeno, u_long *qid_r)
{
	return XENOMAI_SKINCALL2(__psos_muxid, __psos_q_ident, name, qid_r);
}

u_long q_receive(u_long qid, u_long flags, u_long timeout, u_long msgbuf_r[4])
{
	return XENOMAI_SKINCALL4(__psos_muxid, __psos_q_receive,
				 qid, flags, timeout, msgbuf_r);
}

u_long q_send(u_long qid, u_long msgbuf[4])
{
	return XENOMAI_SKINCALL2(__psos_muxid, __psos_q_send, qid, msgbuf);
}

u_long q_urgent(u_long qid, u_long msgbuf[4])
{
	return XENOMAI_SKINCALL2(__psos_muxid, __psos_q_urgent, qid, msgbuf);
}

u_long q_broadcast(u_long qid, u_long msgbuf[4], u_long *count_r)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_q_broadcast, qid,
				 msgbuf, count_r);
}

u_long q_vcreate(const char *name, u_long flags, u_long maxnum,
		 u_long maxlen, u_long *qid_r)
{
	return XENOMAI_SKINCALL5(__psos_muxid, __psos_q_vcreate,
				 name, maxnum, maxlen, flags, qid_r);
}

u_long q_vdelete(u_long qid)
{
	return XENOMAI_SKINCALL1(__psos_muxid, __psos_q_vdelete, qid);
}

u_long q_vident(const char *name, u_long node, u_long *qid_r)
{
	return XENOMAI_SKINCALL2(__psos_muxid, __psos_q_vident, name, qid_r);
}

u_long q_vreceive(u_long qid, u_long flags, u_long timeout,
		  void *msgbuf_r, u_long buflen, u_long *msglen_r)
{
	struct {
		u_long flags;
		u_long timeout;
	} modifiers;	/* Combine to fit into available arg space (i.e. 5) */
	return XENOMAI_SKINCALL5(__psos_muxid, __psos_q_vreceive,
				 qid, &modifiers, msgbuf_r, buflen, msglen_r);
}

u_long q_vsend(u_long qid, void *msgbuf, u_long msglen)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_q_vsend, qid,
				 msgbuf, msglen);
}

u_long q_vurgent(u_long qid, void *msgbuf, u_long msglen)
{
	return XENOMAI_SKINCALL3(__psos_muxid, __psos_q_vurgent, qid,
				 msgbuf, msglen);
}

u_long q_vbroadcast(u_long qid, void *msgbuf, u_long msglen,
		    u_long *count_r)
{
	return XENOMAI_SKINCALL4(__psos_muxid, __psos_q_vbroadcast, qid,
				 msgbuf, msglen, count_r);
}
