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

int sc_qecreate(int qid, int qsize, int opt, int *errp)
{
	int qid_r = -1;

	*errp = XENOMAI_SKINCALL4(__vrtx_muxid,
				  __vrtx_qecreate, qid, qsize, opt, &qid_r);
	return qid_r;
}

int sc_qcreate(int qid, int qsize, int *errp)
{
	return sc_qecreate(qid, qsize, 1, errp);
}

void sc_qdelete(int qid, int opt, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_qdelete, qid, opt);
}

void sc_qpost(int qid, char *msg, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_qpost, qid, msg);
}

void sc_qjam(int qid, char *msg, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_qjam, qid, msg);
}

void sc_qbrdcst(int qid, char *msg, int *errp)
{
	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_qbrdcst, qid, msg);
}

char *sc_qpend(int qid, long timeout, int *errp)
{
	char *msg_r = NULL;

	*errp = XENOMAI_SKINCALL3(__vrtx_muxid,
				  __vrtx_qpend, qid, timeout, &msg_r);
	return msg_r;
}

char *sc_qaccept(int qid, int *errp)
{
	char *msg_r = NULL;

	*errp = XENOMAI_SKINCALL2(__vrtx_muxid, __vrtx_qaccept, qid, &msg_r);
	return msg_r;
}

char *sc_qinquiry(int qid, int *countp, int *errp)
{
	char *msg_r = NULL;

	*errp = XENOMAI_SKINCALL3(__vrtx_muxid,
				  __vrtx_qinquiry, qid, countp, &msg_r);
	return msg_r;
}
