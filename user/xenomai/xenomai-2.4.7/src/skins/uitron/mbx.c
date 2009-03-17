/*
 * Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org>.
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

#include <uitron/uitron.h>

extern int __uitron_muxid;

ER cre_mbx(ID mbxid, T_CMBX *pk_cmbx)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_cre_mbx,
				 mbxid, pk_cmbx);
}

ER del_mbx(ID mbxid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_del_mbx, mbxid);
}

ER snd_msg(ID mbxid, T_MSG *pk_msg)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_snd_msg,
				 mbxid, pk_msg);
}

ER rcv_msg(T_MSG **ppk_msg, ID mbxid)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_rcv_msg,
				 ppk_msg, mbxid);
}

ER prcv_msg(T_MSG **ppk_msg, ID mbxid)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_prcv_msg,
				 ppk_msg, mbxid);
}

ER trcv_msg(T_MSG **ppk_msg, ID mbxid, TMO tmout)
{
	return XENOMAI_SKINCALL3(__uitron_muxid, __uitron_trcv_msg,
				 ppk_msg, mbxid, tmout);
}

ER ref_mbx(T_RMBX *pk_rmbx, ID mbxid)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_ref_mbx,
				 pk_rmbx, mbxid);
}
