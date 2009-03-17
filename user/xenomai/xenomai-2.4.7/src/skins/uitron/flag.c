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

ER cre_flg(ID flgid, T_CFLG *pk_cflg)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_cre_flg,
				 flgid, pk_cflg);
}

ER del_flg(ID flgid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_del_flg, flgid);
}

ER set_flg(ID flgid, UINT setptn)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_set_flg,
				 flgid, setptn);
}

ER clr_flg(ID flgid, UINT clrptn)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_clr_flg,
				 flgid, clrptn);
}

ER wai_flg(UINT *p_flgptn, ID flgid, UINT waiptn, UINT wfmode)
{
	return XENOMAI_SKINCALL4(__uitron_muxid, __uitron_wai_flg,
				 p_flgptn, flgid, waiptn, wfmode);
}

ER pol_flg(UINT *p_flgptn, ID flgid, UINT waiptn, UINT wfmode)
{
	return XENOMAI_SKINCALL4(__uitron_muxid, __uitron_pol_flg,
				 p_flgptn, flgid, waiptn, wfmode);
}

ER twai_flg(UINT *p_flgptn, ID flgid, UINT waiptn, UINT wfmode, TMO tmout)
{
	return XENOMAI_SKINCALL5(__uitron_muxid, __uitron_twai_flg,
				 p_flgptn, flgid, waiptn, wfmode, tmout);
}

ER ref_flg(T_RFLG *pk_rflg, ID flgid)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_ref_flg,
				 pk_rflg, flgid);
}
