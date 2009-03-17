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

ER cre_sem(ID semid, T_CSEM *pk_csem)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_cre_sem,
				 semid, pk_csem);
}

ER del_sem(ID semid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_del_sem, semid);
}

ER sig_sem(ID semid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_sig_sem, semid);
}

ER wai_sem(ID semid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_wai_sem, semid);
}

ER preq_sem(ID semid)
{
	return XENOMAI_SKINCALL1(__uitron_muxid, __uitron_preq_sem, semid);
}

ER twai_sem(ID semid, TMO tmout)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_twai_sem,
				 semid, tmout);
}

ER ref_sem(T_RSEM *pk_rsem, ID semid)
{
	return XENOMAI_SKINCALL2(__uitron_muxid, __uitron_ref_sem,
				 pk_rsem, semid);
}
