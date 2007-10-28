/****************************************************************************
 ** hw_bte.h ****************************************************************
 ****************************************************************************
 *
 *  routines for Ericsson mobile phone receiver (BTE)
 * 
 *  Copyright (C) 2003 Vadim Shliakhov <svadim@nm.ru>
 *
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *	
 */

#ifndef HW_BTE_H
#define HW_BTE_H

#include "drivers/lirc.h"

int bte_decode(struct ir_remote *remote,
	       ir_code *prep,ir_code *codep,ir_code *postp,
	       int *repeat_flagp,lirc_t *remaining_gapp);
int bte_init(void);
int bte_deinit(void);
char *bte_rec(struct ir_remote *remotes);
#endif
