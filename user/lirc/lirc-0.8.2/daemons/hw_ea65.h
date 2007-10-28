/*
 * Support for builtin key panel and remote control on
 *      AOpen XC Cube EA65, EA65-II
 * 
 * Copyright (C) 2004 Max Krasnyansky <maxk@qualcomm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * $Id: hw_ea65.h,v 5.1 2004/11/20 13:43:48 lirc Exp $
 */

#ifndef HW_EA65_H
#define HW_EA65_H

#include "drivers/lirc.h"

int   ea65_decode(struct ir_remote *remote, ir_code *pre, ir_code *code,
		  ir_code *post, int *repeat, lirc_t *gapp);
int   ea65_init(void);
int   ea65_release(void);
char *ea65_receive(struct ir_remote *remote);

#endif
