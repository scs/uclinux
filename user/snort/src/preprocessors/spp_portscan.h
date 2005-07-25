/* $Id$ */
/*
** Copyright (C) 1998-2002 Martin Roesch <roesch@sourcefire.com>
** Copyright (C) 1999,2000,2001 Patrick Mullen <p_mullen@hotmail.com>
** 
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
** 
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
** 
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

/* Snort Portscan Preprocessor Plugin
   by Patrick Mullen <p_mullen@hotmail.com>
*/

/* This file gets included in plugbase.h when it is integrated into the rest 
 * of the program.  Sometime in The Future, I'll whip up a bad ass Perl script
 * to handle automatically loading all the required info into the plugbase.*
 * files.
 */
//#include "snort.h"
#ifndef __SPP_PORTSCAN_H__
#define __SPP_PORTSCAN_H__

void SetupPortscan();
void SetupPortscanIgnoreHosts(void);

#endif  /* __SPP_PORTSCAN_H__ */
