/*********************************************************************
 *
 * Filename:      win32compat.c
 * Version:       0.5
 * Description:   Functions used only by win32
 * Status:        Experimental.
 * Author:        Pontus Fuchs <pontus.fuchs@tactel.se>
 * Created at:    Sun Aug 06 10:22:00 2000
 * CVS ID:        $Id: win32compat.c,v 1.6 2002/10/28 21:51:18 holtmann Exp $
 *
 *     Copyright (c) 2000 Pontus Fuchs, All Rights Reserved.
 *
 *     This library is free software; you can redistribute it and/or
 *     modify it under the terms of the GNU Lesser General Public
 *     License as published by the Free Software Foundation; either
 *     version 2 of the License, or (at your option) any later version.
 *
 *     This library is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *     Lesser General Public License for more details.
 *
 *     You should have received a copy of the GNU Lesser General Public
 *     License along with this library; if not, write to the Free Software
 *     Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 *     MA  02111-1307  USA
 *
 ********************************************************************/

#include "config.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>

#include "obex_main.h"

// The VC proprocessor can't handle variable argument macros,
// so we are forced to do an ugly thing like this.

#ifdef OBEX_DEBUG
extern obex_debug;

void DEBUG(unsigned int n, const char *format, void *a1, void *a2, void *a3, void *a4, 
		void *a5, void *a6, void *a7, void *a8, void *a9, void *a10)
{
	if(n <= obex_debug)
		fprintf(stderr, format, a1,a2,a3,a4,a5,a6,a7,a8,a9,a10);
}
#else
void DEBUG(int n, const char *format, ...){};
#endif
