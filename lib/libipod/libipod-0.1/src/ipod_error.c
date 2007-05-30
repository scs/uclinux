/*
 * ipod_error.c
 *
 * Duane Maxwell
 * (c) 2005 by Linspire Inc
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#include <ipod/ipod_error.h>
#include <stdio.h>

static ipod_error_func g_ipod_error_func;
static void *g_ipod_error_user_data;

void ipod_error(const char *fmt,...)
{
	va_list argp;
	
	va_start(argp,fmt);
	if (g_ipod_error_func)
		(g_ipod_error_func)(g_ipod_error_user_data,fmt,argp);
	else
		vfprintf(stderr,fmt,argp);
	va_end(argp);
}

void ipod_error_set_func(ipod_error_func func, void *userData)
{
	g_ipod_error_func = func;
	g_ipod_error_user_data = userData;
}
