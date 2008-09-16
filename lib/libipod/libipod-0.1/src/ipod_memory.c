/*
 * ipod_memory.c
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

#include <ipod/ipod_memory.h>
#include <ipod/ipod_error.h>
#include <stdio.h>

static unsigned long ipod_memory_allocs = 0;
static unsigned long ipod_memory_frees = 0;

static ipod_memory_alloc_func g_ipod_memory_alloc_func = 0;
static ipod_memory_realloc_func g_ipod_memory_realloc_func = 0;
static ipod_memory_free_func g_ipod_memory_free_func = 0;
static void *g_ipod_memory_user_data = 0;

extern void ipod_memory_set_funcs(
		ipod_memory_alloc_func alloc_func,
		ipod_memory_realloc_func realloc_func,
		ipod_memory_free_func free_func,
		void *userData)
{
	g_ipod_memory_alloc_func = alloc_func;
	g_ipod_memory_realloc_func = realloc_func;
	g_ipod_memory_free_func = free_func;
	g_ipod_memory_user_data = userData;
}



void *ipod_memory_alloc(size_t size)
{
	void *a;
	if (g_ipod_memory_alloc_func)
		a = (g_ipod_memory_alloc_func)(size,g_ipod_memory_user_data);
	else
		a = malloc(size);
	if (a) ipod_memory_allocs++;
	return a;

}
void *ipod_memory_realloc(void *p,size_t size)
{
	if (p) ipod_memory_frees++;
	if (g_ipod_memory_realloc_func)
		p = (g_ipod_memory_realloc_func)(p,size,g_ipod_memory_user_data);
	else
		p = realloc(p,size);
	if (p) ipod_memory_allocs++;
	return p;
}

void ipod_memory_free(void *p)
{
	if (p) ipod_memory_frees++;
	if (g_ipod_memory_free_func)
		(g_ipod_memory_free_func)(p,g_ipod_memory_user_data);
	else
		free(p);
}

void ipod_memory_report(void)
{
	ipod_error("ipod_memory_report(): allocs %lu frees %lu delta %ld\n",
		(long)ipod_memory_allocs,(long)ipod_memory_frees,
		ipod_memory_allocs-ipod_memory_frees);
}
