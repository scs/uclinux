/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _RTAI_XENO_MEM_MGR_H
#define _RTAI_XENO_MEM_MGR_H

#include <nucleus/heap.h>


#define rt_alloc(size)	xnheap_alloc(&kheap,size)
#define rt_free(ptr)	xnheap_free(&kheap,ptr)

/*
 * TODO: 
extern void display_chunk(void *addr);
extern int rt_mem_init(void);
extern void rt_mem_end(void);
extern void rt_mmgr_stats(void);
*/


#endif /* !_RTAI_XENO_MEM_MGR_H */
