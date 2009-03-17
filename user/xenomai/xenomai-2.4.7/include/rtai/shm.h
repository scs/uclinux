/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _RTAI_SHM_H
#define _RTAI_SHM_H

#include <nucleus/heap.h>
#include <rtai/types.h>
#include <rtai/shm.h>
#include <rtai/rtai_nam2num.h>

#define USE_VMALLOC     0
#define USE_GFP_KERNEL  1
#define USE_GFP_ATOMIC  2
#define USE_GFP_DMA     3

#define rtai_kmalloc(name, size) \
	rt_shm_alloc(name, size, USE_VMALLOC)  // legacy

#define rtai_kfree(name) \
	rt_shm_free(name)  // legacy

#define rt_heap_close(name, adr)  \
	rt_shm_free(name)


#if defined(__KERNEL__) || defined(__XENO_SIM__)

#ifdef __cplusplus
extern "C" {
#endif

int __rtai_shm_pkg_init(void);

void __rtai_shm_pkg_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

void *rt_heap_open(unsigned long name,
		   int size,
		   int suprt);

void *rt_shm_alloc(unsigned long name,
		   int size,
		   int suprt);

int rt_shm_free(unsigned long name);


#ifdef __cplusplus
}
#endif

#endif /* !_RTAI_SHM_H */
