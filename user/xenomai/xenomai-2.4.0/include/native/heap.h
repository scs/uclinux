/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
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

#ifndef _XENO_HEAP_H
#define _XENO_HEAP_H

#include <nucleus/synch.h>
#include <nucleus/heap.h>
#include <native/types.h>

/* Creation flags. */
#define H_PRIO     XNSYNCH_PRIO	/* Pend by task priority order. */
#define H_FIFO     XNSYNCH_FIFO	/* Pend by FIFO order. */
#define H_DMA      0x100	/* Use memory suitable for DMA. */
#define H_MAPPABLE 0x200	/* Memory is mappable to user-space. */
#define H_SINGLE   0x400	/* Manage as single-block area. */
#define H_SHARED   (H_MAPPABLE|H_SINGLE) /* I.e. shared memory segment. */

typedef struct rt_heap_info {

    int nwaiters;		/* !< Number of pending tasks. */

    int mode;			/* !< Creation mode. */

    size_t heapsize;		/* !< Requested heap size. */

    size_t usablemem;		/* !< Available heap memory. */

    size_t usedmem;		/* !< Amount of memory used. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

} RT_HEAP_INFO;

typedef struct rt_heap_placeholder {

    xnhandle_t opaque;

    void *opaque2;

    caddr_t mapbase;

    size_t mapsize;

} RT_HEAP_PLACEHOLDER;

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <native/ppd.h>

#define XENO_HEAP_MAGIC 0x55550808

typedef struct rt_heap {

    unsigned magic;   /* !< Magic code - must be first */

    xnsynch_t synch_base; /* !< Base synchronization object. */

    xnheap_t heap_base;	/* !< Internal heap object. */

    int mode;		/* !< Creation mode. */

    size_t csize;	/* !< Original size at creation. */

    void *sba;		/* !< Single block ara (H_SINGLE only) */

    xnhandle_t handle;	/* !< Handle in registry -- zero if unregistered. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    pid_t cpid;			/* !< Creator's pid. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2heap(ln)		container_of(ln, RT_HEAP, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} RT_HEAP;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_XENO_OPT_NATIVE_HEAP

int __native_heap_pkg_init(void);

void __native_heap_pkg_cleanup(void);

static inline void __native_heap_flush_rq(xnqueue_t *rq)
{
	xeno_flush_rq(RT_HEAP, rq, heap);
}

#else /* !CONFIG_XENO_OPT_NATIVE_HEAP */

#define __native_heap_pkg_init()		({ 0; })
#define __native_heap_pkg_cleanup()		do { } while(0)
#define __native_heap_flush_rq(rq)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_NATIVE_HEAP */

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef RT_HEAP_PLACEHOLDER RT_HEAP;

#ifdef __cplusplus
extern "C" {
#endif

int rt_heap_bind(RT_HEAP *heap,
		 const char *name,
		 RTIME timeout);

int rt_heap_unbind(RT_HEAP *heap);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface. */

int rt_heap_create(RT_HEAP *heap,
		   const char *name,
		   size_t heapsize,
		   int mode);

int rt_heap_delete(RT_HEAP *heap);

int rt_heap_alloc(RT_HEAP *heap,
		  size_t size,
		  RTIME timeout,
		  void **blockp);

int rt_heap_free(RT_HEAP *heap,
		 void *block);

int rt_heap_inquire(RT_HEAP *heap,
		    RT_HEAP_INFO *info);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_HEAP_H */
