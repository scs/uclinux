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

#ifndef _XENO_QUEUE_H
#define _XENO_QUEUE_H

#include <nucleus/synch.h>
#include <nucleus/heap.h>
#include <native/types.h>

/* Creation flags. */
#define Q_PRIO   XNSYNCH_PRIO	/* Pend by task priority order. */
#define Q_FIFO   XNSYNCH_FIFO	/* Pend by FIFO order. */
#define Q_DMA    0x100		/* Use memory suitable for DMA. */
#define Q_SHARED 0x200		/* Use mappable shared memory. */

#define Q_UNLIMITED 0		/* No size limit. */

/* Operation flags. */
#define Q_NORMAL     0x0
#define Q_URGENT     0x1
#define Q_BROADCAST  0x2

typedef struct rt_queue_info {

    int nwaiters;		/* !< Number of pending tasks. */

    int nmessages;		/* !< Number of queued messages. */

    int mode;			/* !< Creation mode. */

    size_t qlimit;		/* !< Queue limit. */

    size_t poolsize;		/* !< Size of pool memory (in bytes). */

    size_t usedmem;		/* !< Amount of pool memory used (in bytes). */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

} RT_QUEUE_INFO;

typedef struct rt_queue_placeholder {

    xnhandle_t opaque;

    void *opaque2;

    caddr_t mapbase;

    size_t mapsize;

} RT_QUEUE_PLACEHOLDER;

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <native/ppd.h>

#define XENO_QUEUE_MAGIC 0x55550707

typedef struct rt_queue {

    unsigned magic;   /* !< Magic code - must be first */

    xnsynch_t synch_base; /* !< Base synchronization object. */

    xnqueue_t pendq;	/* !< Pending message queue. */

    xnheap_t bufpool;	/* !< Message buffer pool. */

    int mode;		/* !< Creation mode. */

    xnhandle_t handle;	/* !< Handle in registry -- zero if unregistered. */

    int qlimit;		/* !< Maximum queued elements. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    pid_t cpid;			/* !< Creator's pid. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2queue(ln)	container_of(ln, RT_QUEUE, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} RT_QUEUE;

typedef struct rt_queue_msg {

    size_t size;

    volatile unsigned refcount;

    xnholder_t link;

#define link2rtmsg(ln)		container_of(ln, rt_queue_msg_t, link)

} rt_queue_msg_t;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_XENO_OPT_NATIVE_QUEUE

int __native_queue_pkg_init(void);

void __native_queue_pkg_cleanup(void);

static inline void __native_queue_flush_rq(xnqueue_t *rq)
{
	xeno_flush_rq(RT_QUEUE, rq, queue);
}

#else /* !CONFIG_XENO_OPT_NATIVE_QUEUE */

#define __native_queue_pkg_init()		({ 0; })
#define __native_queue_pkg_cleanup()		do { } while(0)
#define __native_queue_flush_rq(rq)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_NATIVE_QUEUE */

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef RT_QUEUE_PLACEHOLDER RT_QUEUE;

#ifdef __cplusplus
extern "C" {
#endif

int rt_queue_bind(RT_QUEUE *q,
		  const char *name,
		  RTIME timeout);

int rt_queue_unbind(RT_QUEUE *q);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface. */

int rt_queue_create(RT_QUEUE *q,
		    const char *name,
		    size_t poolsize,
		    size_t qlimit,
		    int mode);

int rt_queue_delete(RT_QUEUE *q);

void *rt_queue_alloc(RT_QUEUE *q,
		     size_t size);

int rt_queue_free(RT_QUEUE *q,
		  void *buf);

int rt_queue_send(RT_QUEUE *q,
		  void *buf,
		  size_t size,
		  int mode);

int rt_queue_write(RT_QUEUE *q,
		   const void *buf,
		   size_t size,
		   int mode);

ssize_t rt_queue_receive(RT_QUEUE *q,
			 void **bufp,
			 RTIME timeout);

static inline ssize_t __deprecated_call__ rt_queue_recv(RT_QUEUE *q,
							void **bufp,
							RTIME timeout)
{
    return rt_queue_receive(q,bufp,timeout);
}

ssize_t rt_queue_read(RT_QUEUE *q,
		      void *bufp,
		      size_t size,
		      RTIME timeout);

int rt_queue_inquire(RT_QUEUE *q,
		     RT_QUEUE_INFO *info);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_QUEUE_H */
