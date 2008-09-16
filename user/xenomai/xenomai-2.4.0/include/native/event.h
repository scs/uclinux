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

#ifndef _XENO_EVENT_H
#define _XENO_EVENT_H

#include <nucleus/synch.h>
#include <native/types.h>

/* Creation flags. */
#define EV_PRIO  XNSYNCH_PRIO	/* Pend by task priority order. */
#define EV_FIFO  XNSYNCH_FIFO	/* Pend by FIFO order. */

/* Operation flags. */
#define EV_ANY  0x1	/* Disjunctive wait. */
#define EV_ALL  0x0	/* Conjunctive wait. */

typedef struct rt_event_info {

    unsigned long value; /* !< Current event group value. */

    int nwaiters;	/* !< Number of pending tasks. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

} RT_EVENT_INFO;

typedef struct rt_event_placeholder {
    xnhandle_t opaque;
} RT_EVENT_PLACEHOLDER;

#if (defined(__KERNEL__) || defined(__XENO_SIM__)) && !defined(DOXYGEN_CPP)

#include <native/ppd.h>

#define XENO_EVENT_MAGIC 0x55550404

typedef struct rt_event {

    unsigned magic;   /* !< Magic code - must be first */

    xnsynch_t synch_base; /* !< Base synchronization object. */

    unsigned long value; /* !< Event group value. */

    xnhandle_t handle;	/* !< Handle in registry -- zero if unregistered. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    pid_t cpid;			/* !< Creator's pid. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2event(ln)	container_of(ln, RT_EVENT, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} RT_EVENT;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_XENO_OPT_NATIVE_EVENT

int __native_event_pkg_init(void);

void __native_event_pkg_cleanup(void);

static inline void __native_event_flush_rq(xnqueue_t *rq)
{
	xeno_flush_rq(RT_EVENT, rq, event);
}

#else /* !CONFIG_XENO_OPT_NATIVE_EVENT */

#define __native_event_pkg_init()		({ 0; })
#define __native_event_pkg_cleanup()		do { } while(0)
#define __native_event_flush_rq(rq)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_NATIVE_EVENT */

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef RT_EVENT_PLACEHOLDER RT_EVENT;

#ifdef __cplusplus
extern "C" {
#endif

int rt_event_bind(RT_EVENT *event,
		  const char *name,
		  RTIME timeout);

static inline int rt_event_unbind (RT_EVENT *event)

{
    event->opaque = XN_NO_HANDLE;
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface. */

int rt_event_create(RT_EVENT *event,
		    const char *name,
		    unsigned long ivalue,
		    int mode);

int rt_event_delete(RT_EVENT *event);

int rt_event_signal(RT_EVENT *event,
		    unsigned long mask);

int rt_event_wait(RT_EVENT *event,
		  unsigned long mask,
		  unsigned long *mask_r,
		  int mode,
		  RTIME timeout);

int rt_event_clear(RT_EVENT *event,
		   unsigned long mask,
		   unsigned long *mask_r);

int rt_event_inquire(RT_EVENT *event,
		     RT_EVENT_INFO *info);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_EVENT_H */
