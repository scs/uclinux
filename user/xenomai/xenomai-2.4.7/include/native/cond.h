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

#ifndef _XENO_COND_H
#define _XENO_COND_H

#include <native/mutex.h>

typedef struct rt_cond_info {

    int nwaiters;	/* !< Number of pending tasks. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

} RT_COND_INFO;

typedef struct rt_cond_placeholder {

    xnhandle_t opaque;

} RT_COND_PLACEHOLDER;

#if (defined(__KERNEL__) || defined(__XENO_SIM__)) && !defined(DOXYGEN_CPP)

#include <nucleus/synch.h>
#include <native/ppd.h>

#define XENO_COND_MAGIC 0x55550606

typedef struct rt_cond {

    unsigned magic;   /* !< Magic code - must be first */

    xnsynch_t synch_base; /* !< Base synchronization object. */

    xnhandle_t handle;	/* !< Handle in registry -- zero if unregistered. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    pid_t cpid;			/* !< Creator's pid. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2cond(ln)		container_of(ln, RT_COND, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} RT_COND;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_XENO_OPT_NATIVE_COND

int __native_cond_pkg_init(void);

void __native_cond_pkg_cleanup(void);

static inline void __native_cond_flush_rq(xnqueue_t *rq)
{
	xeno_flush_rq(RT_COND, rq, cond);
}

#else /* !CONFIG_XENO_OPT_NATIVE_COND */

#define __native_cond_pkg_init()		({ 0; })
#define __native_cond_pkg_cleanup()		do { } while(0)
#define __native_cond_flush_rq(rq)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_NATIVE_COND */

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef RT_COND_PLACEHOLDER RT_COND;

#ifdef __cplusplus
extern "C" {
#endif

int rt_cond_bind(RT_COND *cond,
		 const char *name,
		 RTIME timeout);

static inline int rt_cond_unbind (RT_COND *cond)

{
    cond->opaque = XN_NO_HANDLE;
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

int rt_cond_create(RT_COND *cond,
		   const char *name);

int rt_cond_delete(RT_COND *cond);

int rt_cond_signal(RT_COND *cond);

int rt_cond_broadcast(RT_COND *cond);

int rt_cond_wait(RT_COND *cond,
		 RT_MUTEX *mutex,
		 RTIME timeout);

int rt_cond_inquire(RT_COND *cond,
		    RT_COND_INFO *info);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_COND_H */
