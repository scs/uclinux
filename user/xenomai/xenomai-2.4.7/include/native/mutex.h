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

#ifndef _XENO_MUTEX_H
#define _XENO_MUTEX_H

#include <native/types.h>

struct rt_task;

/** Structure containing mutex information useful to users.
 *
 *  @see rt_mutex_inquire()
 */
typedef struct rt_mutex_info {

	int lockcnt;		/**< Lock nesting level (> 0 means "locked"). */

	int nwaiters;		/**< Number of pending tasks. */

	char name[XNOBJECT_NAME_LEN]; /**< Symbolic name. */

} RT_MUTEX_INFO;

typedef struct rt_mutex_placeholder {
	xnhandle_t opaque;
} RT_MUTEX_PLACEHOLDER;

#if (defined(__KERNEL__) || defined(__XENO_SIM__)) && !defined(DOXYGEN_CPP)

#include <nucleus/synch.h>
#include <native/ppd.h>

#define XENO_MUTEX_MAGIC 0x55550505

typedef struct __rt_mutex {

	unsigned magic;		/* !< Magic code - must be first */

	xnsynch_t synch_base;	/* !< Base synchronization object. */

	xnhandle_t handle;	/* !< Handle in registry -- zero if unregistered. */

	int lockcnt;		/* !< Lock nesting level (> 0 means "locked"). */
	
	char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
	pid_t cpid;		/* !< Creator's pid. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

	xnholder_t rlink;	/* !< Link in resource queue. */

#define rlink2mutex(ln)		container_of(ln, RT_MUTEX, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} RT_MUTEX;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_XENO_OPT_NATIVE_MUTEX

int __native_mutex_pkg_init(void);

void __native_mutex_pkg_cleanup(void);

static inline void __native_mutex_flush_rq(xnqueue_t *rq)
{
	xeno_flush_rq(RT_MUTEX, rq, mutex);
}

#else /* !CONFIG_XENO_OPT_NATIVE_MUTEX */

#define __native_mutex_pkg_init()		({ 0; })
#define __native_mutex_pkg_cleanup()		do { } while(0)
#define __native_mutex_flush_rq(rq)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_NATIVE_MUTEX */

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef RT_MUTEX_PLACEHOLDER RT_MUTEX;

#ifdef __cplusplus
extern "C" {
#endif

int rt_mutex_bind(RT_MUTEX *mutex,
		  const char *name,
		  RTIME timeout);

static inline int rt_mutex_unbind (RT_MUTEX *mutex)

{
	mutex->opaque = XN_NO_HANDLE;
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

int rt_mutex_create(RT_MUTEX *mutex,
		    const char *name);

int rt_mutex_delete(RT_MUTEX *mutex);

int rt_mutex_acquire(RT_MUTEX *mutex,
		     RTIME timeout);

int rt_mutex_release(RT_MUTEX *mutex);

int rt_mutex_inquire(RT_MUTEX *mutex,
		     RT_MUTEX_INFO *info);

#ifdef __KERNEL__
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
static inline int __deprecated_call__ rt_mutex_lock(RT_MUTEX *mutex, RTIME timeout)
{
	return rt_mutex_acquire(mutex, timeout);
}

static inline int __deprecated_call__ rt_mutex_unlock(RT_MUTEX *mutex)
{
	return rt_mutex_release(mutex);
}
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18) */
#else /* !__KERNEL__ */

int rt_mutex_lock(RT_MUTEX *mutex,
		  RTIME timeout);

int rt_mutex_unlock(RT_MUTEX *mutex);

#endif /* __KERNEL__ */

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_MUTEX_H */
