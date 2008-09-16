/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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

#ifndef _POSIX_MUTEX_H
#define _POSIX_MUTEX_H

#include <posix/internal.h>
#include <posix/thread.h>

typedef struct pse51_mutex {
	xnsynch_t synchbase;
	xnholder_t link;            /* Link in pse51_mutexq */

#define link2mutex(laddr)                                               \
	((pse51_mutex_t *)(((char *)laddr) - offsetof(pse51_mutex_t, link)))

	pthread_mutexattr_t attr;
	unsigned count;             /* lock count. */
	unsigned condvars;          /* count of condition variables using this
				       mutex. */
	pse51_kqueues_t *owningq;
} pse51_mutex_t;

void pse51_mutexq_cleanup(pse51_kqueues_t *q);

void pse51_mutex_pkg_init(void);

void pse51_mutex_pkg_cleanup(void);

/* Interruptible versions of pthread_mutex_*. Exposed for use by syscall.c. */
int pse51_mutex_timedlock_break(struct __shadow_mutex *shadow,
				int timed, xnticks_t to);

/* must be called with nklock locked, interrupts off. */
static inline int pse51_mutex_trylock_internal(xnthread_t *cur,
					       struct __shadow_mutex *shadow,
					       unsigned count)
{
	pse51_mutex_t *mutex = shadow->mutex;

	if (xnpod_unblockable_p())
		return EPERM;

	if (!pse51_obj_active(shadow, PSE51_MUTEX_MAGIC, struct __shadow_mutex))
		return EINVAL;

#if XENO_DEBUG(POSIX)
	if (mutex->owningq != pse51_kqueues(mutex->attr.pshared))
		return EPERM;
#endif /* XENO_DEBUG(POSIX) */

	if (mutex->count)
		return EBUSY;

	xnsynch_set_owner(&mutex->synchbase, cur);
	mutex->count = count;
	return 0;
}

/* must be called with nklock locked, interrupts off. */
static inline int pse51_mutex_timedlock_internal(xnthread_t *cur,
						 struct __shadow_mutex *shadow,
						 unsigned count,
						 int timed,
						 xnticks_t abs_to)

{
	pse51_mutex_t *mutex;
	int err;

	err = pse51_mutex_trylock_internal(cur, shadow, count);
	if (err != EBUSY)
		return err;

	mutex = shadow->mutex;
	if (xnsynch_owner(&mutex->synchbase) == cur)
		return EBUSY;

	if (timed)
		xnsynch_sleep_on(&mutex->synchbase, abs_to, XN_REALTIME);
	else
		xnsynch_sleep_on(&mutex->synchbase, XN_INFINITE, XN_RELATIVE);

	if (xnthread_test_info(cur, XNBREAK))
		return EINTR;
            
	if (xnthread_test_info(cur, XNRMID))
		return EINVAL;

	if (xnthread_test_info(cur, XNTIMEO))
		return ETIMEDOUT;

	return 0;
}

#endif /* !_POSIX_MUTEX_H */
