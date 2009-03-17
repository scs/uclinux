/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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

#ifndef _POSIX_INTERNAL_H
#define _POSIX_INTERNAL_H

#include <nucleus/xenomai.h>
#include <nucleus/core.h>
#include <nucleus/ppd.h>
#include <nucleus/select.h>
#include <posix/posix.h>
#include <posix/registry.h>

/* debug support */
#include <nucleus/assert.h>

#ifndef CONFIG_XENO_OPT_DEBUG_POSIX
#define CONFIG_XENO_OPT_DEBUG_POSIX 0
#endif

#define PSE51_MAGIC(n) (0x8686##n##n)
#define PSE51_ANY_MAGIC         PSE51_MAGIC(00)
#define PSE51_THREAD_MAGIC      PSE51_MAGIC(01)
#define PSE51_THREAD_ATTR_MAGIC PSE51_MAGIC(02)
#define PSE51_MUTEX_MAGIC       PSE51_MAGIC(03)
#define PSE51_MUTEX_ATTR_MAGIC  (PSE51_MAGIC(04) & ((1 << 24) - 1))
#define PSE51_COND_MAGIC        PSE51_MAGIC(05)
#define PSE51_COND_ATTR_MAGIC   (PSE51_MAGIC(05) & ((1 << 24) - 1))
#define PSE51_SEM_MAGIC         PSE51_MAGIC(06)
#define PSE51_KEY_MAGIC         PSE51_MAGIC(07)
#define PSE51_ONCE_MAGIC        PSE51_MAGIC(08)
#define PSE51_MQ_MAGIC          PSE51_MAGIC(09)
#define PSE51_MQD_MAGIC         PSE51_MAGIC(0A)
#define PSE51_INTR_MAGIC        PSE51_MAGIC(0B)
#define PSE51_NAMED_SEM_MAGIC   PSE51_MAGIC(0C)
#define PSE51_TIMER_MAGIC       PSE51_MAGIC(0D)
#define PSE51_SHM_MAGIC         PSE51_MAGIC(0E)

#define PSE51_MIN_PRIORITY      XNCORE_LOW_PRIO
#define PSE51_MAX_PRIORITY      XNCORE_HIGH_PRIO

#define ONE_BILLION             1000000000

#define pse51_obj_active(h,m,t)			\
	((h) && ((t *)(h))->magic == (m))

#define pse51_obj_deleted(h,m,t)		\
	((h) && ((t *)(h))->magic == ~(m))

#define pse51_mark_deleted(t) ((t)->magic = ~(t)->magic)

typedef struct {
	xnqueue_t condq;
	xnqueue_t intrq;
	xnqueue_t mutexq;
	xnqueue_t semq;
	xnqueue_t threadq;
	xnqueue_t timerq;
} pse51_kqueues_t;

#ifdef CONFIG_XENO_OPT_PERVASIVE
typedef struct {
	pse51_kqueues_t kqueues;
	pse51_assocq_t uqds;
	pse51_assocq_t usems;
	pse51_assocq_t umaps;
	pse51_assocq_t ufds;

	xnshadow_ppd_t ppd;

#define ppd2queues(addr)						\
	((pse51_queues_t *) ((char *) (addr) - offsetof(pse51_queues_t, ppd)))

} pse51_queues_t;

extern int pse51_muxid;
#endif /* CONFIG_XENO_OPT_PERVASIVE */

extern xntbase_t *pse51_tbase;

extern pse51_kqueues_t pse51_global_kqueues;

#ifdef CONFIG_XENO_OPT_PERVASIVE
static inline pse51_queues_t *pse51_queues(void)
{
	xnshadow_ppd_t *ppd;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	ppd = xnshadow_ppd_get(pse51_muxid);
	
	xnlock_put_irqrestore(&nklock, s);

	if (!ppd)
		return NULL;

	return ppd2queues(ppd);
}
#endif /* CONFIG_XENO_OPT_PERVASIVE */

static inline pse51_kqueues_t *pse51_kqueues(int pshared)
{
#ifdef CONFIG_XENO_OPT_PERVASIVE
	xnshadow_ppd_t *ppd;

	if (pshared || !(ppd = xnshadow_ppd_get(pse51_muxid)))
		return &pse51_global_kqueues;

	return &ppd2queues(ppd)->kqueues;
#else /* !CONFIG_XENO_OPT_PERVASIVE */
	return &pse51_global_kqueues;
#endif /* !CONFIG_XENO_OPT_PERVASIVE */
}

static inline void ticks2ts(struct timespec *ts, xnticks_t ticks)
{
	ts->tv_sec = xnarch_uldivrem(xntbase_ticks2ns(pse51_tbase, ticks),
				     ONE_BILLION, &ts->tv_nsec);
}

static inline xnticks_t ts2ticks_floor(const struct timespec *ts)
{
	xntime_t nsecs = ts->tv_nsec;
	if(ts->tv_sec)
		nsecs += (xntime_t) ts->tv_sec * ONE_BILLION;
	return xntbase_ns2ticks(pse51_tbase, nsecs);
}

static inline xnticks_t ts2ticks_ceil(const struct timespec *ts)
{
	xntime_t nsecs = ts->tv_nsec;
	unsigned long rem;
	xnticks_t ticks;
	if(ts->tv_sec)
		nsecs += (xntime_t) ts->tv_sec * ONE_BILLION;
	ticks = xnarch_ulldiv(nsecs, xntbase_get_tickval(pse51_tbase), &rem);
	return rem ? ticks+1 : ticks;
}

static inline xnticks_t tv2ticks_ceil(const struct timeval *tv)
{
	xntime_t nsecs = tv->tv_usec * 1000;
	unsigned long rem;
	xnticks_t ticks;
	if(tv->tv_sec)
		nsecs += (xntime_t) tv->tv_sec * ONE_BILLION;
	ticks = xnarch_ulldiv(nsecs, xntbase_get_tickval(pse51_tbase), &rem);
	return rem ? ticks+1 : ticks;
}

static inline void ticks2tv(struct timeval *tv, xnticks_t ticks)
{
	unsigned long nsecs;
	tv->tv_sec = xnarch_uldivrem(xntbase_ticks2ns(pse51_tbase, ticks),
				     ONE_BILLION,
				     &nsecs);
	tv->tv_usec = nsecs / 1000;
}

static inline xnticks_t clock_get_ticks(clockid_t clock_id)
{
	if(clock_id == CLOCK_REALTIME)
		return xntbase_get_time(pse51_tbase);
	else
		return xntbase_get_jiffies(pse51_tbase);
}

static inline int clock_flag(int flag, clockid_t clock_id)
{
	switch(flag & TIMER_ABSTIME) {
	case 0:
		return XN_RELATIVE;

	case TIMER_ABSTIME:
		switch(clock_id) {
		case CLOCK_MONOTONIC:
			return XN_ABSOLUTE;

		case CLOCK_REALTIME:
			return XN_REALTIME;
		}
	}
	return -EINVAL;
}

int pse51_mq_select_bind(mqd_t fd, struct xnselector *selector,
			 unsigned type, unsigned index);

#endif /* !_POSIX_INTERNAL_H */
