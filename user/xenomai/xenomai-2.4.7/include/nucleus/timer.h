/**
 * @file
 * @note Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
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
 *
 * \ingroup timer
 */

#ifndef _XENO_NUCLEUS_TIMER_H
#define _XENO_NUCLEUS_TIMER_H

#include <nucleus/timebase.h>
#include <nucleus/stat.h>

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#ifndef CONFIG_XENO_OPT_DEBUG_TIMERS
#define CONFIG_XENO_OPT_DEBUG_TIMERS  0
#endif

#define XNTIMER_WHEELSIZE 64
#define XNTIMER_WHEELMASK (XNTIMER_WHEELSIZE - 1)

/* Timer status */
#define XNTIMER_DEQUEUED  0x00000001
#define XNTIMER_KILLED    0x00000002
#define XNTIMER_PERIODIC  0x00000004
#define XNTIMER_REALTIME  0x00000008
#define XNTIMER_FIRED     0x00000010
#define XNTIMER_NOBLCK	  0x00000020

/* These flags are available to the real-time interfaces */
#define XNTIMER_SPARE0  0x01000000
#define XNTIMER_SPARE1  0x02000000
#define XNTIMER_SPARE2  0x04000000
#define XNTIMER_SPARE3  0x08000000
#define XNTIMER_SPARE4  0x10000000
#define XNTIMER_SPARE5  0x20000000
#define XNTIMER_SPARE6  0x40000000
#define XNTIMER_SPARE7  0x80000000

/* Timer priorities */
#define XNTIMER_LOPRIO  (-999999999)
#define XNTIMER_STDPRIO 0
#define XNTIMER_HIPRIO  999999999

#define XNTIMER_KEEPER_ID 0

typedef struct {
	xnholder_t link;
	xnticks_t key;
	int prio;

#define link2tlholder(ln)	container_of(ln, xntlholder_t, link)

} xntlholder_t;

#define xntlholder_date(h)	((h)->key)
#define xntlholder_prio(h)	((h)->prio)
#define xntlholder_init(h)	inith(&(h)->link)
#define xntlist_init(q)	initq(q)
#define xntlist_head(q)			\
	({ xnholder_t *_h = getheadq(q);	\
		!_h ? NULL : link2tlholder(_h);	\
	})

#define xntlist_next(q, h) \
	({ xnholder_t *_h = nextq(q, &(h)->link);	\
		!_h ? NULL : link2tlholder(_h);		\
	})

static inline void xntlist_insert(xnqueue_t *q, xntlholder_t *holder)
{
	xnholder_t *p;

	/* Insert the new timer at the proper place in the single
	   queue managed when running in aperiodic mode. O(N) here,
	   but users of the aperiodic mode need to pay a price for the
	   increased flexibility... */

	for (p = q->head.last; p != &q->head; p = p->last)
		if ((xnsticks_t) (holder->key - link2tlholder(p)->key) > 0 ||
		    (holder->key == link2tlholder(p)->key &&
		     holder->prio <= link2tlholder(p)->prio))
			break;

	insertq(q,p->next,&holder->link);
}

#define xntlist_remove(q, h)  removeq((q),&(h)->link)

#if defined(CONFIG_XENO_OPT_TIMER_HEAP)

#include <nucleus/bheap.h>

typedef bheaph_t xntimerh_t;

#define xntimerh_date(h)          bheaph_key(h)
#define xntimerh_prio(h)          bheaph_prio(h)
#define xntimerh_init(h)          bheaph_init(h)

typedef DECLARE_BHEAP_CONTAINER(xntimerq_t, CONFIG_XENO_OPT_TIMER_HEAP_CAPACITY);

#define xntimerq_init(q)          bheap_init((q), CONFIG_XENO_OPT_TIMER_HEAP_CAPACITY)
#define xntimerq_destroy(q)       bheap_destroy(q)
#define xntimerq_head(q)          bheap_gethead(q)
#define xntimerq_insert(q, h)     bheap_insert((q),(h))
#define xntimerq_remove(q, h)     bheap_delete((q),(h))

typedef struct {} xntimerq_it_t;

#define xntimerq_it_begin(q, i)   ((void) (i), bheap_gethead(q))
#define xntimerq_it_next(q, i, h) ((void) (i), bheap_next((q),(h)))

#elif defined(CONFIG_XENO_OPT_TIMER_WHEEL)

typedef xntlholder_t xntimerh_t;

#define xntimerh_date(h)       xntlholder_date(h)
#define xntimerh_prio(h)       xntlholder_prio(h)
#define xntimerh_init(h)       xntlholder_init(h)

typedef struct {
	unsigned date_shift;
	unsigned long long next_shot;
	unsigned long long shot_wrap;
	xnqueue_t bucket[XNTIMER_WHEELSIZE];
} xntimerq_t;

typedef struct {
	unsigned bucket;
} xntimerq_it_t;

static inline void xntimerq_init(xntimerq_t *q)
{
	unsigned long long step_tsc;
	unsigned i;

	step_tsc = xnarch_ns_to_tsc(CONFIG_XENO_OPT_TIMER_WHEEL_STEP);
	/* q->date_shift = fls(step_tsc); */
	for (q->date_shift = 0; (1 << q->date_shift) < step_tsc; q->date_shift++)
		;
	q->next_shot = q->shot_wrap = ((~0ULL) >> q->date_shift) + 1;
	for (i = 0; i < sizeof(q->bucket)/sizeof(xnqueue_t); i++)
		xntlist_init(&q->bucket[i]);
}

#define xntimerq_destroy(q)    do { } while (0)

static inline xntlholder_t *xntimerq_head(xntimerq_t *q)
{
	unsigned bucket = ((unsigned) q->next_shot) & XNTIMER_WHEELMASK;
	xntlholder_t *result;
	unsigned i;

	if (q->next_shot == q->shot_wrap)
		return NULL;

	result = xntlist_head(&q->bucket[bucket]);

	if (result && (xntlholder_date(result) >> q->date_shift) == q->next_shot)
		return result;

	/* We could not find the next timer in the first bucket, iterate over
	   the other buckets. */
	for (i = (bucket + 1) & XNTIMER_WHEELMASK ;
	     i != bucket; i = (i + 1) & XNTIMER_WHEELMASK) {
		xntlholder_t *candidate = xntlist_head(&q->bucket[i]);

		if(++q->next_shot == q->shot_wrap)
			q->next_shot = 0;

		if (!candidate)
			continue;

		if ((xntlholder_date(candidate) >> q->date_shift) == q->next_shot)
			return candidate;

		if (!result || (xnsticks_t) (xntlholder_date(candidate)
					     - xntlholder_date(result)) < 0)
			result = candidate;
	}

	if (result)
		q->next_shot = (xntlholder_date(result) >> q->date_shift);
	else
		q->next_shot = q->shot_wrap;
	return result;
}

static inline void xntimerq_insert(xntimerq_t *q, xntimerh_t *h)
{
	unsigned long long shifted_date = xntlholder_date(h) >> q->date_shift;
	unsigned bucket = ((unsigned) shifted_date) & XNTIMER_WHEELMASK;

	if ((long long) (shifted_date - q->next_shot) < 0)
		q->next_shot = shifted_date;
	xntlist_insert(&q->bucket[bucket], h);
}

static inline void xntimerq_remove(xntimerq_t *q, xntimerh_t *h)
{
	unsigned long long shifted_date = xntlholder_date(h) >> q->date_shift;
	unsigned bucket = ((unsigned) shifted_date) & XNTIMER_WHEELMASK;

	xntlist_remove(&q->bucket[bucket], h);
	/* Do not attempt to update q->next_shot, xntimerq_head will recover. */
}

static inline xntimerh_t *xntimerq_it_begin(xntimerq_t *q, xntimerq_it_t *it)
{
	xntimerh_t *holder = NULL;

	for (it->bucket = 0; it->bucket < XNTIMER_WHEELSIZE; it->bucket++)
		if ((holder = xntlist_head(&q->bucket[it->bucket])))
			break;

	return holder;
}

static inline xntimerh_t *
xntimerq_it_next(xntimerq_t *q, xntimerq_it_t *it, xntimerh_t *holder)
{
	xntimerh_t *next = xntlist_next(&q->bucket[it->bucket], holder);

	if (!next)
		for(it->bucket++; it->bucket < XNTIMER_WHEELSIZE; it->bucket++)
			if ((next = xntlist_head(&q->bucket[it->bucket])))
				break;

	return next;
}

#else /* CONFIG_XENO_OPT_TIMER_LIST */

typedef xntlholder_t xntimerh_t;

#define xntimerh_date(h)        xntlholder_date(h)
#define xntimerh_prio(h)        xntlholder_prio(h)
#define xntimerh_init(h)        xntlholder_init(h)

typedef xnqueue_t xntimerq_t;

#define xntimerq_init(q)        xntlist_init(q)
#define xntimerq_destroy(q)     do { } while (0)
#define xntimerq_head(q)        xntlist_head(q)
#define xntimerq_insert(q,h)    xntlist_insert((q),(h))
#define xntimerq_remove(q, h)   xntlist_remove((q),(h))

typedef struct {} xntimerq_it_t;

#define xntimerq_it_begin(q,i)  ((void) (i), xntlist_head(q))
#define xntimerq_it_next(q,i,h) ((void) (i), xntlist_next((q),(h)))

#endif /* CONFIG_XENO_OPT_TIMER_LIST */

struct xnsched;

typedef struct xntimer {

	xntimerh_t aplink;	/* Link in aperiodic timers list. */

#define aplink2timer(ln) container_of(ln, xntimer_t, aplink)

#ifdef CONFIG_XENO_OPT_TIMING_PERIODIC
	xntbase_t *base;	/* Time base. */

	xntlholder_t plink;	/* Link in periodic timers wheel. */

#define plink2timer(ln) container_of(ln, xntimer_t, plink)
#endif /* CONFIG_XENO_OPT_TIMING_PERIODIC */

	xnholder_t adjlink;

#define adjlink2timer(ln) container_of(ln, xntimer_t, adjlink)

	xnflags_t status;	/* !< Timer status. */

	xnticks_t interval;	/* !< Periodic interval (in ticks, 0 == one shot). */

	xnticks_t pexpect;	/* !< Date of next periodic release point (raw ticks). */

	struct xnsched *sched;	/* !< Sched structure to which the timer is
				   attached. */

	void (*handler)(struct xntimer *timer); /* !< Timeout handler. */

#ifdef CONFIG_XENO_OPT_STATS
	char name[XNOBJECT_NAME_LEN]; /* !< Timer name to be displayed. */

	const char *handler_name; /* !< Handler name to be displayed. */

	xnholder_t tblink;	/* !< Timer holder in timebase. */

#define tblink2timer(ln)	container_of(ln, xntimer_t, tblink)
#endif /* CONFIG_XENO_OPT_STATS */

	xnstat_counter_t scheduled; /* !< Number of timer schedules. */

	xnstat_counter_t fired; /* !< Number of timer events. */

	XNARCH_DECL_DISPLAY_CONTEXT();

} xntimer_t;

typedef struct xntimed_slave {

	xntbase_t base;		/* !< Cascaded time base. */

	struct percpu_cascade {
		xntimer_t timer; /* !< Cascading timer in master time base. */
		xnqueue_t wheel[XNTIMER_WHEELSIZE]; /*!< BSDish timer wheel. */
	} cascade[XNARCH_NR_CPUS];

#define timer2slave(t) \
    ((xntslave_t *)(((char *)t) - offsetof(xntslave_t, cascade[xnsched_cpu((t)->sched)].timer)))
#define base2slave(b) \
    ((xntslave_t *)(((char *)b) - offsetof(xntslave_t, base)))

} xntslave_t;

#ifdef CONFIG_SMP
#define xntimer_sched(t)	((t)->sched)
#else /* !CONFIG_SMP */
#define xntimer_sched(t)	xnpod_current_sched()
#endif /* !CONFIG_SMP */
#define xntimer_interval(t)	((t)->interval)
#define xntimer_set_cookie(t,c)	((t)->cookie = (c))
#define xntimer_pexpect(t)      ((t)->pexpect)
#define xntimer_pexpect_forward(t,delta) ((t)->pexpect += delta)

#ifdef CONFIG_XENO_OPT_TIMING_PERIODIC
#define xntimer_base(t)		((t)->base)
#define xntimer_set_priority(t,p)				\
	({							\
		xntimer_t *_t = (t);				\
		unsigned prio = (p);				\
		xntimerh_prio(&(_t)->aplink) = prio;		\
		xntlholder_prio(&(_t)->plink) = prio;		\
	})
#else /* !CONFIG_XENO_OPT_TIMING_PERIODIC */
#define xntimer_base(t)		(&nktbase)
#define xntimer_set_priority(t,p)				\
	do { xntimerh_prio(&(t)->aplink) = (p); } while(0)
#endif /* !CONFIG_XENO_OPT_TIMING_PERIODIC */

static inline int xntimer_active_p (xntimer_t *timer)
{
	return timer->sched != NULL;
}

static inline int xntimer_running_p (xntimer_t *timer)
{
	return !testbits(timer->status,XNTIMER_DEQUEUED);
}

static inline int xntimer_reload_p(xntimer_t *timer)
{
	return testbits(timer->status,
			XNTIMER_PERIODIC|XNTIMER_DEQUEUED|XNTIMER_KILLED) ==
		(XNTIMER_PERIODIC|XNTIMER_DEQUEUED);
}

#ifdef __cplusplus
extern "C" {
#endif

extern xntbops_t nktimer_ops_aperiodic,
		 nktimer_ops_periodic;

#ifdef CONFIG_XENO_OPT_STATS
#define xntimer_init(timer, base, handler)		\
	do {						\
		__xntimer_init(timer, base, handler);	\
		(timer)->handler_name = #handler;	\
	} while (0)
#else /* !CONFIG_XENO_OPT_STATS */
#define xntimer_init	__xntimer_init
#endif /* !CONFIG_XENO_OPT_STATS */

void __xntimer_init(xntimer_t *timer,
		  xntbase_t *base,
		  void (*handler)(xntimer_t *timer));

void xntimer_destroy(xntimer_t *timer);

static inline void xntimer_set_name(xntimer_t *timer, const char *name)
{
#ifdef CONFIG_XENO_OPT_STATS
	strncpy(timer->name, name, sizeof(timer->name));
#endif /* CONFIG_XENO_OPT_STATS */
}

/*!
 * \addtogroup timer
 *@{ */

#if defined(CONFIG_XENO_OPT_TIMING_PERIODIC) || defined(DOXYGEN_CPP)

/*!
 * @fn void xntimer_start(xntimer_t *timer,xnticks_t value,xnticks_t interval,
 *                        xntmode_t mode)
 * @brief Arm a timer.
 *
 * Activates a timer so that the associated timeout handler will be
 * fired after each expiration time. A timer can be either periodic or
 * single-shot, depending on the reload value passed to this
 * routine. The given timer must have been previously initialized, and
 * will be clocked according to the policy defined by the time base
 * specified in xntimer_init().
 *
 * @param timer The address of a valid timer descriptor.
 *
 * @param value The date of the initial timer shot, expressed in clock ticks
 * (see note).
 *
 * @param interval The reload value of the timer. It is a periodic
 * interval value to be used for reprogramming the next timer shot,
 * expressed in clock ticks (see note). If @a interval is equal to
 * XN_INFINITE, the timer will not be reloaded after it has expired.
 *
 * @param mode The timer mode. It can be XN_RELATIVE if @a value shall
 * be interpreted as a relative date, XN_ABSOLUTE for an absolute date
 * based on the monotonic clock of the related time base (as returned
 * my xntbase_get_jiffies()), or XN_REALTIME if the absolute date is
 * based on the adjustable real-time clock of the time base (as returned
 * by xntbase_get_time().
 *
 * @return 0 is returned upon success, or -ETIMEDOUT if an absolute
 * date in the past has been given.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 *
 * @note This service is sensitive to the current operation mode of
 * the associated time base, as defined by the xnpod_init_timebase()
 * service. In periodic mode, clock ticks are interpreted as periodic
 * jiffies. In oneshot mode, clock ticks are interpreted as
 * nanoseconds.
 *
 * @note Must be called with nklock held, IRQs off.
 */

static inline int xntimer_start(xntimer_t *timer,
				xnticks_t value, xnticks_t interval,
				xntmode_t mode)
{
	return timer->base->ops->start_timer(timer, value, interval, mode);
}

/*!
 * \fn int xntimer_stop(xntimer_t *timer)
 *
 * \brief Disarm a timer.
 *
 * This service deactivates a timer previously armed using
 * xntimer_start(). Once disarmed, the timer can be subsequently
 * re-armed using the latter service.
 *
 * @param timer The address of a valid timer descriptor.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 *
 * @note Must be called with nklock held, IRQs off.
 */

static inline void xntimer_stop(xntimer_t *timer)
{
	/* Careful: the do_timer_stop() helper is expected to preserve
	   the date field of the stopped timer, so that subsequent
	   calls to xntimer_get_timeout() would still work on such
	   timer as expected. */
	if (!testbits(timer->status,XNTIMER_DEQUEUED))
		timer->base->ops->stop_timer(timer);
}

/*!
 * \fn xnticks_t xntimer_get_date(xntimer_t *timer)
 *
 * \brief Return the absolute expiration date.
 *
 * Return the next expiration date of a timer in absolute clock ticks
 * (see note).
 *
 * @param timer The address of a valid timer descriptor.
 *
 * @return The expiration date converted to the current time unit. The
 * special value XN_INFINITE is returned if @a timer is currently
 * inactive.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 *
 * @note This service is sensitive to the current operation mode of
 * the associated time base, as defined by the xnpod_init_timebase()
 * service. In periodic mode, clock ticks are interpreted as periodic
 * jiffies. In oneshot mode, clock ticks are interpreted as
 * nanoseconds.
 */

static inline xnticks_t xntimer_get_date(xntimer_t *timer)
{
	if (!xntimer_running_p(timer))
		return XN_INFINITE;

	return timer->base->ops->get_timer_date(timer);
}

/*!
 * \fn xnticks_t xntimer_get_timeout(xntimer_t *timer)
 *
 * \brief Return the relative expiration date.
 *
 * Return the next expiration date of a timer in relative clock ticks
 * (see note).
 *
 * @param timer The address of a valid timer descriptor.
 *
 * @return The expiration date converted to the current time unit. The
 * special value XN_INFINITE is returned if @a timer is currently
 * inactive. In oneshot mode, it might happen that the timer has
 * already expired when this service is run (even if the associated
 * handler has not been fired yet); in such a case, 1 is returned.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 *
 * @note This service is sensitive to the current operation mode of
 * the associated time base, as defined by the xnpod_init_timebase()
 * service. In periodic mode, clock ticks are interpreted as periodic
 * jiffies. In oneshot mode, clock ticks are interpreted as
 * nanoseconds.
 */

static inline xnticks_t xntimer_get_timeout(xntimer_t *timer)
{
	if (!xntimer_running_p(timer))
		return XN_INFINITE;

	return timer->base->ops->get_timer_timeout(timer);
}

static inline xnticks_t xntimer_get_timeout_stopped(xntimer_t *timer)
{
	return timer->base->ops->get_timer_timeout(timer);
}

/*!
 * \fn xnticks_t xntimer_get_interval(xntimer_t *timer)
 *
 * \brief Return the timer interval value.
 *
 * Return the timer interval value in clock ticks (see note).
 *
 * @param timer The address of a valid timer descriptor.
 *
 * @return The expiration date converted to the current time unit. The
 * special value XN_INFINITE is returned if @a timer is currently
 * inactive or aperiodic.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Kernel module initialization/cleanup code
 * - Interrupt service routine
 * - Kernel-based task
 * - User-space task
 *
 * Rescheduling: never.
 *
 * @note This service is sensitive to the current operation mode of
 * the associated time base, as defined by the xnpod_init_timebase()
 * service. In periodic mode, clock ticks are interpreted as periodic
 * jiffies. In oneshot mode, clock ticks are interpreted as
 * nanoseconds.
 */

static inline xnticks_t xntimer_get_interval(xntimer_t *timer)
{
	return timer->base->ops->get_timer_interval(timer);
}

static inline xnticks_t xntimer_get_raw_expiry (xntimer_t *timer)
{
	return timer->base->ops->get_timer_raw_expiry(timer);
}

void xntslave_init(xntslave_t *slave);

void xntslave_destroy(xntslave_t *slave);

void xntslave_update(xntslave_t *slave,
		     xnticks_t interval);

void xntslave_start(xntslave_t *slave,
		    xnticks_t start,
		    xnticks_t interval);

void xntslave_stop(xntslave_t *slave);

void xntslave_adjust(xntslave_t *slave, xnsticks_t delta);

#else /* !CONFIG_XENO_OPT_TIMING_PERIODIC */

int xntimer_start_aperiodic(xntimer_t *timer,
			    xnticks_t value,
			    xnticks_t interval,
			    xntmode_t mode);

void xntimer_stop_aperiodic(xntimer_t *timer);

xnticks_t xntimer_get_date_aperiodic(xntimer_t *timer);

xnticks_t xntimer_get_timeout_aperiodic(xntimer_t *timer);

xnticks_t xntimer_get_interval_aperiodic(xntimer_t *timer);

xnticks_t xntimer_get_raw_expiry_aperiodic(xntimer_t *timer);

static inline int xntimer_start(xntimer_t *timer,
				xnticks_t value, xnticks_t interval,
				xntmode_t mode)
{
	return xntimer_start_aperiodic(timer, value, interval, mode);
}

static inline void xntimer_stop(xntimer_t *timer)
{
	if (!testbits(timer->status,XNTIMER_DEQUEUED))
		xntimer_stop_aperiodic(timer);
}

static inline xnticks_t xntimer_get_date(xntimer_t *timer)
{
	if (!xntimer_running_p(timer))
		return XN_INFINITE;

	return xntimer_get_date_aperiodic(timer);
}

static inline xnticks_t xntimer_get_timeout(xntimer_t *timer)
{
	if (!xntimer_running_p(timer))
		return XN_INFINITE;

	return xntimer_get_timeout_aperiodic(timer);
}

static inline xnticks_t xntimer_get_timeout_stopped(xntimer_t *timer)
{
	return xntimer_get_timeout_aperiodic(timer);
}

static inline xnticks_t xntimer_get_interval(xntimer_t *timer)
{
	return xntimer_get_interval_aperiodic(timer);
}

static inline xnticks_t xntimer_get_raw_expiry (xntimer_t *timer)
{
	return xntimerh_date(&timer->aplink);
}

#endif /* CONFIG_XENO_OPT_TIMING_PERIODIC */

/*@}*/

unsigned long xntimer_get_overruns(xntimer_t *timer, xnticks_t now);

void xntimer_freeze(void);

void xntimer_tick_aperiodic(void);

void xntimer_tick_periodic(xntimer_t *timer);

void xntimer_tick_periodic_inner(xntslave_t *slave);

void xntimer_adjust_all_aperiodic(xnsticks_t delta);

#ifdef CONFIG_SMP
int xntimer_migrate(xntimer_t *timer,
		    struct xnsched *sched);
#else /* ! CONFIG_SMP */
#define xntimer_migrate(timer, sched)		do { } while(0)
#endif /* CONFIG_SMP */

#define xntimer_set_sched(timer, sched)	xntimer_migrate(timer, sched)

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#endif /* !_XENO_NUCLEUS_TIMER_H */
