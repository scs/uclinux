/*!\file pod.h
 * \brief Real-time pod interface header.
 * \author Philippe Gerum
 *
 * Copyright (C) 2001-2007 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004 The RTAI project <http://www.rtai.org>
 * Copyright (C) 2004 The HYADES project <http://www.hyades-itea.org>
 * Copyright (C) 2004 The Xenomai project <http://www.xenomai.org>
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
 * \ingroup pod
 */

#ifndef _XENO_NUCLEUS_POD_H
#define _XENO_NUCLEUS_POD_H

/*! \addtogroup pod
 *@{*/

#include <nucleus/thread.h>
#include <nucleus/intr.h>

/* Pod status flags */
#define XNFATAL  0x00000001	/* Fatal error in progress */
#define XNPEXEC  0x00000002	/* Pod is active (a skin is attached) */

/* Sched status flags */
#define XNKCOUT  0x80000000	/* Sched callout context */
#define XNHTICK  0x40000000	/* Host tick pending  */
#define XNRPICK  0x20000000	/* Check RPI state */
#define XNINTCK  0x10000000	/* In master tick handler context */

/* These flags are available to the real-time interfaces */
#define XNPOD_SPARE0  0x01000000
#define XNPOD_SPARE1  0x02000000
#define XNPOD_SPARE2  0x04000000
#define XNPOD_SPARE3  0x08000000
#define XNPOD_SPARE4  0x10000000
#define XNPOD_SPARE5  0x20000000
#define XNPOD_SPARE6  0x40000000
#define XNPOD_SPARE7  0x80000000

/* Flags for context checking */
#define XNPOD_THREAD_CONTEXT     0x1	/* Regular thread */
#define XNPOD_INTERRUPT_CONTEXT  0x2	/* Interrupt service thread */
#define XNPOD_HOOK_CONTEXT       0x4	/* Nanokernel hook */
#define XNPOD_ROOT_CONTEXT       0x8	/* Root thread */

#define XNPOD_NORMAL_EXIT  0x0
#define XNPOD_FATAL_EXIT   0x1

#define XNPOD_ALL_CPUS  XNARCH_CPU_MASK_ALL

#define XNPOD_HEAPSIZE  (CONFIG_XENO_OPT_SYS_HEAPSZ * 1024)
#define XNPOD_PAGESIZE  512
#define XNPOD_RUNPRIO   0x80000000	/* Placeholder for "stdthread priority" */

/* Flags for xnpod_schedule_runnable() */
#define XNPOD_SCHEDFIFO 0x0
#define XNPOD_SCHEDLIFO 0x1
#define XNPOD_NOSWITCH  0x2

#ifdef CONFIG_XENO_OPT_SCALABLE_SCHED
typedef xnmlqueue_t xnsched_queue_t;
#define sched_initpq		initmlq
#define sched_emptypq_p		emptymlq_p
#define sched_insertpql		insertmlql
#define sched_insertpqf		insertmlqf
#define sched_appendpq		appendmlq
#define sched_prependpq		prependmlq
#define sched_removepq		removemlq
#define sched_getheadpq		getheadmlq
#define sched_getpq		getmlq
#define sched_findpqh		findmlqh
#else /* ! CONFIG_XENO_OPT_SCALABLE_SCHED */
typedef xnpqueue_t xnsched_queue_t;
#define sched_initpq(pqslot, minp, maxp)	initpq(pqslot)
#define sched_emptypq_p		emptypq_p
#define sched_insertpql		insertpql
#define sched_insertpqf		insertpqf
#define sched_appendpq		appendpq
#define sched_prependpq		prependpq
#define sched_removepq		removepq
#define sched_getheadpq		getheadpq
#define sched_getpq		getpq
#define sched_findpqh		findpqh
#endif /* !CONFIG_XENO_OPT_SCALABLE_SCHED */

#define XNPOD_FATAL_BUFSZ  16384

/*! 
 * \brief Scheduling information structure.
 */

typedef struct xnsched {

	xnflags_t status;	/*!< Scheduler specific status bitmask */

	xnthread_t *runthread;	/*!< Current thread (service or user). */

	xnarch_cpumask_t resched; /*!< Mask of CPUs needing rescheduling. */

	xnsched_queue_t readyq;	/*!< Ready-to-run threads (prioritized). */

	xntimerq_t timerqueue;	/* !< Core timer queue. */

	volatile unsigned inesting; /*!< Interrupt nesting level. */

#ifdef CONFIG_XENO_HW_FPU
	xnthread_t *fpuholder;	/*!< Thread owning the current FPU context. */
#endif				/* CONFIG_XENO_HW_FPU */

#ifdef CONFIG_XENO_OPT_WATCHDOG
	xntimer_t wdtimer;	/*!< Watchdog timer object. */
	int wdcount;		/*!< Watchdog tick count. */
#endif	/* CONFIG_XENO_OPT_WATCHDOG */

	xnthread_t rootcb;	/*!< Root thread control block. */

#ifdef CONFIG_XENO_OPT_STATS
	xnticks_t last_account_switch;	/*!< Last account switch date (ticks). */

	xnstat_exectime_t *current_account;	/*!< Currently active account */
#endif	/* CONFIG_XENO_OPT_STATS */

	xntimer_t htimer;	/*!< Host timer. */

} xnsched_t;

#define nkpod (&nkpod_struct)

#ifdef CONFIG_SMP
#define xnsched_cpu(__sched__)                  \
    ((__sched__) - &nkpod->sched[0])
#else /* !CONFIG_SMP */
#define xnsched_cpu(__sched__) ({ (void)__sched__; 0; })
#endif /* CONFIG_SMP */

#define xnsched_resched_mask() \
    (xnpod_current_sched()->resched)

#define xnsched_resched_p()                     \
    (!xnarch_cpus_empty(xnsched_resched_mask()))

#define xnsched_tst_resched(__sched__) \
    xnarch_cpu_isset(xnsched_cpu(__sched__), xnsched_resched_mask())

#define xnsched_set_resched(__sched__) \
    xnarch_cpu_set(xnsched_cpu(__sched__), xnsched_resched_mask())

#define xnsched_clr_resched(__sched__) \
    xnarch_cpu_clear(xnsched_cpu(__sched__), xnsched_resched_mask())

#define xnsched_clr_mask(__sched__) \
    xnarch_cpus_clear((__sched__)->resched)

struct xnsynch;
struct xnintr;

/*! 
 * \brief Real-time pod descriptor.
 *
 * The source of all Xenomai magic.
 */

struct xnpod {

	xnflags_t status;	/*!< Status bitmask. */

	xnsched_t sched[XNARCH_NR_CPUS];	/*!< Per-cpu scheduler slots. */

	xnqueue_t threadq;	/*!< All existing threads. */
	int threadq_rev;	/*!< Modification counter of threadq. */

	xnqueue_t tstartq,	/*!< Thread start hook queue. */
	 tswitchq,		/*!< Thread switch hook queue. */
	 tdeleteq;		/*!< Thread delete hook queue. */

	int refcnt;		/*!< Reference count.  */

#ifdef __KERNEL__
	atomic_counter_t timerlck;	/*!< Timer lock depth.  */
#endif	/* __KERNEL__ */

#ifdef __XENO_SIM__
	void (*schedhook) (xnthread_t *thread, xnflags_t mask);	/*!< Internal scheduling hook. */
#endif	/* __XENO_SIM__ */
};

typedef struct xnpod xnpod_t;

DECLARE_EXTERN_XNLOCK(nklock);

extern u_long nklatency;

extern u_long nktimerlat;

extern char *nkmsgbuf;

extern xnarch_cpumask_t nkaffinity;

extern xnpod_t nkpod_struct;

#ifdef __cplusplus
extern "C" {
#endif

void xnpod_schedule_runnable(xnthread_t *thread, int flags);

void xnpod_renice_thread_inner(xnthread_t *thread, int prio, int propagate);

#ifdef CONFIG_XENO_HW_FPU
void xnpod_switch_fpu(xnsched_t *sched);
#endif /* CONFIG_XENO_HW_FPU */

#ifdef CONFIG_XENO_OPT_WATCHDOG
static inline void xnpod_reset_watchdog(xnsched_t *sched)
{
	sched->wdcount = 0;
}
#else /* !CONFIG_XENO_OPT_WATCHDOG */
static inline void xnpod_reset_watchdog(xnsched_t *sched)
{
}
#endif /* CONFIG_XENO_OPT_WATCHDOG */

	/* -- Beginning of the exported interface */

#define xnpod_sched_slot(cpu) \
    (&nkpod->sched[cpu])

#define xnpod_current_sched() \
    xnpod_sched_slot(xnarch_current_cpu())

#define xnpod_active_p() \
    (!!testbits(nkpod->status, XNPEXEC))

#define xnpod_fatal_p() \
    (!!testbits(nkpod->status, XNFATAL))

#define xnpod_interrupt_p() \
    (xnpod_current_sched()->inesting > 0)

#define xnpod_callout_p() \
    (!!testbits(xnpod_current_sched()->status,XNKCOUT))

#define xnpod_asynch_p() \
    (xnpod_interrupt_p() || xnpod_callout_p())

#define xnpod_current_thread() \
    (xnpod_current_sched()->runthread)

#define xnpod_current_root() \
    (&xnpod_current_sched()->rootcb)

#ifdef CONFIG_XENO_OPT_PERVASIVE
#define xnpod_current_p(thread)					\
    ({ int __shadow_p = xnthread_test_state(thread, XNSHADOW);		\
       int __curr_p = __shadow_p ? xnshadow_thread(current) == thread	\
	   : thread == xnpod_current_thread();				\
       __curr_p;})
#else
#define xnpod_current_p(thread) \
    (xnpod_current_thread() == (thread))
#endif

#define xnpod_locked_p() \
    (!!xnthread_test_state(xnpod_current_thread(),XNLOCK))

#define xnpod_unblockable_p() \
    (xnpod_asynch_p() || xnthread_test_state(xnpod_current_thread(),XNROOT))

#define xnpod_root_p() \
    (!!xnthread_test_state(xnpod_current_thread(),XNROOT))

#define xnpod_shadow_p() \
    (!!xnthread_test_state(xnpod_current_thread(),XNSHADOW))

#define xnpod_userspace_p() \
    (!!xnthread_test_state(xnpod_current_thread(),XNROOT|XNSHADOW))

#define xnpod_primary_p() \
    (!(xnpod_asynch_p() || xnpod_root_p()))

#define xnpod_secondary_p()		xnpod_root_p()

#define xnpod_idle_p()		xnpod_root_p()

static inline void xnpod_renice_root(int prio)
{
	xnthread_t *rootcb;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	rootcb = xnpod_current_root();
	rootcb->cprio = prio;
	xnpod_schedule_runnable(rootcb, XNPOD_SCHEDLIFO | XNPOD_NOSWITCH);
	xnlock_put_irqrestore(&nklock, s);
}

static inline int xnpod_root_priority(void)
{
	return xnthread_current_priority(xnpod_current_root());
}

int xnpod_init(void);

int xnpod_enable_timesource(void);

void xnpod_disable_timesource(void);

void xnpod_shutdown(int xtype);

int xnpod_init_thread(xnthread_t *thread,
		      xntbase_t *tbase,
		      const char *name,
		      int prio,
		      xnflags_t flags,
		      unsigned stacksize,
		      xnthrops_t *ops);

int xnpod_start_thread(xnthread_t *thread,
		       xnflags_t mode,
		       int imask,
		       xnarch_cpumask_t affinity,
		       void (*entry) (void *cookie),
		       void *cookie);

void xnpod_restart_thread(xnthread_t *thread);

void xnpod_delete_thread(xnthread_t *thread);

void xnpod_abort_thread(xnthread_t *thread);

xnflags_t xnpod_set_thread_mode(xnthread_t *thread,
				xnflags_t clrmask,
				xnflags_t setmask);

void xnpod_suspend_thread(xnthread_t *thread,
			  xnflags_t mask,
			  xnticks_t timeout,
			  xntmode_t timeout_mode,
			  struct xnsynch *wchan);

void xnpod_resume_thread(xnthread_t *thread,
			 xnflags_t mask);

int xnpod_unblock_thread(xnthread_t *thread);

void xnpod_renice_thread(xnthread_t *thread,
			 int prio);

int xnpod_migrate_thread(int cpu);

void xnpod_rotate_readyq(int prio);

void xnpod_do_rr(void);

void xnpod_schedule(void);

void xnpod_dispatch_signals(void);

static inline void xnpod_lock_sched(void)
{
	xnthread_t *runthread;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	runthread = xnpod_current_sched()->runthread;

	if (xnthread_lock_count(runthread)++ == 0)
		xnthread_set_state(runthread, XNLOCK);

	xnlock_put_irqrestore(&nklock, s);
}

static inline void xnpod_unlock_sched(void)
{
	xnthread_t *runthread;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);

	runthread = xnpod_current_sched()->runthread;

	if (--xnthread_lock_count(runthread) == 0) {
		xnthread_clear_state(runthread, XNLOCK);
		xnpod_schedule();
	}

	xnlock_put_irqrestore(&nklock, s);
}

void xnpod_activate_rr(xnticks_t quantum);

void xnpod_deactivate_rr(void);

int xnpod_set_thread_periodic(xnthread_t *thread,
			      xnticks_t idate,
			      xnticks_t period);

int xnpod_wait_thread_period(unsigned long *overruns_r);

static inline xntime_t xnpod_get_cpu_time(void)
{
	return xnarch_get_cpu_time();
}

int xnpod_add_hook(int type, void (*routine) (xnthread_t *));

int xnpod_remove_hook(int type, void (*routine) (xnthread_t *));

void xnpod_check_context(int mask);

static inline void xnpod_yield(void)
{
	xnpod_resume_thread(xnpod_current_thread(), 0);
	xnpod_schedule();
}

static inline void xnpod_delay(xnticks_t timeout)
{
	xnpod_suspend_thread(xnpod_current_thread(), XNDELAY, timeout, XN_RELATIVE, NULL);
}

static inline void xnpod_suspend_self(void)
{
	xnpod_suspend_thread(xnpod_current_thread(), XNSUSP, XN_INFINITE, XN_RELATIVE, NULL);
}

static inline void xnpod_delete_self(void)
{
	xnpod_delete_thread(xnpod_current_thread());
}

#ifdef __cplusplus
}
#endif

/*@}*/

#endif /* !_XENO_NUCLEUS_POD_H */
