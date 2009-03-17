/* 
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
 * \ingroup thread
 */

#ifndef _XENO_NUCLEUS_THREAD_H
#define _XENO_NUCLEUS_THREAD_H

/*! @ingroup nucleus 
  @defgroup nucleus_state_flags Thread state flags.
  @brief Bits reporting permanent or transient states of thread.
  @{
*/

/* State flags */

#define XNSUSP    0x00000001 /**< Suspended. */
#define XNPEND    0x00000002 /**< Sleep-wait for a resource. */
#define XNDELAY   0x00000004 /**< Delayed */
#define XNREADY   0x00000008 /**< Linked to the ready queue. */
#define XNDORMANT 0x00000010 /**< Not started yet or killed */
#define XNZOMBIE  0x00000020 /**< Zombie thread in deletion process */
#define XNRESTART 0x00000040 /**< Restarting thread */
#define XNSTARTED 0x00000080 /**< Thread has been started */
#define XNMAPPED  0x00000100 /**< Mapped to a regular Linux task (shadow only) */
#define XNRELAX   0x00000200 /**< Relaxed shadow thread (blocking bit) */
#define XNHELD    0x00000400 /**< Held thread from suspended partition */

#define XNBOOST   0x00000800 /**< Undergoes a PIP boost */
#define XNDEBUG   0x00001000 /**< Hit a debugger breakpoint (shadow only) */
#define XNLOCK    0x00002000 /**< Holds the scheduler lock (i.e. not preemptible) */
#define XNRRB     0x00004000 /**< Undergoes a round-robin scheduling */
#define XNASDI    0x00008000 /**< ASR are disabled */

/* Some skins may depend on the following fields to live in the high
   16-bit word, in order to be combined with the emulated RTOS flags
   which use the low one, so don't change them carelessly. */

#define XNSHIELD  0x00010000 /**< IRQ shield is enabled (shadow only) */
#define XNTRAPSW  0x00020000 /**< Trap execution mode switches */
#define XNRPIOFF  0x00040000 /**< Stop priority coupling (shadow only) */

#define XNFPU     0x00100000 /**< Thread uses FPU */
#define XNSHADOW  0x00200000 /**< Shadow thread */
#define XNROOT    0x00400000 /**< Root thread (that is, Linux/IDLE) */

/*! @} */ /* Ends doxygen comment group: nucleus_state_flags */

/*
  Must follow the declaration order of the above bits. Status symbols
  are defined as follows:
  'S' -> Forcibly suspended.
  'w'/'W' -> Waiting for a resource, with or without timeout.
  'D' -> Delayed (without any other wait condition).
  'R' -> Runnable.
  'U' -> Unstarted or dormant.
  'X' -> Relaxed shadow.
  'H' -> Held thread.
  'b' -> Priority boost undergoing.
  'T' -> Ptraced and stopped.
  'l' -> Locks scheduler.
  'r' -> Undergoes round-robin.
  's' -> Interrupt shield enabled.
  't' -> Mode switches trapped.
  'o' -> Priority coupling off.
  'f' -> FPU enabled (for kernel threads).
*/
#define XNTHREAD_STATE_LABELS  {	\
	'S', 'W', 'D', 'R', 'U',	\
	'.', '.', '.', '.', 'X',	\
	'H', 'b', 'T', 'l', 'r',	\
	'.', 's', 't', 'o', '.',	\
	'f', '.', '.',			\
}

#define XNTHREAD_BLOCK_BITS   (XNSUSP|XNPEND|XNDELAY|XNDORMANT|XNRELAX|XNHELD)
#define XNTHREAD_MODE_BITS    (XNLOCK|XNRRB|XNASDI|XNSHIELD|XNTRAPSW|XNRPIOFF)

/* These state flags are available to the real-time interfaces */
#define XNTHREAD_STATE_SPARE0  0x10000000
#define XNTHREAD_STATE_SPARE1  0x20000000
#define XNTHREAD_STATE_SPARE2  0x40000000
#define XNTHREAD_STATE_SPARE3  0x80000000
#define XNTHREAD_STATE_SPARES  0xf0000000

/*! @ingroup nucleus 
  @defgroup nucleus_info_flags Thread information flags.
  @brief Bits reporting events notified to the thread.
  @{
*/

/* Information flags */

#define XNTIMEO   0x00000001 /**< Woken up due to a timeout condition */
#define XNRMID    0x00000002 /**< Pending on a removed resource */
#define XNBREAK   0x00000004 /**< Forcibly awaken from a wait state */
#define XNKICKED  0x00000008 /**< Kicked upon Linux signal (shadow only) */
#define XNWAKEN   0x00000010 /**< Thread waken up upon resource availability */
#define XNROBBED  0x00000020 /**< Robbed from resource ownership */
#define XNATOMIC  0x00000040 /**< In atomic switch from secondary to primary mode */
#define XNAFFSET  0x00000080 /**< CPU affinity changed from primary mode */

/* These information flags are available to the real-time interfaces */
#define XNTHREAD_INFO_SPARE0  0x10000000
#define XNTHREAD_INFO_SPARE1  0x20000000
#define XNTHREAD_INFO_SPARE2  0x40000000
#define XNTHREAD_INFO_SPARE3  0x80000000
#define XNTHREAD_INFO_SPARES  0xf0000000

/*! @} */ /* Ends doxygen comment group: nucleus_info_flags */

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/stat.h>
#include <nucleus/timer.h>

#ifdef __XENO_SIM__
/* Pseudo-status (must not conflict with other bits) */
#define XNRUNNING  XNTHREAD_STATE_SPARE0
#define XNDELETED  XNTHREAD_STATE_SPARE1
#endif /* __XENO_SIM__ */

#define XNTHREAD_INVALID_ASR  ((void (*)(xnsigmask_t))0)

struct xnthread;
struct xnsched;
struct xnsynch;
struct xnrpi;

typedef struct xnthrops {

	int (*get_denormalized_prio)(struct xnthread *, int coreprio);
	unsigned (*get_magic)(void);

} xnthrops_t;

typedef void (*xnasr_t)(xnsigmask_t sigs);

typedef struct xnthread {

    xnarchtcb_t tcb;		/* Architecture-dependent block -- Must be first */

    xnflags_t state;		/* Thread state flags */

    xnflags_t info;		/* Thread information flags */

    struct xnsched *sched;	/* Thread scheduler */

    xnarch_cpumask_t affinity;	/* Processor affinity. */

    int bprio;			/* Base priority (before PIP boost) */

    int cprio;			/* Current priority */

    u_long schedlck;		/*!< Scheduler lock count. */

    xnpholder_t rlink;		/* Thread holder in ready queue */

    xnpholder_t plink;		/* Thread holder in synchronization queue(s) */

#ifdef CONFIG_XENO_OPT_PRIOCPL
    xnpholder_t xlink;		/* Thread holder in the RPI queue (shadow only) */

    struct xnrpi *rpi;		/* Backlink pointer to the RPI slot (shadow only) */
#endif /* CONFIG_XENO_OPT_PRIOCPL */

    xnholder_t glink;		/* Thread holder in global queue */

#define link2thread(ln, fld)	container_of(ln, xnthread_t, fld)

    xnpqueue_t claimq;		/* Owned resources claimed by others (PIP) */

    struct xnsynch *wchan;	/* Resource the thread pends on */

    struct xnsynch *wwake;	/* Wait channel the thread was resumed from */

    xntimer_t rtimer;		/* Resource timer */

    xntimer_t ptimer;		/* Periodic timer */

    xnsigmask_t signals;	/* Pending core signals */

    xnticks_t rrperiod;		/* Allotted round-robin period (ticks) */

    xnticks_t rrcredit;		/* Remaining round-robin time credit (ticks) */

    struct {
	xnstat_counter_t ssw;	/* Primary -> secondary mode switch count */
	xnstat_counter_t csw;	/* Context switches (includes secondary -> primary switches) */
	xnstat_counter_t pf;	/* Number of page faults */
	xnstat_exectime_t account; /* Execution time accounting entity */
	xnstat_exectime_t lastperiod; /* Interval marker for execution time reports */
    } stat;

    int errcode;		/* Local errno */

    xnasr_t asr;		/* Asynchronous service routine */

    xnflags_t asrmode;		/* Thread's mode for ASR */

    int asrimask;		/* Thread's interrupt mask for ASR */

    unsigned asrlevel;		/* ASR execution level (ASRs are reentrant) */

    int imask;			/* Initial interrupt mask */

    int imode;			/* Initial mode */

    int iprio;			/* Initial priority */

#ifdef CONFIG_XENO_OPT_REGISTRY
    struct {
	xnhandle_t handle;	/* Handle in registry */
	const char *waitkey;	/* Pended key */
    } registry;
#endif /* CONFIG_XENO_OPT_REGISTRY */

    xnthrops_t *ops;		/* Thread class operations. */

    char name[XNOBJECT_NAME_LEN]; /* Symbolic name of thread */

    void (*entry)(void *cookie); /* Thread entry routine */

    void *cookie;		/* Cookie to pass to the entry routine */

    XNARCH_DECL_DISPLAY_CONTEXT();

} xnthread_t;

#define XNHOOK_THREAD_START  1
#define XNHOOK_THREAD_SWITCH 2
#define XNHOOK_THREAD_DELETE 3

typedef struct xnhook {

	xnholder_t link;
#define link2hook(ln)		container_of(ln, xnhook_t, link)

	void (*routine)(xnthread_t *thread);

} xnhook_t;

#define xnthread_name(thread)               ((thread)->name)
#define xnthread_clear_name(thread)        do { *(thread)->name = 0; } while(0)
#define xnthread_sched(thread)             ((thread)->sched)
#define xnthread_start_time(thread)        ((thread)->stime)
#define xnthread_state_flags(thread)       ((thread)->state)
#define xnthread_test_state(thread,flags)  testbits((thread)->state,flags)
#define xnthread_set_state(thread,flags)   __setbits((thread)->state,flags)
#define xnthread_clear_state(thread,flags) __clrbits((thread)->state,flags)
#define xnthread_test_info(thread,flags)   testbits((thread)->info,flags)
#define xnthread_set_info(thread,flags)    __setbits((thread)->info,flags)
#define xnthread_clear_info(thread,flags)  __clrbits((thread)->info,flags)
#define xnthread_lock_count(thread)        ((thread)->schedlck)
#define xnthread_initial_priority(thread) ((thread)->iprio)
#define xnthread_base_priority(thread)     ((thread)->bprio)
#define xnthread_current_priority(thread) ((thread)->cprio)
#define xnthread_time_slice(thread)        ((thread)->rrperiod)
#define xnthread_time_credit(thread)       ((thread)->rrcredit)
#define xnthread_archtcb(thread)           (&((thread)->tcb))
#define xnthread_asr_level(thread)         ((thread)->asrlevel)
#define xnthread_pending_signals(thread)  ((thread)->signals)
#define xnthread_timeout(thread)           xntimer_get_timeout(&(thread)->rtimer)
#define xnthread_stack_size(thread)        xnarch_stack_size(xnthread_archtcb(thread))
#define xnthread_stack_base(thread)        xnarch_stack_base(xnthread_archtcb(thread))
#define xnthread_stack_end(thread)         xnarch_stack_end(xnthread_archtcb(thread))
#define xnthread_handle(thread)            ((thread)->registry.handle)
#ifdef CONFIG_XENO_OPT_TIMING_PERIODIC
#define xnthread_time_base(thread)         ((thread)->rtimer.base)
#else /* !CONFIG_XENO_OPT_TIMING_PERIODIC */
#define xnthread_time_base(thread)         (&nktbase)
#endif /* !CONFIG_XENO_OPT_TIMING_PERIODIC */
#define xnthread_signaled_p(thread)        ((thread)->signals != 0)
#define xnthread_timed_p(thread)	      (!!testbits(xnthread_time_base(thread)->status, XNTBRUN))
#define xnthread_user_task(thread)         xnarch_user_task(xnthread_archtcb(thread))
#define xnthread_user_pid(thread) \
    (xnthread_test_state((thread),XNROOT) || !xnthread_user_task(thread) ? \
    0 : xnarch_user_pid(xnthread_archtcb(thread)))
#define xnthread_affinity(thread)          ((thread)->affinity)
#define xnthread_affine_p(thread, cpu)     xnarch_cpu_isset(cpu, (thread)->affinity)
#define xnthread_get_exectime(thread)      xnstat_exectime_get_total(&(thread)->stat.account)
#define xnthread_get_lastswitch(thread)    xnstat_exectime_get_last_switch((thread)->sched)

/* Class-level operations for threads. */
static inline int xnthread_get_denormalized_prio(xnthread_t *t, int coreprio)
{
	return t->ops && t->ops->get_denormalized_prio ?
		t->ops->get_denormalized_prio(t, coreprio) : coreprio;
}

static inline unsigned xnthread_get_magic(xnthread_t *t)
{
	return t->ops ? t->ops->get_magic() : 0;
}

#ifdef __cplusplus
extern "C" {
#endif

int xnthread_init(xnthread_t *thread,
		  xntbase_t *tbase,
		  const char *name,
		  int prio,
		  xnflags_t flags,
		  unsigned stacksize,
		  xnthrops_t *ops);

void xnthread_cleanup_tcb(xnthread_t *thread);

char *xnthread_symbolic_status(xnflags_t status, char *buf, int size);

int *xnthread_get_errno_location(xnthread_t *thread);

static inline xnticks_t xnthread_get_timeout(xnthread_t *thread, xnticks_t tsc_ns)
{
	xnticks_t timeout;
	xntimer_t *timer;

	if (!xnthread_test_state(thread,XNDELAY))
		return 0LL;

	if (xntimer_running_p(&thread->rtimer))
		timer = &thread->rtimer;
	else if (xntimer_running_p(&thread->ptimer))
		timer = &thread->ptimer;
	else
		return 0LL;

	/*
	 * The caller should have masked IRQs while collecting the
	 * timeout(s), so no tick could be announced in the meantime,
	 * and all timeouts would always use the same epoch
	 * value. Obviously, this can't be a valid assumption for
	 * aperiodic timers, which values are based on the hardware
	 * TSC, and as such the current time will change regardless of
	 * the interrupt state; for this reason, we use the "tsc_ns"
	 * input parameter (TSC converted to nanoseconds) the caller
	 * has passed us as the epoch value instead.
	 */

	if (xntbase_periodic_p(xnthread_time_base(thread)))
		return xntimer_get_timeout(timer);

	timeout = xntimer_get_date(timer);

	if (timeout <= tsc_ns)
		return 1;

	return timeout - tsc_ns;
}

static inline xnticks_t xnthread_get_period(xnthread_t *thread)
{
	xnticks_t period = 0;

	/*
	 * The current thread period might be:
	 * - the value of the timer interval for periodic threads (ns/ticks)
	 * - or, the value of the alloted round-robin quantum (ticks)
	 * - or zero, meaning "no periodic activity".
	 */
       
	if (xntimer_running_p(&thread->ptimer))
		period = xntimer_get_interval(&thread->ptimer);
	else if (xnthread_test_state(thread,XNRRB))
		period = xnthread_time_slice(thread);

	return period;
}

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#endif /* !_XENO_NUCLEUS_THREAD_H */
