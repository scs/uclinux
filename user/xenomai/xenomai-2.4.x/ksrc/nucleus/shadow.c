/*!\file shadow.c
 * \brief Real-time shadow services.
 * \author Philippe Gerum
 *
 * Copyright (C) 2001-2007 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004 The RTAI project <http://www.rtai.org>
 * Copyright (C) 2004 The HYADES project <http://www.hyades-itea.org>
 * Copyright (C) 2005 The Xenomai project <http://www.xenomai.org>
 * Copyright (C) 2006 Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>
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
 * \ingroup shadow
 */

/*!
 * \ingroup nucleus
 * \defgroup shadow Real-time shadow services.
 *
 * Real-time shadow services.
 *
 *@{*/

#include <stdarg.h>
#include <linux/unistd.h>
#include <linux/wait.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <asm/signal.h>
#include <nucleus/pod.h>
#include <nucleus/heap.h>
#include <nucleus/synch.h>
#include <nucleus/module.h>
#include <nucleus/shadow.h>
#include <nucleus/core.h>
#include <nucleus/jhash.h>
#include <nucleus/ppd.h>
#include <nucleus/trace.h>
#include <nucleus/stat.h>
#include <asm/xenomai/features.h>
#include <asm/xenomai/syscall.h>
#include <asm/xenomai/bits/shadow.h>

/* debug support */
#include <nucleus/assert.h>

#ifndef CONFIG_XENO_OPT_DEBUG_NUCLEUS
#define CONFIG_XENO_OPT_DEBUG_NUCLEUS  0
#endif

static int xn_gid_arg = -1;
module_param_named(xenomai_gid, xn_gid_arg, int, 0644);
MODULE_PARM_DESC(xenomai_gid, "GID of the group with access to Xenomai services");

int nkthrptd;

int nkerrptd;

struct xnskin_slot muxtable[XENOMAI_MUX_NR];

static struct __gatekeeper {

	struct task_struct *server;
	wait_queue_head_t waitq;
	struct linux_semaphore sync;
	xnthread_t *thread;
	struct xnrpi {
		DECLARE_XNLOCK(lock);
		xnsched_queue_t threadq;
	} rpislot;

} gatekeeper[XNARCH_NR_CPUS];

static int lostage_apc;

static struct __lostagerq {

	int in, out;

	struct {
#define LO_START_REQ  0
#define LO_WAKEUP_REQ 1
#define LO_RENICE_REQ 2
#define LO_SIGGRP_REQ 3
#define LO_SIGTHR_REQ 4
#define LO_UNMAP_REQ  5
		int type;
		struct task_struct *task;
		int arg;
#define LO_MAX_REQUESTS 64	/* Must be a ^2 */
	} req[LO_MAX_REQUESTS];

} lostagerq[XNARCH_NR_CPUS];

#define get_switch_lock_owner() \
switch_lock_owner[task_cpu(current)]

#define set_switch_lock_owner(t) \
do { \
   switch_lock_owner[task_cpu(t)] = t; \
} while(0)

static struct task_struct *switch_lock_owner[XNARCH_NR_CPUS];

static int nucleus_muxid = -1;

static DECLARE_MUTEX(completion_mutex);

void xnpod_declare_iface_proc(struct xnskin_slot *iface);

void xnpod_discard_iface_proc(const char *iface);

#ifdef CONFIG_XENO_OPT_PRIOCPL

/*
 * Priority inheritance by the root thread (RPI) of some real-time
 * priority is used to bind the Linux and Xenomai schedulers with
 * respect to a given real-time thread, which migrates from primary to
 * secondary execution mode. In effect, this means upgrading the root
 * thread priority to the one of the migrating thread, so that the
 * Linux kernel - as a whole - inherits the priority of the thread
 * that leaves the Xenomai domain for a while, typically to perform
 * regular Linux system calls, process Linux-originated signals and so
 * on. This is what makes a real-time shadow able to access the Linux
 * services seamlessly, from the application POV.
 *
 * To do that, we have to track real-time threads as they move to/from
 * the Linux domain (see xnshadow_relax/xnshadow_harden), so that we
 * always have a clear picture of which priority the root thread needs
 * to be given at any point in time, in order to preserve the priority
 * scheme consistent across both schedulers. In practice, this means
 * that a real-time thread with a current priority of, say 27,
 * Xenomai-wise (i.e. xnthread_current_priority(thread)) would cause
 * the root thread to inherit the same priority value, so that any
 * Xenomai thread below (or at) this level would not preempt the Linux
 * kernel while running on behalf of the migrated thread. This mapping
 * only concerns Xenomai threads underlaid by Linux tasks in the
 * SCHED_FIFO class, some of them may operate in the
 * SCHED_OTHER/SCHED_NORMAL class and as such are excluded from the
 * RPI management.
 *
 * When the Xenomai priority value does not fit in the [1..99]
 * SCHED_FIFO bounds exhibited by the Linux kernel, then such value is
 * constrained to those respective bounds, so beware: a real-time
 * thread with a Xenomai priority of 240 migrating to the secondary
 * mode would have the same priority in the Linux scheduler than
 * another thread with a priority of 239, i.e. SCHED_FIFO(99)
 * Linux-wise. In contrast, everything in the [1..99] range
 * Xenomai-wise perfectly maps to a distinct SCHED_FIFO priority
 * level. On a more general note, Xenomai's RPI management is NOT
 * meant to make the Linux kernel deterministic; threads operating in
 * relaxed mode would still potentially incur priority inversions and
 * unbounded execution times of the kernel code. But, it is meant to
 * maintain a consistent priority scheme for real-time threads across
 * domain migrations, which under a number of circumstances, is much
 * better than losing the Xenomai priority entirely.
 *
 * Implementation-wise, a list of all the currently relaxed Xenomai
 * threads (rpi_push) is maintained for each CPU in the corresponding
 * gatekeeper slot (i.e. struct gatekeeper::rpislot.threadq). Threads
 * are removed from this queue (rpi_pop) as they 1) go back to primary
 * mode, or 2) exit.  Each time a relaxed Xenomai thread is scheduled
 * in by the Linux scheduler, the root thread inherits its priority
 * (rpi_switch). Each time the gatekeeper processes a request to move
 * a relaxed thread back to primary mode, the latter thread is popped
 * from the RPI list, and the root thread inherits the Xenomai
 * priority of the thread leading the RPI list after the removal. If
 * no other thread is currently relaxed, the root thread is given back
 * its base priority, i.e. the lowest available level.
 */

#define rpi_p(t)	((t)->rpi != NULL)

static inline void rpi_init_gk(struct __gatekeeper *gk)
{
	struct xnrpi *rpislot = &gk->rpislot;
	xnlock_init(&rpislot->lock);
	sched_initpq(&rpislot->threadq, XNCORE_MIN_PRIO, XNCORE_MAX_PRIO);
}

static inline void rpi_none(xnthread_t *thread)
{
	thread->rpi = NULL;
	xnarch_memory_barrier();
}

static void rpi_push(xnthread_t *thread, int cpu)
{
	struct xnrpi *rpislot = &gatekeeper[cpu].rpislot;
	xnthread_t *top;
	int prio;
	spl_t s;

	/*
	 * The purpose of the following code is to enqueue the thread
	 * whenever it involves RPI, and determine which priority to
	 * pick next for the root thread (i.e. the highest among RPI
	 * enabled threads, or the base level if none exists).
	 */
	if (likely(xnthread_user_task(thread)->policy == SCHED_FIFO &&
		   !xnthread_test_state(thread, XNRPIOFF))) {
		xnlock_get_irqsave(&rpislot->lock, s);

		if (XENO_DEBUG(NUCLEUS) && rpi_p(thread))
			xnpod_fatal("re-enqueuing a relaxed thread in the RPI queue");

		sched_insertpqf(&rpislot->threadq, &thread->xlink, xnthread_current_priority(thread));
		thread->rpi = rpislot;

		top = link2thread(sched_getheadpq(&rpislot->threadq), xlink);
		prio = xnthread_current_priority(top);
		xnlock_put_irqrestore(&rpislot->lock, s);
	} else
		prio = XNCORE_IDLE_PRIO;

	if (xnpod_root_priority(cpu) != prio)
		xnpod_renice_root(cpu, prio);
}

static void rpi_pop(xnthread_t *thread)
{
	int cpu = rthal_processor_id();
	struct xnrpi *rpislot = &gatekeeper[cpu].rpislot;
	int prio;
	spl_t s;

	xnlock_get_irqsave(&rpislot->lock, s);

	/* Make sure we don't try to unlink a shadow which is not
	   linked to the local RPI queue. This may happen in case a
	   hardening thread is migrated by the kernel while in flight
	   to the primary mode. */

	if (likely(thread->rpi == rpislot)) {
		sched_removepq(&rpislot->threadq, &thread->xlink);
		rpi_none(thread);
	} else if (!rpi_p(thread)) {
		xnlock_put_irqrestore(&rpislot->lock, s);
		return;
	}

	if (likely(sched_emptypq_p(&rpislot->threadq)))
		prio = XNCORE_IDLE_PRIO;
	else {
		xnpholder_t *pholder = sched_getheadpq(&rpislot->threadq);
		xnthread_t *top = link2thread(pholder, xlink);
		prio = xnthread_current_priority(top);
	}

	xnlock_put_irqrestore(&rpislot->lock, s);

	if (xnpod_root_priority(cpu) != prio)
		xnpod_renice_root(cpu, prio);
}

static void rpi_update(xnthread_t *thread)
{
	int cpu = rthal_processor_id();
	struct xnrpi *rpislot = &gatekeeper[cpu].rpislot;
	spl_t s;

	xnlock_get_irqsave(&rpislot->lock, s);

	if (rpi_p(thread)) {
		sched_removepq(&rpislot->threadq, &thread->xlink);
		rpi_none(thread);
		rpi_push(thread, cpu);
	}

	xnlock_put_irqrestore(&rpislot->lock, s);
}

#ifdef CONFIG_SMP

static void rpi_clear_remote(xnthread_t *thread)
{
	struct xnrpi *rpislot;
	int rcpu = -1;
	spl_t s;

	/*
	 * This is the only place where we may touch a remote RPI slot
	 * (after a migration within the Linux domain), so let's use
	 * the backlink pointer the thread provides to fetch the
	 * actual slot it is supposed to be linked to, _not_ the
	 * gatekeeper's RPI slot for the current CPU.
	 *
	 * BIG FAT WARNING: The nklock must NOT be held when entering
	 * this routine, otherwise a deadlock would be possible,
	 * caused by conflicting locking sequences between the per-CPU
	 * RPI lock and the nklock.
	 */

	if (XENO_DEBUG(NUCLEUS) && xnlock_is_owner(&nklock))
		xnpod_fatal("nklock held while calling %s - this may deadlock!",
			    __FUNCTION__);

	rpislot = thread->rpi;

	if (unlikely(rpislot == NULL))
		return;

	xnlock_get_irqsave(&rpislot->lock, s);

	/* The RPI slot - if present - is always valid, and won't
	 * change since the thread is resuming on this CPU and cannot
	 * migrate under our feet. We may grab the remote slot lock
	 * now. */

	sched_removepq(&rpislot->threadq, &thread->xlink);
	rpi_none(thread);

	if (sched_emptypq_p(&rpislot->threadq))
		rcpu = container_of(rpislot, struct __gatekeeper, rpislot) - gatekeeper;

	xnlock_put_irqrestore(&rpislot->lock, s);

	/*
	 * Ok, this one is not trivial. Unless a relaxed shadow has
	 * forced its CPU affinity, it may migrate to another CPU as a
	 * result of Linux's load balancing strategy. If the last
	 * relaxed Xenomai thread migrates, there is no way for
	 * rpi_switch() to lower the root thread priority on the
	 * source CPU, since do_schedule_event() is only called for
	 * incoming/outgoing Xenomai shadows. This would leave the
	 * Xenomai root thread for the source CPU with a boosted
	 * priority. To prevent this, we send an IPI from the
	 * destination CPU to the source CPU when a migration is
	 * detected, so that the latter could adjust its root thread
	 * priority.
	 */
	if (rcpu != -1 && rcpu != rthal_processor_id()) {
		xnsched_t *rsched = xnpod_sched_slot(rcpu);
		if (!testbits(rsched->status, XNRPICK)) {
			xnarch_cpumask_t cpumask;
			setbits(rsched->status, XNRPICK);
			xnarch_cpus_clear(cpumask);
			xnarch_cpu_set(rcpu, cpumask);
			xnarch_send_ipi(cpumask);
		}
	}
}

static void rpi_migrate(xnthread_t *thread)
{
	rpi_clear_remote(thread);
	rpi_push(thread, rthal_processor_id());
}

#else  /* !CONFIG_SMP */
#define rpi_clear_remote(t)	do { } while(0)
#define rpi_migrate(t)		do { } while(0)
#endif	/* !CONFIG_SMP */

static inline void rpi_switch(struct task_struct *next)
{
	int cpu = rthal_processor_id();
	xnthread_t *threadin, *threadout;
	struct xnrpi *rpislot;
	int oldprio, newprio;
	spl_t s;

	threadout = xnshadow_thread(current);
	threadin = xnshadow_thread(next);
	rpislot = &gatekeeper[cpu].rpislot;
	oldprio = xnpod_root_priority(cpu);

	if (threadout &&
	    current->state != TASK_RUNNING &&
	    !xnthread_test_info(threadout, XNATOMIC)) {
		/*
		 * A blocked Linux task must be removed from the RPI
		 * list. Checking for XNATOMIC prevents from unlinking
		 * a thread which is currently in flight to the
		 * primary domain (see xnshadow_harden()); not doing
		 * so would open a tiny window for priority
		 * inversion.
		 *
		 * BIG FAT WARNING: Do not consider a blocked thread
		 * linked to another processor's RPI list for removal,
		 * since this may happen if such thread immediately
		 * resumes on the remote CPU.
		 */
		xnlock_get_irqsave(&rpislot->lock, s);
		if (threadout->rpi == rpislot) {
			sched_removepq(&rpislot->threadq, &threadout->xlink);
			rpi_none(threadout);
		}
		xnlock_put_irqrestore(&rpislot->lock, s);
	}

	if (threadin == NULL ||
	    next->policy != SCHED_FIFO ||
	    xnthread_test_state(threadin, XNRPIOFF)) {
		xnlock_get_irqsave(&rpislot->lock, s);

		if (!sched_emptypq_p(&rpislot->threadq)) {
			xnpholder_t *pholder = sched_getheadpq(&rpislot->threadq);
			xnthread_t *top = link2thread(pholder, xlink);
			newprio = xnthread_current_priority(top);
		} else
			newprio = XNCORE_IDLE_PRIO;

		xnlock_put_irqrestore(&rpislot->lock, s);
		goto boost_root;
	}

	newprio = xnthread_current_priority(threadin);

	/* Be careful about two issues affecting a task's RPI state
	 * here:
	 *
	 * 1) A relaxed shadow awakes (Linux-wise) after a blocked
	 * state, which caused it to be removed from the RPI list
	 * while it was sleeping; we have to link it back again as it
	 * resumes.
	 *
	 * 2) A relaxed shadow has migrated from another CPU, in that
	 * case, we end up having a thread linked to an RPI slot which
	 * is _not_ the current gatekeeper's one [sidenote: we don't
	 * care about migrations handled by Xenomai in primary mode,
	 * since the shadow would not be linked to any RPI queue in
	 * the first place].  Since a migration must happen while the
	 * task is off the CPU Linux-wise, rpi_switch() will be called
	 * upon resumption on the target CPU by the Linux
	 * scheduler. At that point, we just need to update the RPI
	 * information in case the RPI queue backlink does not match
	 * the gatekeeper's RPI slot for the current CPU. */

	if (unlikely(threadin->rpi == NULL)) {
		if (!xnthread_test_state(threadin, XNDORMANT)) {
			xnlock_get_irqsave(&rpislot->lock, s);
			sched_insertpqf(&rpislot->threadq, &threadin->xlink, newprio);
			threadin->rpi = rpislot;
			xnlock_put_irqrestore(&rpislot->lock, s);
		}
	} else if (unlikely(threadin->rpi != rpislot))
		/* We hold no lock here. */
		rpi_migrate(threadin);

boost_root:

	if (newprio == oldprio)
		return;

	xnpod_renice_root(cpu, newprio);

	if (newprio < oldprio)
		/* Subtle: by downgrading the root thread priority,
		   some higher priority thread might well become
		   eligible for execution instead of us. Since
		   xnpod_renice_root() does not reschedule (and must
		   _not_ in most of other cases), let's call the
		   rescheduling procedure ourselves. */
		xnpod_schedule();
}

static inline void rpi_clear_local(xnthread_t *thread)
{
	int cpu = rthal_processor_id();
	if (thread == NULL && xnpod_root_priority(cpu) != XNCORE_IDLE_PRIO)
		xnpod_renice_root(cpu, XNCORE_IDLE_PRIO);
}

#ifdef CONFIG_SMP

void xnshadow_rpi_check(void)
{
	/*
	 * BIG FAT WARNING: interrupts should be off on entry,
	 * otherwise, we would have to mask them while testing the
	 * queue for emptiness _and_ demoting the boost level.
	 */
	int cpu = rthal_processor_id();
	struct xnrpi *rpislot = &gatekeeper[cpu].rpislot;
	int norpi;
 
 	xnlock_get(&rpislot->lock);
 	norpi = sched_emptypq_p(&rpislot->threadq);
 	xnlock_put(&rpislot->lock);

	if (norpi && xnpod_root_priority(cpu) != XNCORE_IDLE_PRIO)
		xnpod_renice_root(cpu, XNCORE_IDLE_PRIO);
}

#endif	/* CONFIG_SMP */
 
#else

#define rpi_p(t)		(0)
#define rpi_init_gk(gk)		do { } while(0)
#define rpi_clear_local(t)	do { } while(0)
#define rpi_clear_remote(t)	do { } while(0)
#define rpi_push(t, cpu)	do { } while(0)
#define rpi_pop(t)		do { } while(0)
#define rpi_update(t)		do { } while(0)
#define rpi_switch(n)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_RPIDISABLE */

#ifdef CONFIG_XENO_OPT_ISHIELD

static rthal_pipeline_stage_t irq_shield;

static cpumask_t shielded_cpus, unshielded_cpus;

static unsigned long shield_sync;

static void engage_irq_shield(void)
{
	unsigned long flags;
	int cpu;

	rthal_local_irq_save_hw(flags);

	cpu = rthal_processor_id();

	if (xnarch_cpu_test_and_set(cpu, shielded_cpus))
		goto unmask_and_exit;

	while (test_bit(0, &shield_sync))
		/* We don't want to defer the actual shielding for too
		 * long, so we spin IRQS off. */
		cpu_relax();

	xnarch_cpu_clear(cpu, unshielded_cpus);

	xnarch_lock_xirqs(&irq_shield, cpu);

      unmask_and_exit:

	rthal_local_irq_restore_hw(flags);
}

static void disengage_irq_shield(void)
{
	unsigned long flags;
	int cpu;

	rthal_local_irq_save_hw(flags);

	cpu = rthal_processor_id();

	if (xnarch_cpu_test_and_set(cpu, unshielded_cpus))
		goto unmask_and_exit;

	/* Prevent other CPUs from engaging the shield while we
	   attempt to disengage. */
	set_bit(0, &shield_sync);

	/* Ok, this one is now unshielded. */
	xnarch_cpu_clear(cpu, shielded_cpus);

	smp_mb__after_clear_bit();

	/* We want the shield to be either engaged on all CPUs (i.e. if at
	   least one CPU asked for shielding), or disengaged on all
	   (i.e. if no CPU asked for shielding). */

	if (!xnarch_cpus_empty(shielded_cpus))
		goto clear_sync;

	/* At this point we know that we are the last CPU to disengage the
	   shield, so we just unlock the external IRQs for all CPUs, and
	   trigger an IPI on everyone but self to make sure that the
	   remote interrupt logs will be played. We also forcibly unstall
	   the shield stage on the local CPU in order to flush it the same
	   way. */

	xnarch_unlock_xirqs(&irq_shield, cpu);

#ifdef CONFIG_SMP
	{
		cpumask_t other_cpus = xnarch_cpu_online_map;
		xnarch_cpu_clear(cpu, other_cpus);
		rthal_send_ipi(RTHAL_SERVICE_IPI1, other_cpus);
	}
#endif /* CONFIG_SMP */

	rthal_stage_irq_enable(&irq_shield);

clear_sync:

	clear_bit(0, &shield_sync);

	smp_mb__after_clear_bit();

unmask_and_exit:

	rthal_local_irq_restore_hw(flags);
}

static void shield_handler(unsigned irq, void *cookie)
{
#ifdef CONFIG_SMP
	if (irq != RTHAL_SERVICE_IPI1)
#endif /* CONFIG_SMP */
		rthal_propagate_irq(irq);
}

static inline void do_shield_domain_entry(void)
{
	xnarch_grab_xirqs(&shield_handler);
}

RTHAL_DECLARE_DOMAIN(shield_domain_entry);

static inline int ishield_init(void)
{
	if (rthal_register_domain(&irq_shield,
				  "IShield",
				  0x53484c44,
				  RTHAL_ROOT_PRIO + 50, &shield_domain_entry))
		return -EBUSY;

	shielded_cpus = CPU_MASK_NONE;
	unshielded_cpus = xnarch_cpu_online_map;

	return 0;
}

static inline void ishield_cleanup(void)
{
	rthal_unregister_domain(&irq_shield);
}

static inline void ishield_on(xnthread_t *thread)
{
	if (xnthread_test_state(thread, XNSHIELD))
		engage_irq_shield();
}

static inline void ishield_off(void)
{
	disengage_irq_shield();
}

static inline void ishield_reset(xnthread_t *thread)
{
	if (xnthread_test_state(thread, XNSHIELD))
		engage_irq_shield();
	else
		disengage_irq_shield();
}

void xnshadow_reset_shield(void)
{
	xnthread_t *thread = xnshadow_thread(current);

	if (!thread)
		return;

	ishield_reset(thread);
}

#else /* !CONFIG_XENO_OPT_ISHIELD */

#define ishield_init()		0
#define ishield_cleanup()	do { } while(0)
#define ishield_on(t)		do { } while(0)
#define ishield_off()		do { } while(0)
#define ishield_reset(t)	do { } while(0)

#endif /* !CONFIG_XENO_OPT_ISHIELD */

static xnqueue_t *ppd_hash;
#define PPD_HASH_SIZE 13

union xnshadow_ppd_hkey {
	struct mm_struct *mm;
	uint32_t val;
};

/* ppd holder with the same mm collide and are stored contiguously in the same
   bucket, so that they can all be destroyed with only one hash lookup by
   ppd_remove_mm. */
static unsigned ppd_lookup_inner(xnqueue_t **pq,
				 xnshadow_ppd_t ** pholder, xnshadow_ppd_key_t * pkey)
{
	union xnshadow_ppd_hkey key = {.mm = pkey->mm };
	unsigned bucket = jhash2(&key.val, sizeof(key) / sizeof(uint32_t), 0);
	xnshadow_ppd_t *ppd;
	xnholder_t *holder;

	*pq = &ppd_hash[bucket % PPD_HASH_SIZE];
	holder = getheadq(*pq);

	if (!holder) {
		*pholder = NULL;
		return 0;
	}

	do {
		ppd = link2ppd(holder);
		holder = nextq(*pq, holder);
	}
	while (holder &&
	       (ppd->key.mm < pkey->mm ||
		(ppd->key.mm == pkey->mm && ppd->key.muxid < pkey->muxid)));

	if (ppd->key.mm == pkey->mm && ppd->key.muxid == pkey->muxid) {
		/* found it, return it. */
		*pholder = ppd;
		return 1;
	}

	/* not found, return successor for insertion. */
	if (ppd->key.mm < pkey->mm ||
	    (ppd->key.mm == pkey->mm && ppd->key.muxid < pkey->muxid))
		*pholder = holder ? link2ppd(holder) : NULL;
	else
		*pholder = ppd;

	return 0;
}

static int ppd_insert(xnshadow_ppd_t * holder)
{
	xnshadow_ppd_t *next;
	xnqueue_t *q;
	unsigned found;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	found = ppd_lookup_inner(&q, &next, &holder->key);
	if (found) {
		xnlock_put_irqrestore(&nklock, s);
		return -EBUSY;
	}

	inith(&holder->link);
	if (next)
		insertq(q, &next->link, &holder->link);
	else
		appendq(q, &holder->link);
	xnlock_put_irqrestore(&nklock, s);

	return 0;
}

/* will be called by skin code, nklock locked irqs off. */
static xnshadow_ppd_t *ppd_lookup(unsigned muxid, struct mm_struct *mm)
{
	xnshadow_ppd_t *holder;
	xnshadow_ppd_key_t key;
	unsigned found;
	xnqueue_t *q;

	key.muxid = muxid;
	key.mm = mm;
	found = ppd_lookup_inner(&q, &holder, &key);

	if (!found)
		return NULL;

	return holder;
}

static void ppd_remove(xnshadow_ppd_t * holder)
{
	unsigned found;
	xnqueue_t *q;
	spl_t s;

	xnlock_get_irqsave(&nklock, s);
	found = ppd_lookup_inner(&q, &holder, &holder->key);

	if (found)
		removeq(q, &holder->link);

	xnlock_put_irqrestore(&nklock, s);
}

static inline void ppd_remove_mm(struct mm_struct *mm,
				 void (*destructor) (xnshadow_ppd_t *))
{
	xnshadow_ppd_key_t key;
	xnshadow_ppd_t *ppd;
	xnholder_t *holder;
	xnqueue_t *q;
	spl_t s;

	key.muxid = 0;
	key.mm = mm;
	xnlock_get_irqsave(&nklock, s);
	ppd_lookup_inner(&q, &ppd, &key);

	while (ppd && ppd->key.mm == mm) {
		holder = nextq(q, &ppd->link);
		removeq(q, &ppd->link);
		xnlock_put_irqrestore(&nklock, s);
		/* releasing nklock is safe here, if we assume that no insertion for the
		   same mm will take place while we are running xnpod_remove_mm. */
		destructor(ppd);

		ppd = holder ? link2ppd(holder) : NULL;
		xnlock_get_irqsave(&nklock, s);
	}

	xnlock_put_irqrestore(&nklock, s);
}

static inline void request_syscall_restart(xnthread_t *thread,
					   struct pt_regs *regs,
					   int sysflags)
{
	int notify = 0;

	if (xnthread_test_info(thread, XNKICKED)) {
		if (__xn_interrupted_p(regs)) {
			__xn_error_return(regs,
					  (sysflags & __xn_exec_norestart) ?
					  -ERESTARTNOHAND : -ERESTARTSYS);
			notify = 1;
		}

		xnthread_clear_info(thread, XNKICKED);
	}

	xnshadow_relax(notify);
}

static inline void set_linux_task_priority(struct task_struct *p, int prio)
{
	if (rthal_setsched_root(p, prio ? SCHED_FIFO : SCHED_NORMAL, prio) < 0)
		printk(KERN_WARNING
		       "Xenomai: invalid Linux priority level: %d, task=%s\n",
		       prio, p->comm);
}

static inline void lock_timers(void)
{
	xnarch_atomic_inc(&nkpod->timerlck);
	setbits(nktbase.status, XNTBLCK);
}

static inline void unlock_timers(void)
{
	if (xnarch_atomic_dec_and_test(&nkpod->timerlck))
		clrbits(nktbase.status, XNTBLCK);
}

static void xnshadow_dereference_skin(unsigned magic)
{
	unsigned muxid;

	for (muxid = 0; muxid < XENOMAI_MUX_NR; muxid++) {
		if (muxtable[muxid].props && muxtable[muxid].props->magic == magic) {
			if (xnarch_atomic_dec_and_test(&muxtable[0].refcnt))
				xnarch_atomic_dec(&muxtable[0].refcnt);
			if (xnarch_atomic_dec_and_test(&muxtable[muxid].refcnt))

				/* We were the last thread, decrement the counter,
				   since it was incremented by the xn_sys_bind
				   operation. */
				xnarch_atomic_dec(&muxtable[muxid].refcnt);
			if (muxtable[muxid].props->module)
				module_put(muxtable[muxid].props->module);

			break;
		}
	}
}

static void lostage_handler(void *cookie)
{
	int cpu = smp_processor_id(), reqnum, sig;
	struct __lostagerq *rq = &lostagerq[cpu];

	while ((reqnum = rq->out) != rq->in) {
		struct task_struct *p = rq->req[reqnum].task;
		rq->out = (reqnum + 1) & (LO_MAX_REQUESTS - 1);

		trace_mark(xn_nucleus_lostage_work, "reqnum %d comm %s pid %d",
			   reqnum, p->comm, p->pid);

		switch (rq->req[reqnum].type) {
		case LO_UNMAP_REQ:

			xnshadow_dereference_skin(rq->req[reqnum].arg);

			/* fall through */
		case LO_WAKEUP_REQ:

			/* We need to downgrade the root thread
			   priority whenever the APC runs over a
			   non-shadow, so that the temporary boost we
			   applied in xnshadow_relax() is not
			   spuriously inherited by the latter until
			   the relaxed shadow actually resumes in
			   secondary mode. */

			rpi_clear_local(xnshadow_thread(current));

			/* fall through */
		case LO_START_REQ:

			if (xnshadow_thread(p))
				ishield_on(xnshadow_thread(p));

			wake_up_process(p);

			if (xnsched_resched_p())
				xnpod_schedule();

			break;

		case LO_RENICE_REQ:

			set_linux_task_priority(p, rq->req[reqnum].arg);
			break;

		case LO_SIGTHR_REQ:

			sig = rq->req[reqnum].arg;
			send_sig(sig, p, 1);
			break;

		case LO_SIGGRP_REQ:

			sig = rq->req[reqnum].arg;
			kill_proc(p->pid, sig, 1);
			break;
		}
	}
}

static void schedule_linux_call(int type, struct task_struct *p, int arg)
{
	/* Do _not_ use smp_processor_id() here so we don't trigger Linux
	   preemption debug traps inadvertently (see lib/smp_processor_id.c). */
	int cpu = rthal_processor_id(), reqnum;
	struct __lostagerq *rq = &lostagerq[cpu];
	spl_t s;

	XENO_ASSERT(NUCLEUS, p,
		xnpod_fatal("schedule_linux_call() invoked "
			    "with NULL task pointer (req=%d, arg=%d)?!", type,
			    arg);
		);

	splhigh(s);

	reqnum = rq->in;

	if (XENO_DEBUG(NUCLEUS) &&
	    ((reqnum + 1) & (LO_MAX_REQUESTS - 1)) == rq->out)
	    xnpod_fatal("lostage queue overflow on CPU %d! "
			"Increase LO_MAX_REQUESTS", cpu);

	rq->req[reqnum].type = type;
	rq->req[reqnum].task = p;
	rq->req[reqnum].arg = arg;
	rq->in = (reqnum + 1) & (LO_MAX_REQUESTS - 1);
	
	splexit(s);

	rthal_apc_schedule(lostage_apc);
}

static inline int normalize_priority(int prio)
{
	return prio < MAX_RT_PRIO ? prio : MAX_RT_PRIO - 1;
}

static int gatekeeper_thread(void *data)
{
	struct __gatekeeper *gk = (struct __gatekeeper *)data;
	struct task_struct *this_task = current;
	DECLARE_WAITQUEUE(wait, this_task);
	int cpu = gk - &gatekeeper[0];
	xnthread_t *thread;
	cpumask_t cpumask;
	spl_t s;

	this_task->flags |= PF_NOFREEZE;
	sigfillset(&this_task->blocked);
	cpumask = cpumask_of_cpu(cpu);
	set_cpus_allowed(this_task, cpumask);
	set_linux_task_priority(this_task, MAX_RT_PRIO - 1);

	init_waitqueue_head(&gk->waitq);
	add_wait_queue_exclusive(&gk->waitq, &wait);

	up(&gk->sync);		/* Sync with xnshadow_mount(). */

	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		up(&gk->sync);	/* Make the request token available. */
		schedule();

		if (kthread_should_stop())
			break;

		/* Real-time shadow TCBs are always removed on behalf
		   of the killed thread. */

		thread = gk->thread;

		/* In the very rare case where the requestor has been awaken
		   by a signal before we have been able to process the
		   pending request, just ignore the latter. */

		if ((xnthread_user_task(thread)->state & ~TASK_ATOMICSWITCH)
		    == TASK_INTERRUPTIBLE) {
			rpi_pop(thread);
			xnlock_get_irqsave(&nklock, s);
#ifdef CONFIG_SMP
			/* If the task changed its CPU while in secondary mode,
			   change the CPU of the underlying Xenomai shadow too. We
			   do not migrate the thread timers here, it would not
			   work. For a "full" migration comprising timers, using
			   xnpod_migrate_thread is required. */
			thread->sched = xnpod_sched_slot(cpu);
#endif /* CONFIG_SMP */
			xnpod_resume_thread(thread, XNRELAX);
			ishield_off();
			xnpod_schedule();
			xnlock_put_irqrestore(&nklock, s);
		}
	}

	return 0;
}

/*! 
 * @internal
 * \fn int xnshadow_harden(void);
 * \brief Migrate a Linux task to the Xenomai domain.
 *
 * This service causes the transition of "current" from the Linux
 * domain to Xenomai. This is obtained by asking the gatekeeper to resume
 * the shadow mated with "current" then triggering the rescheduling
 * procedure in the Xenomai domain. The shadow will resume in the Xenomai
 * domain as returning from schedule().
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - User-space thread operating in secondary (i.e. relaxed) mode.
 *
 * Rescheduling: always.
 */

int xnshadow_harden(void)
{
	struct task_struct *this_task = current;
	struct __gatekeeper *gk;
	xnthread_t *thread;
	int gk_cpu;

redo:
	gk_cpu = task_cpu(this_task);
	thread = xnshadow_thread(this_task);

	if (!thread)
		return -EPERM;

	gk = &gatekeeper[gk_cpu];

	if (signal_pending(this_task) || down_interruptible(&gk->sync))
		/* Grab the request token. */
		return -ERESTARTSYS;

	preempt_disable();

	/* Assume that we might have been migrated while waiting for
	 * the token. Redo acquisition in such a case, so that we
	 * don't mistakenly send the request to the wrong
	 * gatekeeper. */

	if (gk_cpu != task_cpu(this_task)) {
		preempt_enable();
		up(&gk->sync);
		goto redo;
	}

	/* Set up the request to move "current" from the Linux domain to
	   the Xenomai domain. This will cause the shadow thread to resume
	   using the register state of the current Linux task. For this to
	   happen, we set up the migration data, prepare to suspend the
	   current task, wake up the gatekeeper which will perform the
	   actual transition, then schedule out. Most of this sequence
	   must be atomic, and we get this guarantee by disabling
	   preemption and using the TASK_ATOMICSWITCH cumulative state
	   provided by Adeos to Linux tasks. */

	trace_mark(xn_nucleus_shadow_gohard,
		   "thread %p thread_name %s comm %s",
		   thread, xnthread_name(thread), this_task->comm);

	gk->thread = thread;
	xnthread_set_info(thread, XNATOMIC);
	set_current_state(TASK_INTERRUPTIBLE | TASK_ATOMICSWITCH);
	wake_up_interruptible_sync(&gk->waitq);
	schedule();	/* Will preempt_enable() thanks to TASK_ATOMICSWITCH */
	xnthread_clear_info(thread, XNATOMIC);

	/* Rare case: we might have been awaken by a signal before the
	   gatekeeper sent us to primary mode. Since TASK_UNINTERRUPTIBLE
	   is unavailable to us without wrecking the runqueue's count of
	   uniniterruptible tasks, we just notice the issue and gracefully
	   fail; the caller will have to process this signal anyway. */

	if (rthal_current_domain == rthal_root_domain) {
		if (XENO_DEBUG(NUCLEUS) && (!signal_pending(this_task)
		    || this_task->state != TASK_RUNNING))
			xnpod_fatal
			    ("xnshadow_harden() failed for thread %s[%d]",
			     thread->name, xnthread_user_pid(thread));
		return -ERESTARTSYS;
	}

	/* "current" is now running into the Xenomai domain. */

#ifdef CONFIG_XENO_HW_FPU
	xnpod_switch_fpu(xnpod_current_sched());
#endif /* CONFIG_XENO_HW_FPU */

	xnarch_schedule_tail(this_task);

	if (xnthread_signaled_p(thread))
		xnpod_dispatch_signals();

	xnlock_clear_irqon(&nklock);

	/*
	 * Normally, we should not be linked to any RPI list at this
	 * point, except if Linux sent us to another CPU while in
	 * flight to the primary domain, waiting to be resumed by the
	 * gatekeeper; in such a case, we must unlink from the remote
	 * CPU's RPI list now.
	 */
	if (rpi_p(thread))
		rpi_clear_remote(thread);

	trace_mark(xn_nucleus_shadow_hardened, "thread %p thread_name %s",
		   thread, xnthread_name(thread));

	return 0;
}

/*! 
 * @internal
 * \fn void xnshadow_relax(int notify);
 * \brief Switch a shadow thread back to the Linux domain.
 *
 * This service yields the control of the running shadow back to
 * Linux. This is obtained by suspending the shadow and scheduling a
 * wake up call for the mated user task inside the Linux domain. The
 * Linux task will resume on return from xnpod_suspend_thread() on
 * behalf of the root thread.
 *
 * @param notify A boolean flag indicating whether threads monitored
 * from secondary mode switches should be sent a SIGXCPU signal. For
 * instance, some internal operations like task exit should not
 * trigger such signal.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - User-space thread operating in primary (i.e. harden) mode.
 *
 * Rescheduling: always.
 *
 * @note "current" is valid here since the shadow runs with the
 * properties of the Linux task.
 */

void xnshadow_relax(int notify)
{
	xnthread_t *thread = xnpod_current_thread();
	int prio;
	spl_t s;

	XENO_BUGON(NUCLEUS, xnthread_test_state(thread, XNROOT));

	/* Enqueue the request to move the running shadow from the Xenomai
	   domain to the Linux domain.  This will cause the Linux task
	   to resume using the register state of the shadow thread. */

	trace_mark(xn_nucleus_shadow_gorelax, "thread %p thread_name %s",
		  thread, xnthread_name(thread));

	ishield_on(thread);

	splhigh(s);

	schedule_linux_call(LO_WAKEUP_REQ, current, 0);

	rpi_push(thread, rthal_processor_id());

	clear_task_nowakeup(current);

	xnpod_suspend_thread(thread, XNRELAX, XN_INFINITE, XN_RELATIVE, NULL);

	splexit(s);

	if (XENO_DEBUG(NUCLEUS) && rthal_current_domain != rthal_root_domain)
		xnpod_fatal("xnshadow_relax() failed for thread %s[%d]",
			    thread->name, xnthread_user_pid(thread));

	prio = normalize_priority(xnthread_current_priority(thread));
	rthal_reenter_root(get_switch_lock_owner(),
			   prio ? SCHED_FIFO : SCHED_NORMAL, prio);

	xnstat_counter_inc(&thread->stat.ssw);	/* Account for secondary mode switch. */

	if (notify && xnthread_test_state(thread, XNTRAPSW))
		/* Help debugging spurious relaxes. */
		send_sig(SIGXCPU, current, 1);

#ifdef CONFIG_SMP
	/* If the shadow thread changed its CPU affinity while in
	   primary mode, reset the CPU affinity of its Linux
	   counter-part when returning to secondary mode. [Actually,
	   there is no service changing the CPU affinity from primary
	   mode available from the nucleus --rpm]. */
	if (xnthread_test_info(thread, XNAFFSET)) {
		xnthread_clear_info(thread, XNAFFSET);
		set_cpus_allowed(current, xnthread_affinity(thread));
	}
#endif /* CONFIG_SMP */

	/* "current" is now running into the Linux domain on behalf of the
	   root thread. */

	trace_mark(xn_nucleus_shadow_relaxed,
		   "thread %p thread_name %s comm %s",
		   thread, xnthread_name(thread), current->comm);
}

void xnshadow_exit(void)
{
	rthal_reenter_root(get_switch_lock_owner(),
			   current->rt_priority ? SCHED_FIFO : SCHED_NORMAL,
			   current->rt_priority);
	do_exit(0);
}

/*!
 * \fn int xnshadow_map(xnthread_t *thread, xncompletion_t __user *u_completion)
 * @internal
 * \brief Create a shadow thread context.
 *
 * This call maps a nucleus thread to the "current" Linux task.  The
 * priority and scheduling class of the underlying Linux task are not
 * affected; it is assumed that the interface library did set them
 * appropriately before issuing the shadow mapping request.
 *
 * @param thread The descriptor address of the new shadow thread to be
 * mapped to "current". This descriptor must have been previously
 * initialized by a call to xnpod_init_thread().
 *
 * @param u_completion is the address of an optional completion
 * descriptor aimed at synchronizing our parent thread with us. If
 * non-NULL, the information xnshadow_map() will store into the
 * completion block will be later used to wake up the parent thread
 * when the current shadow has been initialized. In the latter case,
 * the new shadow thread is left in a dormant state (XNDORMANT) after
 * its creation, leading to the suspension of "current" in the Linux
 * domain, only processing signals. Otherwise, the shadow thread is
 * immediately started and "current" immediately resumes in the Xenomai
 * domain from this service.
 *
 * @return 0 is returned on success. Otherwise:
 *
 * - -ERESTARTSYS is returned if the current Linux task has received a
 * signal, thus preventing the final migration to the Xenomai domain
 * (i.e. in order to process the signal in the Linux domain). This
 * error should not be considered as fatal.
 *
 * - -EPERM is returned if the shadow thread has been killed before
 * the current task had a chance to return to the caller. In such a
 * case, the real-time mapping operation has failed globally, and no
 * Xenomai resource remains attached to it.
 *
 * - -EINVAL is returned if the thread control block does not bear the
 * XNSHADOW bit.
 *
 * - -EBUSY is returned if either the current Linux task or the
 * associated shadow thread is already involved in a shadow mapping.
 *
 * Environments:
 *
 * This service can be called from:
 *
 * - Regular user-space process. 
 *
 * Rescheduling: always.
 *
 */

int xnshadow_map(xnthread_t *thread, xncompletion_t __user *u_completion)
{
	xnarch_cpumask_t affinity;
	unsigned muxid, magic;
	int err;

	if (!xnthread_test_state(thread, XNSHADOW))
		return -EINVAL;

	if (xnshadow_thread(current) || xnthread_test_state(thread, XNMAPPED))
		return -EBUSY;

#ifdef CONFIG_MMU
	if (!(current->mm->def_flags & VM_LOCKED))
		send_sig(SIGXCPU, current, 1);
	else
		if ((err = rthal_disable_ondemand_mappings(current)))
			return err;
#endif /* CONFIG_MMU */

	/* Increment the interface reference count. */
	magic = xnthread_get_magic(thread);

	for (muxid = 0; muxid < XENOMAI_MUX_NR; muxid++) {
		if (muxtable[muxid].props && muxtable[muxid].props->magic == magic) {
			xnarch_atomic_inc(&muxtable[muxid].refcnt);
			xnarch_atomic_inc(&muxtable[0].refcnt);
			if (muxtable[muxid].props->module
			    && !try_module_get(muxtable[muxid].props->module))
				return -ENOSYS;
			break;
		}
	}

	trace_mark(xn_nucleus_shadow_map,
		   "thread %p thread_name %s pid %d priority %d",
		   thread, xnthread_name(thread), current->pid,
		   xnthread_base_priority(thread));

	/* Switch on propagation of normal kernel events for the bound
	   task. This is basically a per-task event filter which
	   restricts event notifications (e.g. syscalls) to tasks
	   bearing the PF_EVNOTIFY flag, so that we don't uselessly
	   intercept those events when they happen to be caused by
	   plain (i.e. non-Xenomai) Linux tasks. */
	current->flags |= PF_EVNOTIFY;

	xnarch_init_shadow_tcb(xnthread_archtcb(thread), thread,
			       xnthread_name(thread));
	xnshadow_thrptd(current) = thread;
	xnthread_set_state(thread, XNMAPPED);
	xnpod_suspend_thread(thread, XNRELAX, XN_INFINITE, XN_RELATIVE, NULL);

	/* Restrict affinity to a single CPU of nkaffinity & current set. */
	xnarch_cpus_and(affinity, current->cpus_allowed, nkaffinity);
	affinity = xnarch_cpumask_of_cpu(xnarch_first_cpu(affinity));
	set_cpus_allowed(current, affinity);

	if (u_completion) {
 		/* We still have the XNDORMANT bit set, so we can't
 		 * link to the RPI queue which only links _runnable_
 		 * relaxed shadow. */
		xnshadow_signal_completion(u_completion, 0);
		return 0;
	}

	/* Nobody waits for us, so we may start the shadow immediately. */
	err = xnpod_start_thread(thread, 0, 0, affinity, NULL, NULL);

	if (err)
		return err;

	err = xnshadow_harden();

	xnarch_trace_pid(xnarch_user_pid(xnthread_archtcb(thread)),
			 xnthread_current_priority(thread));

	return err;
}

void xnshadow_unmap(xnthread_t *thread)
{
	struct task_struct *p;

	if (XENO_DEBUG(NUCLEUS) &&
	    !testbits(xnpod_current_sched()->status, XNKCOUT))
		xnpod_fatal("xnshadow_unmap() called from invalid context");

	p = xnthread_archtcb(thread)->user_task;

	xnthread_clear_state(thread, XNMAPPED);
	rpi_pop(thread);

	trace_mark(xn_nucleus_shadow_unmap,
		   "thread %p thread_name %s pid %d",
		   thread, xnthread_name(thread), p ? p->pid : -1);

	if (!p)
		return;

	XENO_ASSERT(NUCLEUS, p == current,
		    xnpod_fatal("%s invoked for a non-current task (t=%s/p=%s)",
				__FUNCTION__, thread->name, p->comm);
		);

	xnshadow_thrptd(p) = NULL;

	schedule_linux_call(LO_UNMAP_REQ, p, xnthread_get_magic(thread));
}

int xnshadow_wait_barrier(struct pt_regs *regs)
{
	xnthread_t *thread = xnshadow_thread(current);
	spl_t s;

	if (!thread)
		return -EPERM;

	xnlock_get_irqsave(&nklock, s);

	if (xnthread_test_state(thread, XNSTARTED)) {
		/* Already done -- no op. */
		xnlock_put_irqrestore(&nklock, s);
		goto release_task;
	}

	/* We must enter this call on behalf of the Linux domain. */
	set_current_state(TASK_INTERRUPTIBLE);
	xnlock_put_irqrestore(&nklock, s);

	schedule();

	if (signal_pending(current))
		return -ERESTARTSYS;

	if (!xnthread_test_state(thread, XNSTARTED))	/* Not really paranoid. */
		return -EPERM;

      release_task:

	if (__xn_reg_arg1(regs))
		__xn_copy_to_user(current,
				  (void __user *)__xn_reg_arg1(regs),
				  &thread->entry, sizeof(thread->entry));

	if (__xn_reg_arg2(regs))
		__xn_copy_to_user(current,
				  (void __user *)__xn_reg_arg2(regs),
				  &thread->cookie, sizeof(thread->cookie));

	return xnshadow_harden();
}

void xnshadow_start(xnthread_t *thread)
{
	struct task_struct *p = xnthread_archtcb(thread)->user_task;

	/* A shadow always starts in relaxed mode. */
	rpi_push(thread, xnsched_cpu(thread->sched));

	trace_mark(xn_nucleus_shadow_start, "thread %p thread_name %s",
		   thread, xnthread_name(thread));
	xnpod_resume_thread(thread, XNDORMANT);

	if (p->state == TASK_INTERRUPTIBLE)
		/* Wakeup the Linux mate waiting on the barrier. */
		schedule_linux_call(LO_START_REQ, p, 0);
}

void xnshadow_renice(xnthread_t *thread)
{
	/* Called with nklock locked, Xenomai interrupts off. */
	struct task_struct *p = xnthread_archtcb(thread)->user_task;

	/* We need to bound the priority values in the [1..MAX_RT_PRIO-1]
	   range, since the core pod's priority scale is a superset of
	   Linux's priority scale. */
	int prio = normalize_priority(xnthread_current_priority(thread));
	schedule_linux_call(LO_RENICE_REQ, p, prio);

	if (!xnthread_test_state(thread, XNDORMANT) &&
	    xnthread_sched(thread) == xnpod_current_sched())
		rpi_update(thread);
}

void xnshadow_suspend(xnthread_t *thread)
{
	/* Called with nklock locked, Xenomai interrupts off. */
	struct task_struct *p = xnthread_archtcb(thread)->user_task;
	schedule_linux_call(LO_SIGTHR_REQ, p, SIGHARDEN);
}

static int xnshadow_sys_migrate(struct task_struct *curr, struct pt_regs *regs)
{
	if (rthal_current_domain == rthal_root_domain)
		if (__xn_reg_arg1(regs) == XENOMAI_XENO_DOMAIN) {
			if (!xnshadow_thread(curr))
				return -EPERM;

			/* Paranoid: a corner case where the
			   user-space side fiddles with SIGHARDEN
			   while the target thread is still waiting to
			   be started. */
			if (xnthread_test_state(xnshadow_thread(curr), XNDORMANT))
				return 0;

			return xnshadow_harden()? : 1;
		} else
			return 0;
	else /* rthal_current_domain != rthal_root_domain */
    if (__xn_reg_arg1(regs) == XENOMAI_LINUX_DOMAIN) {
		xnshadow_relax(0);
		return 1;
	} else
		return 0;
}

static int xnshadow_sys_arch(struct task_struct *curr, struct pt_regs *regs)
{
	return xnarch_local_syscall(regs);
}

static void stringify_feature_set(u_long fset, char *buf, int size)
{
	unsigned long feature;
	int nc, nfeat;

	*buf = '\0';

	for (feature = 1, nc = nfeat = 0; fset != 0 && size > 0; feature <<= 1) {
		if (fset & feature) {
			nc = snprintf(buf, size, "%s%s",
				      nfeat > 0 ? " " : "",
				      get_feature_label(feature));
			nfeat++;
			size -= nc;
			buf += nc;
			fset &= ~feature;
		}
	}
}

static int xnshadow_sys_bind(struct task_struct *curr, struct pt_regs *regs)
{
	unsigned magic = __xn_reg_arg1(regs);
	u_long featdep = __xn_reg_arg2(regs);
	u_long abirev = __xn_reg_arg3(regs);
	u_long infarg = __xn_reg_arg4(regs);
	xnshadow_ppd_t *ppd = NULL;
	xnfeatinfo_t finfo;
	u_long featmis;
	int muxid, err;
	spl_t s;

	featmis = (~XENOMAI_FEAT_DEP & (featdep & XENOMAI_FEAT_MAN));

	if (infarg) {
		if (!__xn_access_ok(curr, VERIFY_WRITE, infarg, sizeof(finfo)))
			return -EFAULT;

		/* Pass back the supported feature set and the ABI revision
		   level to user-space. */

		finfo.feat_all = XENOMAI_FEAT_DEP;
		stringify_feature_set(XENOMAI_FEAT_DEP, finfo.feat_all_s,
				      sizeof(finfo.feat_all_s));
		finfo.feat_man = featdep & XENOMAI_FEAT_MAN;
		stringify_feature_set(XENOMAI_FEAT_MAN, finfo.feat_man_s,
				      sizeof(finfo.feat_man_s));
		finfo.feat_mis = featmis;
		stringify_feature_set(featmis, finfo.feat_mis_s,
				      sizeof(finfo.feat_mis_s));
		finfo.feat_req = featdep;
		stringify_feature_set(featdep, finfo.feat_req_s,
				      sizeof(finfo.feat_req_s));
		finfo.abirev = XENOMAI_ABI_REV;

		__xn_copy_to_user(curr, (void *)infarg, &finfo, sizeof(finfo));
	}

	if (featmis)
		/* Some mandatory features the user-space interface relies on
		   are missing at kernel level; cannot go further. */
		return -EINVAL;

	if (!check_abi_revision(abirev))
		return -ENOEXEC;

	if (!cap_raised(current->cap_effective, CAP_SYS_NICE) &&
	    (xn_gid_arg == -1 || !in_group_p(xn_gid_arg)))
		return -EPERM;

	/* Raise capabilities for the caller in case they are lacking yet. */
	cap_raise(current->cap_effective, CAP_SYS_NICE);
	cap_raise(current->cap_effective, CAP_IPC_LOCK);
	cap_raise(current->cap_effective, CAP_SYS_RAWIO);

	xnlock_get_irqsave(&nklock, s);

	for (muxid = 1; muxid < XENOMAI_MUX_NR; muxid++)
		if (muxtable[muxid].props && muxtable[muxid].props->magic == magic)
			goto do_bind;

	xnlock_put_irqrestore(&nklock, s);

	return -ESRCH;

      do_bind:

	/* Increment the reference count now (actually, only the first
	   call to bind_to_interface() really increments the counter), so
	   that the interface cannot be removed under our feet. */

	if (!xnarch_atomic_inc_and_test(&muxtable[muxid].refcnt))
		xnarch_atomic_dec(&muxtable[muxid].refcnt);
	if (!xnarch_atomic_inc_and_test(&muxtable[0].refcnt))
		xnarch_atomic_dec(&muxtable[0].refcnt);

	xnlock_put_irqrestore(&nklock, s);

	/* Since the pod might be created by the event callback and not
	   earlier than that, do not refer to nkpod until the latter had a
	   chance to call xnpod_init(). */

	if (!muxtable[muxid].props->eventcb)
		goto eventcb_done;

	xnlock_get_irqsave(&nklock, s);
	ppd = ppd_lookup(muxid, curr->mm);
	xnlock_put_irqrestore(&nklock, s);

	/* protect from the same process binding several times. */
	if (ppd)
		goto eventcb_done;

	ppd = (xnshadow_ppd_t *) muxtable[muxid].props->eventcb(XNSHADOW_CLIENT_ATTACH,
							       curr);

	if (IS_ERR(ppd)) {
		err = PTR_ERR(ppd);
		goto fail;
	}

	if (!ppd)
		goto eventcb_done;

	ppd->key.muxid = muxid;
	ppd->key.mm = curr->mm;

	if (ppd_insert(ppd) == -EBUSY) {
		/* In case of concurrent binding (which can not happen with
		   Xenomai libraries), detach right away the second ppd. */
		muxtable[muxid].props->eventcb(XNSHADOW_CLIENT_DETACH, ppd);
		ppd = NULL;
		goto eventcb_done;
	}

	if (muxtable[muxid].props->module && !try_module_get(muxtable[muxid].props->module)) {
		err = -ESRCH;
		goto fail;
	}

      eventcb_done:

	if (!xnpod_active_p()) {
		/* Ok mate, but you really ought to call xnpod_init()
		   at some point if you want me to be of some help
		   here... */
		if (muxtable[muxid].props->eventcb && ppd) {
			ppd_remove(ppd);
			muxtable[muxid].props->eventcb(XNSHADOW_CLIENT_DETACH, ppd);
			if (muxtable[muxid].props->module)
				module_put(muxtable[muxid].props->module);
		}

		err = -ENOSYS;

	      fail:
		if (!xnarch_atomic_get(&muxtable[muxid].refcnt))
			xnarch_atomic_dec(&muxtable[muxid].refcnt);
		if (!xnarch_atomic_get(&muxtable[muxid].refcnt))
			xnarch_atomic_dec(&muxtable[0].refcnt);
		return err;
	}

	return muxid;
}

static int xnshadow_sys_info(struct task_struct *curr, struct pt_regs *regs)
{
	int muxid = __xn_reg_arg1(regs);
	u_long infarg = __xn_reg_arg2(regs);
	xntbase_t **timebasep;
	xnsysinfo_t info;
	spl_t s;

	if (!__xn_access_ok(curr, VERIFY_WRITE, infarg, sizeof(info)))
		return -EFAULT;

	xnlock_get_irqsave(&nklock, s);

	if (muxid < 0 || muxid > XENOMAI_MUX_NR ||
	    muxtable[muxid].props == NULL) {
		xnlock_put_irqrestore(&nklock, s);
		return -EINVAL;
	}

	timebasep = muxtable[muxid].props->timebasep;
	info.tickval = xntbase_get_tickval(timebasep ? *timebasep : &nktbase);
	xnlock_put_irqrestore(&nklock, s);
	info.cpufreq = xnarch_get_cpu_freq();
	__xn_copy_to_user(curr, (void *)infarg, &info, sizeof(info));

	return 0;
}

#define completion_value_ok ((1UL << (BITS_PER_LONG-1))-1)

void xnshadow_signal_completion(xncompletion_t __user *u_completion, int err)
{
	xncompletion_t completion;
	struct task_struct *p;
	pid_t pid;

	/* Hold a mutex to avoid missing a wakeup signal. */
	down(&completion_mutex);

	__xn_copy_from_user(current, &completion, u_completion, sizeof(completion));

	/* Poor man's semaphore V. */
	completion.syncflag = err ? : completion_value_ok;
	__xn_copy_to_user(current, u_completion, &completion, sizeof(completion));
	pid = completion.pid;

	up(&completion_mutex);

	if (pid == -1)
		return;

	read_lock(&tasklist_lock);

	p = find_task_by_pid(completion.pid);

	if (p)
		wake_up_process(p);

	read_unlock(&tasklist_lock);
}

static int xnshadow_sys_completion(struct task_struct *curr,
				   struct pt_regs *regs)
{
	xncompletion_t __user *u_completion;
	xncompletion_t completion;

	u_completion = (xncompletion_t __user *)__xn_reg_arg1(regs);

	for (;;) {		/* Poor man's semaphore P. */
		down(&completion_mutex);

		__xn_copy_from_user(current, &completion, u_completion, sizeof(completion));

		if (completion.syncflag)
			break;

		completion.pid = current->pid;

		__xn_copy_to_user(current, u_completion, &completion, sizeof(completion));

		set_current_state(TASK_INTERRUPTIBLE);

		up(&completion_mutex);

		schedule();

		if (signal_pending(current)) {
			completion.pid = -1;
			__xn_copy_to_user(current, u_completion, &completion, sizeof(completion));
			return -ERESTARTSYS;
		}
	}

	up(&completion_mutex);

	return completion.syncflag == completion_value_ok ? 0 : (int)completion.syncflag;
}

static int xnshadow_sys_barrier(struct task_struct *curr, struct pt_regs *regs)
{
	return xnshadow_wait_barrier(regs);
}

static int xnshadow_sys_trace(struct task_struct *curr, struct pt_regs *regs)
{
	int err = -ENOSYS;

	switch (__xn_reg_arg1(regs)) {
	case __xntrace_op_max_begin:
		err = xnarch_trace_max_begin(__xn_reg_arg2(regs));
		break;

	case __xntrace_op_max_end:
		err = xnarch_trace_max_end(__xn_reg_arg2(regs));
		break;

	case __xntrace_op_max_reset:
		err = xnarch_trace_max_reset();
		break;

	case __xntrace_op_user_start:
		err = xnarch_trace_user_start();
		break;

	case __xntrace_op_user_stop:
		err = xnarch_trace_user_stop(__xn_reg_arg2(regs));
		break;

	case __xntrace_op_user_freeze:
		err = xnarch_trace_user_freeze(__xn_reg_arg2(regs),
					       __xn_reg_arg3(regs));
		break;

	case __xntrace_op_special:
		err = xnarch_trace_special(__xn_reg_arg2(regs) & 0xFF,
					   __xn_reg_arg3(regs));
		break;

	case __xntrace_op_special_u64:
		err = xnarch_trace_special_u64(__xn_reg_arg2(regs) & 0xFF,
					       (((u64) __xn_reg_arg3(regs)) <<
						32) | __xn_reg_arg4(regs));
		break;
	}
	return err;
}

static xnsysent_t __systab[] = {
	[__xn_sys_migrate] = {&xnshadow_sys_migrate, __xn_exec_current},
	[__xn_sys_arch] = {&xnshadow_sys_arch, __xn_exec_any},
	[__xn_sys_bind] = {&xnshadow_sys_bind, __xn_exec_lostage},
	[__xn_sys_info] = {&xnshadow_sys_info, __xn_exec_lostage},
	[__xn_sys_completion] = {&xnshadow_sys_completion, __xn_exec_lostage},
	[__xn_sys_barrier] = {&xnshadow_sys_barrier, __xn_exec_lostage},
	[__xn_sys_trace] = {&xnshadow_sys_trace, __xn_exec_any},
};


static struct xnskin_props __props = {
	.name = "sys",
	.magic = 0x434F5245,
	.nrcalls = sizeof(__systab) / sizeof(__systab[0]),
	.systab = __systab,
	.eventcb = NULL,
	.timebasep = NULL,
	.module = NULL
};

static inline int substitute_linux_syscall(struct task_struct *curr,
					   struct pt_regs *regs)
{
	/* No real-time replacement for now -- let Linux handle this call. */
	return 0;
}

void xnshadow_send_sig(xnthread_t *thread, int sig, int specific)
{
	schedule_linux_call(specific ? LO_SIGTHR_REQ : LO_SIGGRP_REQ,
			    xnthread_user_task(thread), sig);
}

static inline int do_hisyscall_event(unsigned event, unsigned domid, void *data)
{
	struct pt_regs *regs = (struct pt_regs *)data;
	int muxid, muxop, switched, err;
	struct task_struct *p;
	xnthread_t *thread;
	u_long sysflags;

	if (!xnpod_active_p())
		goto no_skin;

	xnarch_hisyscall_entry();

	p = current;
	thread = xnshadow_thread(p);

	if (!__xn_reg_mux_p(regs))
		goto linux_syscall;

	/* Executing Xenomai services requires CAP_SYS_NICE, except for
	   __xn_sys_bind which does its own checks. */
	if (unlikely(!cap_raised(p->cap_effective, CAP_SYS_NICE)) &&
	    __xn_reg_mux(regs) != __xn_mux_code(0, __xn_sys_bind)) {
		__xn_error_return(regs, -EPERM);
		return RTHAL_EVENT_STOP;
	}

	muxid = __xn_mux_id(regs);
	muxop = __xn_mux_op(regs);

	trace_mark(xn_nucleus_syscall_histage,
		   "thread %p thread_name %s muxid %d muxop %d",
		   thread, thread ? xnthread_name(thread) : NULL,
		   muxid, muxop);

	if (muxid < 0 || muxid > XENOMAI_MUX_NR ||
	    muxop < 0 || muxop >= muxtable[muxid].props->nrcalls) {
		__xn_error_return(regs, -ENOSYS);
		return RTHAL_EVENT_STOP;
	}

	sysflags = muxtable[muxid].props->systab[muxop].flags;

	if ((sysflags & __xn_exec_shadow) != 0 && !thread) {
		__xn_error_return(regs, -EPERM);
		return RTHAL_EVENT_STOP;
	}

	if ((sysflags & __xn_exec_conforming) != 0)
		/* If the conforming exec bit has been set, turn the exec
		   bitmask for the syscall into the most appropriate setup for
		   the caller, i.e. Xenomai domain for shadow threads, Linux
		   otherwise. */
		sysflags |= (thread ? __xn_exec_histage : __xn_exec_lostage);

	/*
	 * Here we have to dispatch the syscall execution properly,
	 * depending on:
	 *
	 * o Whether the syscall must be run into the Linux or Xenomai
	 * domain, or indifferently in the current Xenomai domain.
	 *
	 * o Whether the caller currently runs in the Linux or Xenomai
	 * domain.
	 */

	switched = 0;

      restart:			/* Process adaptive syscalls by restarting them in the
				   opposite domain. */

	if ((sysflags & __xn_exec_lostage) != 0) {
		/* Syscall must run into the Linux domain. */

		if (domid == RTHAL_DOMAIN_ID) {
			/* Request originates from the Xenomai domain: just relax the
			   caller and execute the syscall immediately after. */
			xnshadow_relax(1);
			switched = 1;
		} else
			/* Request originates from the Linux domain: propagate the
			   event to our Linux-based handler, so that the syscall
			   is executed from there. */
			goto propagate_syscall;
	} else if ((sysflags & (__xn_exec_histage | __xn_exec_current)) != 0) {
		/* Syscall must be processed either by Xenomai, or by the
		   calling domain. */

		if (domid != RTHAL_DOMAIN_ID)
			/* Request originates from the Linux domain: propagate the
			   event to our Linux-based handler, so that the caller is
			   hardened and the syscall is eventually executed from
			   there. */
			goto propagate_syscall;

		/* Request originates from the Xenomai domain: run the syscall
		   immediately. */
	}

	err = muxtable[muxid].props->systab[muxop].svc(p, regs);

	if (err == -ENOSYS && (sysflags & __xn_exec_adaptive) != 0) {
		if (switched) {
			switched = 0;

			if ((err = xnshadow_harden()) != 0)
				goto done;
		}

		sysflags ^=
		    (__xn_exec_lostage | __xn_exec_histage |
		     __xn_exec_adaptive);
		goto restart;
	}

      done:

	__xn_status_return(regs, err);

	if (xnpod_shadow_p() && signal_pending(p))
		request_syscall_restart(thread, regs, sysflags);
	else if ((sysflags & __xn_exec_switchback) != 0 && switched)
		xnshadow_harden();	/* -EPERM will be trapped later if needed. */

	return RTHAL_EVENT_STOP;

      linux_syscall:

	if (xnpod_root_p())
		/* The call originates from the Linux domain, either from a
		   relaxed shadow or from a regular Linux task; just propagate
		   the event so that we will fall back to linux_sysentry(). */
		goto propagate_syscall;

	/* From now on, we know that we have a valid shadow thread
	   pointer. */

	if (substitute_linux_syscall(p, regs))
		/* This is a Linux syscall issued on behalf of a shadow thread
		   running inside the Xenomai domain. This call has just been
		   intercepted by the nucleus and a Xenomai replacement has been
		   substituted for it. */
		return RTHAL_EVENT_STOP;

	/* This syscall has not been substituted, let Linux handle
	   it. This will eventually fall back to the Linux syscall handler
	   if our Linux domain handler does not intercept it. Before we
	   let it go, ensure that our running thread has properly entered
	   the Linux domain. */

	xnshadow_relax(1);

	goto propagate_syscall;

      no_skin:

	if (__xn_reg_mux_p(regs)) {
		if (__xn_reg_mux(regs) == __xn_mux_code(0, __xn_sys_bind))
			/* Valid exception case: we may be called to bind to a
			   skin which will create its own pod through its callback
			   routine before returning to user-space. */
			goto propagate_syscall;

		xnlogwarn("bad syscall %ld/%ld -- no skin loaded.\n",
			  __xn_mux_id(regs), __xn_mux_op(regs));

		__xn_error_return(regs, -ENOSYS);
		return RTHAL_EVENT_STOP;
	}

	/* Regular Linux syscall with no skin loaded -- propagate it
	   to the Linux kernel. */

      propagate_syscall:

	return RTHAL_EVENT_PROPAGATE;
}

RTHAL_DECLARE_EVENT(hisyscall_event);

static inline int do_losyscall_event(unsigned event, unsigned domid, void *data)
{
	struct pt_regs *regs = (struct pt_regs *)data;
	xnthread_t *thread = xnshadow_thread(current);
	int muxid, muxop, sysflags, switched, err;

	if (__xn_reg_mux_p(regs))
		goto xenomai_syscall;

	if (!thread || !substitute_linux_syscall(current, regs))
		/* Fall back to Linux syscall handling. */
		return RTHAL_EVENT_PROPAGATE;

	/* This is a Linux syscall issued on behalf of a shadow thread
	   running inside the Linux domain. If the call has been
	   substituted with a Xenomai replacement, do not let Linux know
	   about it. */

	return RTHAL_EVENT_STOP;

      xenomai_syscall:

	/* muxid and muxop have already been checked in the Xenomai domain
	   handler. */

	muxid = __xn_mux_id(regs);
	muxop = __xn_mux_op(regs);

	trace_mark(xn_nucleus_syscall_lostage,
		   "thread %p thread_name %s muxid %d muxop %d",
		   xnpod_active_p() ? xnpod_current_thread() : NULL,
		   xnpod_active_p() ? xnthread_name(xnpod_current_thread()) : NULL,
		   muxid, muxop);

	/* Processing a real-time skin syscall. */

	sysflags = muxtable[muxid].props->systab[muxop].flags;

	if ((sysflags & __xn_exec_conforming) != 0)
		sysflags |= (thread ? __xn_exec_histage : __xn_exec_lostage);

      restart:			/* Process adaptive syscalls by restarting them in the
				   opposite domain. */

	if ((sysflags & __xn_exec_histage) != 0) {
		/* This request originates from the Linux domain and must be
		   run into the Xenomai domain: harden the caller and execute the
		   syscall. */
		if ((err = xnshadow_harden()) != 0) {
			__xn_error_return(regs, err);
			return RTHAL_EVENT_STOP;
		}

		switched = 1;
	} else			/* We want to run the syscall in the Linux domain.  */
		switched = 0;

	err = muxtable[muxid].props->systab[muxop].svc(current, regs);

	if (err == -ENOSYS && (sysflags & __xn_exec_adaptive) != 0) {
		if (switched) {
			switched = 0;
			xnshadow_relax(1);
		}

		sysflags ^=
		    (__xn_exec_lostage | __xn_exec_histage |
		     __xn_exec_adaptive);
		goto restart;
	}

	__xn_status_return(regs, err);

	if (xnpod_active_p() && xnpod_shadow_p() && signal_pending(current))
		request_syscall_restart(xnshadow_thread(current), regs, sysflags);
	else if ((sysflags & __xn_exec_switchback) != 0 && switched)
		xnshadow_relax(0);

	return RTHAL_EVENT_STOP;
}

RTHAL_DECLARE_EVENT(losyscall_event);

static inline void do_taskexit_event(struct task_struct *p)
{
	xnthread_t *thread = xnshadow_thread(p); /* p == current */
	unsigned magic;
	spl_t s;

	if (!thread)
		return;

	if (xnthread_test_state(thread, XNDEBUG))
		unlock_timers();

	if (xnpod_shadow_p())
		xnshadow_relax(0);

	magic = xnthread_get_magic(thread);

	xnlock_get_irqsave(&nklock, s);
	/* Prevent wakeup call from xnshadow_unmap(). */
	xnshadow_thrptd(p) = NULL;
	xnthread_archtcb(thread)->user_task = NULL;
	/* xnpod_delete_thread() -> hook -> xnshadow_unmap(). */
	xnpod_delete_thread(thread);
	xnsched_set_resched(thread->sched);
	xnlock_put_irqrestore(&nklock, s);
	xnpod_schedule();

	xnshadow_dereference_skin(magic);
	trace_mark(xn_nucleus_shadow_exit, "thread %p thread_name %s",
		   thread, xnthread_name(thread));
}

RTHAL_DECLARE_EXIT_EVENT(taskexit_event);

static inline void do_schedule_event(struct task_struct *next)
{
	struct task_struct *prev;
	xnthread_t *threadin;

	if (!xnpod_active_p())
		return;

	prev = current;
	threadin = xnshadow_thread(next);
	set_switch_lock_owner(prev);

	if (threadin) {
		/*
		 * Check whether we need to unlock the timers, each
		 * time a Linux task resumes from a stopped state,
		 * excluding tasks resuming shortly for entering a
		 * stopped state asap due to ptracing. To identify the
		 * latter, we need to check for SIGSTOP and SIGINT in
		 * order to encompass both the NPTL and LinuxThreads
		 * behaviours.
		 */
		if (xnthread_test_state(threadin, XNDEBUG)) {
			if (signal_pending(next)) {
				sigset_t pending;
				/*
				 * Do not grab the sighand lock here:
				 * it's useless, and we already own
				 * the runqueue lock, so this would
				 * expose us to deadlock situations on
				 * SMP.
				 */
				wrap_get_sigpending(&pending, next);

				if (sigismember(&pending, SIGSTOP) ||
				    sigismember(&pending, SIGINT))
					goto no_ptrace;
			}

			xnthread_clear_state(threadin, XNDEBUG);
			unlock_timers();
		}

	      no_ptrace:

		if (XENO_DEBUG(NUCLEUS)) {
			int sigpending = signal_pending(next);

			if (!xnthread_test_state(threadin, XNRELAX)) {
				xnarch_trace_panic_freeze();
				show_stack(xnthread_user_task(threadin), NULL);
				xnpod_fatal
				    ("Hardened thread %s[%d] running in Linux"" domain?! (status=0x%lx, sig=%d, prev=%s[%d])",
				     threadin->name, next->pid, xnthread_state_flags(threadin),
				     sigpending, prev->comm, prev->pid);
			} else if (!(next->ptrace & PT_PTRACED) &&
				   /* Allow ptraced threads to run shortly in order to
				      properly recover from a stopped state. */
				   xnthread_test_state(threadin, XNSTARTED)
				   && xnthread_test_state(threadin, XNPEND)) {
				xnarch_trace_panic_freeze();
				show_stack(xnthread_user_task(threadin), NULL);
				xnpod_fatal
				    ("blocked thread %s[%d] rescheduled?! (status=0x%lx, sig=%d, prev=%s[%d])",
				     threadin->name, next->pid, xnthread_state_flags(threadin),
				     sigpending, prev->comm, prev->pid);
			}
		}

		ishield_reset(threadin);
	} else if (next != gatekeeper[rthal_processor_id()].server)
		ishield_off();

	rpi_switch(next);
}

RTHAL_DECLARE_SCHEDULE_EVENT(schedule_event);

static inline void do_sigwake_event(struct task_struct *p)
{
	xnthread_t *thread = xnshadow_thread(p);
	spl_t s;

	if (thread == NULL)
		return;

	xnlock_get_irqsave(&nklock, s);

	if ((p->ptrace & PT_PTRACED) && !xnthread_test_state(thread, XNDEBUG)) {
		sigset_t pending;

		/* We already own the siglock. */
		wrap_get_sigpending(&pending, p);

		if (sigismember(&pending, SIGTRAP) ||
		    sigismember(&pending, SIGSTOP)
		    || sigismember(&pending, SIGINT)) {
			xnthread_set_state(thread, XNDEBUG);
			lock_timers();
		}
	}

	if (xnthread_test_state(thread, XNRELAX))
		goto unlock_and_exit;
	/*
	 * If we are kicking a shadow thread in primary mode, make
	 * sure Linux won't schedule in its mate under our feet as a
	 * result of running signal_wake_up(). The Xenomai scheduler
	 * must remain in control for now, until we explicitly relax
	 * the shadow thread to allow for processing the pending
	 * signals. Make sure we keep the additional state flags
	 * unmodified so that we don't break any undergoing ptrace.
	 */
	set_task_nowakeup(p);

	/*
	 * Tricky case: a ready thread does not actually run, but
	 * nevertheless waits for the CPU in primary mode, so we have
	 * to make sure that it will be notified of the pending break
	 * condition as soon as it enters xnpod_suspend_thread() from
	 * a blocking Xenomai syscall.
	 */
	if (xnthread_test_state(thread, XNREADY)) {
		xnthread_set_info(thread, XNKICKED);
		goto unlock_and_exit;
	}

	if (xnpod_unblock_thread(thread))
		xnthread_set_info(thread, XNKICKED);

	if (xnthread_test_state(thread, XNSUSP)) {
		xnpod_resume_thread(thread, XNSUSP);
		xnthread_set_info(thread, XNKICKED|XNBREAK);
	}

	if (xnthread_test_info(thread, XNKICKED)) {
		xnsched_set_resched(thread->sched);
		xnpod_schedule();
	}

unlock_and_exit:

	xnlock_put_irqrestore(&nklock, s);
}

RTHAL_DECLARE_SIGWAKE_EVENT(sigwake_event);

static inline void do_setsched_event(struct task_struct *p, int priority)
{
	xnthread_t *thread = xnshadow_thread(p);

	if (!thread || p->policy != SCHED_FIFO)
		return;

	/*
	 * Linux's priority scale is a subset of the core pod's
	 * priority scale, so there is no need to bound the priority
	 * values when mapping them from Linux -> Xenomai. We
	 * propagate priority changes to the nucleus only for threads
	 * that belong to skins that have a compatible priority scale.
	 */
	if (xnthread_current_priority(thread) != priority &&
		xnthread_get_denormalized_prio(thread, priority) == priority) {
		xnpod_renice_thread_inner(thread, priority, 0);
		if (xnsched_resched_p()) {
			if (p == current &&
			    xnthread_sched(thread) == xnpod_current_sched())
				rpi_update(thread);
			/*
			 * rpi_switch() will fix things properly
			 * otherwise.  This may delay the update if
			 * the thread is running on the remote CPU
			 * until it gets back into rpi_switch() as the
			 * incoming thread anew, but this is
			 * acceptable (i.e. strict ordering across
			 * CPUs is not supported anyway).
			 */
			xnpod_schedule();
		}
	}
}

RTHAL_DECLARE_SETSCHED_EVENT(setsched_event);

static void detach_ppd(xnshadow_ppd_t * ppd)
{
	unsigned muxid = xnshadow_ppd_muxid(ppd);
	muxtable[muxid].props->eventcb(XNSHADOW_CLIENT_DETACH, ppd);
	if (muxtable[muxid].props->module)
		module_put(muxtable[muxid].props->module);
}

static inline void do_cleanup_event(struct mm_struct *mm)
{
	ppd_remove_mm(mm, &detach_ppd);
}

RTHAL_DECLARE_CLEANUP_EVENT(cleanup_event);

/*
 * xnshadow_register_interface() -- Register a new skin/interface.
 * NOTE: an interface can be registered without its pod being
 * necessarily active. In such a case, a lazy initialization scheme
 * can be implemented through the event callback fired upon the first
 * client binding.
 *
 * The event callback will be called with its first argument set to:
 * - XNSHADOW_CLIENT_ATTACH, when a user-space process binds the interface, the
 *   second argument being the task_struct pointer of the calling thread, the
 *   callback may then return:
 *   . a pointer to an xnshadow_ppd_t structure, meaning that this structure
 *   will be attached to the calling process for this interface;
 *   . a NULL pointer, meaning that no per-process structure should be attached
 *   to this process for this interface;
 *   . ERR_PTR(negative value) indicating an error, the binding process will
 *   then abort;
 * - XNSHADOW_DETACH, when a user-space process terminates, if a non-NULL
 *   per-process structure is attached to the dying process, the second argument
 *   being the pointer to the per-process data attached to the dying process.
 */

int xnshadow_register_interface(struct xnskin_props *props)
{
	int muxid;
	spl_t s;

	/* We can only handle up to 256 syscalls per skin, check for over-
	   and underflow (MKL). */

	if (XENOMAI_MAX_SYSENT < props->nrcalls || 0 > props->nrcalls)
		return -EINVAL;

	xnlock_get_irqsave(&nklock, s);

	for (muxid = 0; muxid < XENOMAI_MUX_NR; muxid++) {
		if (muxtable[muxid].props == NULL) {
			muxtable[muxid].props = props;
			xnarch_atomic_set(&muxtable[muxid].refcnt, -1);
			xnlock_put_irqrestore(&nklock, s);

#ifdef CONFIG_PROC_FS
			xnpod_declare_iface_proc(muxtable + muxid);
#endif /* CONFIG_PROC_FS */

			return muxid;
		}
	}

	xnlock_put_irqrestore(&nklock, s);

	return -ENOBUFS;
}

/*
 * xnshadow_unregister_interface() -- Unregister a skin/interface.
 * NOTE: an interface can be unregistered without its pod being
 * necessarily active.
 */

int xnshadow_unregister_interface(int muxid)
{
	int err = 0;
	spl_t s;

	if (muxid < 0 || muxid >= XENOMAI_MUX_NR)
		return -EINVAL;

	xnlock_get_irqsave(&nklock, s);

	if (xnarch_atomic_get(&muxtable[muxid].refcnt) <= 0) {
#ifdef CONFIG_PROC_FS
		const char *name = muxtable[muxid].props->name;
#endif /* CONFIG_PROC_FS */
		muxtable[muxid].props = NULL;
		xnarch_atomic_set(&muxtable[muxid].refcnt, -1);
#ifdef CONFIG_PROC_FS
		{
			xnlock_put_irqrestore(&nklock, s);
			xnpod_discard_iface_proc(name);
			return 0;
		}
#endif /* CONFIG_PROC_FS */
	} else
		err = -EBUSY;

	xnlock_put_irqrestore(&nklock, s);

	return err;
}

/**
 * Return the per-process data attached to the calling process.
 *
 * This service returns the per-process data attached to the calling process for
 * the skin whose muxid is @a muxid. It must be called with nklock locked, irqs
 * off.
 *
 * See xnshadow_register_interface() documentation for information on the way to
 * attach a per-process data to a process.
 *
 * @param muxid the skin muxid.
 *
 * @return the per-process data if the current context is a user-space process;
 * @return NULL otherwise.
 * 
 */
xnshadow_ppd_t *xnshadow_ppd_get(unsigned muxid)
{
	if (xnpod_userspace_p())
		return ppd_lookup(muxid, current->mm);

	return NULL;
}

void xnshadow_grab_events(void)
{
	rthal_catch_taskexit(&taskexit_event);
	rthal_catch_sigwake(&sigwake_event);
	rthal_catch_schedule(&schedule_event);
	rthal_catch_setsched(&setsched_event);
	rthal_catch_cleanup(&cleanup_event);
}

void xnshadow_release_events(void)
{
	rthal_catch_taskexit(NULL);
	rthal_catch_sigwake(NULL);
	rthal_catch_schedule(NULL);
	rthal_catch_setsched(NULL);
	rthal_catch_cleanup(NULL);
}

int xnshadow_mount(void)
{
	unsigned i, size;
	int cpu, err;

	nucleus_muxid = -1;

	err = ishield_init();

	if (err)
		return err;

	nkthrptd = rthal_alloc_ptdkey();
	nkerrptd = rthal_alloc_ptdkey();

	if (nkthrptd < 0 || nkerrptd < 0) {
		printk(KERN_WARNING "Xenomai: cannot allocate PTD slots\n");
		return -ENOMEM;
	}

	lostage_apc =
	    rthal_apc_alloc("lostage_handler", &lostage_handler, NULL);

	for_each_online_cpu(cpu) {
		struct __gatekeeper *gk = &gatekeeper[cpu];
		rpi_init_gk(gk);
		sema_init(&gk->sync, 0);
		xnarch_memory_barrier();
		gk->server =
		    kthread_create(&gatekeeper_thread, gk, "gatekeeper/%d",
				   cpu);
		wake_up_process(gk->server);
		down(&gk->sync);
	}

	/* We need to grab these ones right now. */
	rthal_catch_losyscall(&losyscall_event);
	rthal_catch_hisyscall(&hisyscall_event);

	size = sizeof(xnqueue_t) * PPD_HASH_SIZE;
	ppd_hash = (xnqueue_t *)xnarch_alloc_host_mem(size);
	if (!ppd_hash) {
		xnshadow_cleanup();
		printk(KERN_WARNING
		       "Xenomai: cannot allocate PPD hash table.\n");
		return -ENOMEM;
	}

	for (i = 0; i < PPD_HASH_SIZE; i++)
		initq(&ppd_hash[i]);

	nucleus_muxid = xnshadow_register_interface(&__props);

	if (nucleus_muxid != 0) {
		if (nucleus_muxid > 0) {
			printk(KERN_WARNING
			       "Xenomai: got non null id when registering "
			       "nucleus syscall table.\n");
		} else
			printk(KERN_WARNING
			       "Xenomai: cannot register nucleus syscall table.\n");

		xnshadow_cleanup();
		return -ENOMEM;
	}

	return 0;
}

void xnshadow_cleanup(void)
{
	int cpu;

	if (nucleus_muxid >= 0)
		xnshadow_unregister_interface(nucleus_muxid);

	nucleus_muxid = -1;

	if (ppd_hash)
		xnarch_free_host_mem(ppd_hash,
			       sizeof(xnqueue_t) * PPD_HASH_SIZE);
	ppd_hash = NULL;

	rthal_catch_losyscall(NULL);
	rthal_catch_hisyscall(NULL);

	for_each_online_cpu(cpu) {
		struct __gatekeeper *gk = &gatekeeper[cpu];
		down(&gk->sync);
		gk->thread = NULL;
		kthread_stop(gk->server);
	}

	rthal_apc_free(lostage_apc);
	rthal_free_ptdkey(nkerrptd);
	rthal_free_ptdkey(nkthrptd);
	ishield_cleanup();
}

/*@}*/

EXPORT_SYMBOL(xnshadow_map);
EXPORT_SYMBOL(xnshadow_register_interface);
EXPORT_SYMBOL(xnshadow_harden);
EXPORT_SYMBOL(xnshadow_relax);
EXPORT_SYMBOL(xnshadow_start);
EXPORT_SYMBOL(xnshadow_signal_completion);
EXPORT_SYMBOL(xnshadow_unmap);
EXPORT_SYMBOL(xnshadow_send_sig);
EXPORT_SYMBOL(xnshadow_unregister_interface);
EXPORT_SYMBOL(xnshadow_wait_barrier);
EXPORT_SYMBOL(xnshadow_suspend);
EXPORT_SYMBOL(xnshadow_ppd_get);
EXPORT_SYMBOL(nkthrptd);
EXPORT_SYMBOL(nkerrptd);
