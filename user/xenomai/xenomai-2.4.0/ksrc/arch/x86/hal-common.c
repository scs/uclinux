/**
 *   @ingroup hal
 *   @file
 *
 *   Adeos-based Real-Time Abstraction Layer for x86.
 *   Common code of i386 and x86_64.
 *
 *   Copyright (C) 2007 Philippe Gerum.
 *
 *   Xenomai is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License as
 *   published by the Free Software Foundation, Inc., 675 Mass Ave,
 *   Cambridge MA 02139, USA; either version 2 of the License, or (at
 *   your option) any later version.
 *
 *   Xenomai is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

/**
 * @addtogroup hal
 *
 *@{*/

#include <asm/xenomai/hal.h>

enum rthal_ktimer_mode rthal_ktimer_saved_mode;

static struct {
	unsigned long flags;
	int count;
} rthal_linux_irq[IPIPE_NR_XIRQS];

#ifdef CONFIG_X86_LOCAL_APIC

#define RTHAL_SET_ONESHOT_XENOMAI	1
#define RTHAL_SET_ONESHOT_LINUX		2
#define RTHAL_SET_PERIODIC		3

static void rthal_critical_sync(void)
{
	switch (rthal_sync_op) {
	case RTHAL_SET_ONESHOT_XENOMAI:
		rthal_setup_oneshot_apic(RTHAL_APIC_TIMER_VECTOR);
		break;

	case RTHAL_SET_ONESHOT_LINUX:
		rthal_setup_oneshot_apic(LOCAL_TIMER_VECTOR);
		/* We need to keep the timing cycle alive for the kernel. */
		rthal_trigger_irq(ipipe_apic_vector_irq(LOCAL_TIMER_VECTOR));
		break;

	case RTHAL_SET_PERIODIC:
		rthal_setup_periodic_apic(RTHAL_APIC_ICOUNT, LOCAL_TIMER_VECTOR);
		break;
	}
}

static void rthal_timer_set_oneshot(int rt_mode)
{
	unsigned long flags;

	flags = rthal_critical_enter(rthal_critical_sync);
	if (rt_mode) {
		rthal_sync_op = RTHAL_SET_ONESHOT_XENOMAI;
		rthal_setup_oneshot_apic(RTHAL_APIC_TIMER_VECTOR);
	} else {
		rthal_sync_op = RTHAL_SET_ONESHOT_LINUX;
		rthal_setup_oneshot_apic(LOCAL_TIMER_VECTOR);
		/* We need to keep the timing cycle alive for the kernel. */
		rthal_trigger_irq(ipipe_apic_vector_irq(LOCAL_TIMER_VECTOR));
	}
	rthal_critical_exit(flags);
}

static void rthal_timer_set_periodic(void)
{
	unsigned long flags;

	flags = rthal_critical_enter(&rthal_critical_sync);
	rthal_sync_op = RTHAL_SET_PERIODIC;
	rthal_setup_periodic_apic(RTHAL_APIC_ICOUNT, LOCAL_TIMER_VECTOR);
	rthal_critical_exit(flags);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#include <asm/smpboot.h>
static inline void send_IPI_all(int vector)
{
	unsigned long flags;

	rthal_local_irq_save_hw(flags);
	apic_wait_icr_idle();
	apic_write_around(APIC_ICR,
			  APIC_DM_FIXED | APIC_DEST_ALLINC | INT_DEST_ADDR_MODE
			  | vector);
	rthal_local_irq_restore_hw(flags);
}
#elif defined(__i386__)
#include <mach_ipi.h>
#endif

DECLARE_LINUX_IRQ_HANDLER(rthal_broadcast_to_local_timers, irq, dev_id)
{
#ifdef CONFIG_SMP
	send_IPI_all(LOCAL_TIMER_VECTOR);
#else
	rthal_trigger_irq(ipipe_apic_vector_irq(LOCAL_TIMER_VECTOR));
#endif
	return IRQ_HANDLED;
}

#ifdef CONFIG_GENERIC_CLOCKEVENTS

int rthal_timer_request(
	void (*tick_handler)(void),
	void (*mode_emul)(enum clock_event_mode mode,
			  struct clock_event_device *cdev),
	int (*tick_emul)(unsigned long delay,
			 struct clock_event_device *cdev),
	int cpu)
{
	unsigned long tmfreq;
	int tickval, err;

	/* This code works both for UP+LAPIC and SMP configurations. */

#ifdef __IPIPE_FEATURE_REQUEST_TICKDEV
	int res = ipipe_request_tickdev("lapic", mode_emul, tick_emul, cpu,
					&tmfreq);
#else
	int res = ipipe_request_tickdev("lapic",
					(compat_emumode_t)mode_emul,
					(compat_emutick_t)tick_emul,
					cpu);
	tmfreq = RTHAL_COMPAT_TIMERFREQ;
#endif

	switch (res) {
	case CLOCK_EVT_MODE_PERIODIC:
		/* oneshot tick emulation callback won't be used, ask
		 * the caller to start an internal timer for emulating
		 * a periodic tick. */
		tickval = 1000000000UL / HZ;
		break;

	case CLOCK_EVT_MODE_ONESHOT:
		/* oneshot tick emulation */
		tickval = 1;
		break;

	case CLOCK_EVT_MODE_UNUSED:
		/* we don't need to emulate the tick at all. */
		tickval = 0;
		break;

	case CLOCK_EVT_MODE_SHUTDOWN:
		return -ENODEV;

	default:
		return res;
	}
	rthal_ktimer_saved_mode = res;

	if (rthal_timerfreq_arg == 0)
		rthal_tunables.timer_freq = tmfreq;

	/*
	 * The rest of the initialization should only be performed
	 * once by a single CPU.
	 */
	if (cpu > 0)
		goto out;

	rthal_timer_set_oneshot(1);

	err = rthal_irq_request(RTHAL_APIC_TIMER_IPI,
				(rthal_irq_handler_t) tick_handler, NULL, NULL);

	if (err)
		return err;

	rthal_nmi_init(&rthal_latency_above_max);
out:
	return tickval;
}

#else /* !CONFIG_GENERIC_CLOCKEVENTS */

int rthal_timer_request(void (*tick_handler)(void), int cpu)
{
	int err;

	/*
	 * When the local APIC is enabled for kernels lacking generic
	 * support for clock events, we do not need to relay the host tick
	 * since 8254 interrupts are already flowing normally to Linux
	 * (i.e. the nucleus does not intercept them, but uses a dedicated
	 * APIC-based timer interrupt instead, i.e. RTHAL_APIC_TIMER_IPI).
	 *
	 * This code works both for UP+LAPIC and SMP configurations.
	 */
	rthal_ktimer_saved_mode = KTIMER_MODE_PERIODIC;

	if (rthal_timerfreq_arg == 0)
		rthal_tunables.timer_freq = RTHAL_COMPAT_TIMERFREQ;

	/*
	 * The rest of the initialization should only be performed
	 * once by a single CPU.
	 */
	if (cpu > 0)
		goto out;

	rthal_timer_set_oneshot(1);

	err = rthal_irq_request(RTHAL_APIC_TIMER_IPI,
			  (rthal_irq_handler_t) tick_handler, NULL, NULL);

	if (err)
		return err;

	rthal_irq_host_request(RTHAL_BCAST_TICK_IRQ,
			       &rthal_broadcast_to_local_timers,
			       "rthal_broadcast_timer",
			       &rthal_broadcast_to_local_timers);

	rthal_nmi_init(&rthal_latency_above_max);
out:
	return 0;
}

#endif /* !CONFIG_GENERIC_CLOCKEVENTS */

void rthal_timer_release(int cpu)
{
#ifdef CONFIG_GENERIC_CLOCKEVENTS
	ipipe_release_tickdev(cpu);
#else
	rthal_irq_host_release(RTHAL_BCAST_TICK_IRQ,
			       &rthal_broadcast_to_local_timers);
#endif

	/*
	 * The rest of the cleanup work should only be performed once
	 * by a single CPU.
	 */
	if (cpu > 0)
		return;

	rthal_nmi_release();

	rthal_irq_release(RTHAL_APIC_TIMER_IPI);

	if (rthal_ktimer_saved_mode == KTIMER_MODE_PERIODIC)
		rthal_timer_set_periodic();
	else if (rthal_ktimer_saved_mode == KTIMER_MODE_ONESHOT)
		rthal_timer_set_oneshot(0);
}


#endif /* CONFIG_X86_LOCAL_APIC */

#ifdef CONFIG_GENERIC_CLOCKEVENTS

void rthal_timer_notify_switch(enum clock_event_mode mode,
			       struct clock_event_device *cdev)
{
	if (rthal_processor_id() > 0)
		/*
		 * We assume all CPUs switch the same way, so we only
		 * track mode switches from the boot CPU.
		 */
		return;

	rthal_ktimer_saved_mode = mode;
}

EXPORT_SYMBOL(rthal_timer_notify_switch);

#endif /* CONFIG_GENERIC_CLOCKEVENTS */

int rthal_irq_host_request(unsigned irq,
			   rthal_irq_host_handler_t handler,
			   char *name, void *dev_id)
{
	unsigned long flags;

	if (irq >= IPIPE_NR_XIRQS || !handler)
		return -EINVAL;

	spin_lock_irqsave(&rthal_irq_descp(irq)->lock, flags);

	if (rthal_linux_irq[irq].count++ == 0 && rthal_irq_descp(irq)->action) {
		rthal_linux_irq[irq].flags =
		    rthal_irq_descp(irq)->action->flags;
		rthal_irq_descp(irq)->action->flags |= IRQF_SHARED;
	}

	spin_unlock_irqrestore(&rthal_irq_descp(irq)->lock, flags);

	return request_irq(irq, handler, IRQF_SHARED, name, dev_id);
}

int rthal_irq_host_release(unsigned irq, void *dev_id)
{
	unsigned long flags;

	if (irq >= NR_IRQS || rthal_linux_irq[irq].count == 0)
		return -EINVAL;

	free_irq(irq, dev_id);

	spin_lock_irqsave(&rthal_irq_descp(irq)->lock, flags);

	if (--rthal_linux_irq[irq].count == 0 && rthal_irq_descp(irq)->action)
		rthal_irq_descp(irq)->action->flags =
		    rthal_linux_irq[irq].flags;

	spin_unlock_irqrestore(&rthal_irq_descp(irq)->lock, flags);

	return 0;
}

int rthal_irq_enable(unsigned irq)
{
	if (irq >= NR_IRQS)
		return -EINVAL;

	rthal_irq_desc_status(irq) &= ~IRQ_DISABLED;

	return rthal_irq_chip_enable(irq);
}

int rthal_irq_disable(unsigned irq)
{

	if (irq >= NR_IRQS)
		return -EINVAL;

	rthal_irq_desc_status(irq) |= IRQ_DISABLED;

	return rthal_irq_chip_disable(irq);
}

int rthal_irq_end(unsigned irq)
{
	if (irq >= NR_IRQS)
		return -EINVAL;

	return rthal_irq_chip_end(irq);
}

static inline int do_exception_event(unsigned event, unsigned domid, void *data)
{
	/* Notes:

	   1) GPF needs to be propagated downstream whichever domain caused
	   it. This is required so that we don't spuriously raise a fatal
	   error when some fixup code is available to solve the error
	   condition. For instance, Linux always attempts to reload the %gs
	   segment register when switching a process in (__switch_to()),
	   regardless of its value. It is then up to Linux's GPF handling
	   code to search for a possible fixup whenever some exception
	   occurs. In the particular case of the %gs register, such an
	   exception could be raised for an exiting process if a preemption
	   occurs inside a short time window, after the process's LDT has
	   been dropped, but before the kernel lock is taken.  The same goes
	   for Xenomai switching back a Linux thread in non-RT mode which
	   happens to have been preempted inside do_exit() after the MM
	   context has been dropped (thus the LDT too). In such a case, %gs
	   could be reloaded with what used to be the TLS descriptor of the
	   exiting thread, but unfortunately after the LDT itself has been
	   dropped. Since the default LDT is only 5 entries long, any attempt
	   to refer to an LDT-indexed descriptor above this value would cause
	   a GPF.  2) NMI is not pipelined. */

	if (domid == RTHAL_DOMAIN_ID) {
		rthal_realtime_faults[rthal_processor_id()][event]++;

		if (rthal_trap_handler != NULL &&
		    rthal_trap_handler(event, domid, data) != 0)
			return RTHAL_EVENT_STOP;
	}

	return RTHAL_EVENT_PROPAGATE;
}

RTHAL_DECLARE_EVENT(exception_event);

static inline void do_rthal_domain_entry(void)
{
	unsigned trapnr;

	/* Trap all faults. */
	for (trapnr = 0; trapnr < RTHAL_NR_FAULTS; trapnr++)
		rthal_catch_exception(trapnr, &exception_event);

	printk(KERN_INFO "Xenomai: hal/%s started.\n", RTHAL_ARCH_NAME);
}

RTHAL_DECLARE_DOMAIN(rthal_domain_entry);

/*@}*/
