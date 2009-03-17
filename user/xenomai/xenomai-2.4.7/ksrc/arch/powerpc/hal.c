/**
 *   @ingroup hal
 *   @file
 *
 *   Adeos-based Real-Time Abstraction Layer for PowerPC.
 *
 *   Copyright (C) 2004-2006 Philippe Gerum.
 *
 *   64-bit PowerPC adoption
 *     copyright (C) 2005 Taneli Vähäkangas and Heikki Lindholm
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
 * PowerPC-specific HAL services.
 *
 *@{*/

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/irq.h>
#include <linux/console.h>
#include <asm/system.h>
#include <asm/hardirq.h>
#include <asm/hw_irq.h>
#include <asm/irq.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/xenomai/hal.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */
#include <stdarg.h>

#ifdef DEBUG
#define DBG(fmt...) udbg_printf(fmt)
#else
#define DBG(fmt...)
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define rthal_irq_handlerp(irq) rthal_irq_descp(irq)->handler
#else
#define rthal_irq_handlerp(irq) rthal_irq_descp(irq)->chip
#endif

static struct {
	unsigned long flags;
	int count;
} rthal_linux_irq[IPIPE_NR_XIRQS];

enum rthal_ktimer_mode rthal_ktimer_saved_mode;

#define RTHAL_SET_ONESHOT_XENOMAI	1
#define RTHAL_SET_ONESHOT_LINUX		2
#define RTHAL_SET_PERIODIC		3

static inline void rthal_disarm_decr(int disarmed)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	disarm_decr[rthal_processor_id()] = disarmed;
#else
	per_cpu(disarm_decr, rthal_processor_id()) = disarmed;
#endif
}

static inline void rthal_setup_oneshot_dec(void)
{
#ifdef CONFIG_40x
	mtspr(SPRN_TCR, mfspr(SPRN_TCR) & ~TCR_ARE);    /* Auto-reload off. */
#endif /* CONFIG_40x */
}

static inline void rthal_setup_periodic_dec(void)
{
#ifdef CONFIG_40x
	mtspr(SPRN_TCR, mfspr(SPRN_TCR) | TCR_ARE); /* Auto-reload on. */
	mtspr(SPRN_PIT, tb_ticks_per_jiffy);
#else /* !CONFIG_40x */
	set_dec(tb_ticks_per_jiffy);
#endif /* CONFIG_40x */
}

#ifdef CONFIG_SMP

static void rthal_critical_sync(void)
{
	switch (rthal_sync_op) {
	case RTHAL_SET_ONESHOT_XENOMAI:
		rthal_setup_oneshot_dec();
		rthal_disarm_decr(1);
		break;

	case RTHAL_SET_ONESHOT_LINUX:
		rthal_setup_oneshot_dec();
		rthal_disarm_decr(0);
		/* We need to keep the timing cycle alive for the kernel. */
		rthal_trigger_irq(RTHAL_TIMER_IRQ);
		break;

	case RTHAL_SET_PERIODIC:
		rthal_setup_periodic_dec();
		rthal_disarm_decr(0);
		break;
	}
}

#else /* CONFIG_SMP */

static void rthal_critical_sync(void)
{
}

#endif /* !CONFIG_SMP */

static void rthal_timer_set_oneshot(int rt_mode)
{
	unsigned long flags;

	flags = rthal_critical_enter(rthal_critical_sync);
	if (rt_mode) {
		rthal_sync_op = RTHAL_SET_ONESHOT_XENOMAI;
		rthal_setup_oneshot_dec();
		rthal_disarm_decr(1);
	} else {
		rthal_sync_op = RTHAL_SET_ONESHOT_LINUX;
		rthal_setup_oneshot_dec();
		rthal_disarm_decr(0);
		/* We need to keep the timing cycle alive for the kernel. */
		rthal_trigger_irq(RTHAL_TIMER_IRQ);
	}
	rthal_critical_exit(flags);
}

static void rthal_timer_set_periodic(void)
{
	unsigned long flags;

	flags = rthal_critical_enter(&rthal_critical_sync);
	rthal_sync_op = RTHAL_SET_PERIODIC;
	rthal_setup_periodic_dec();
	rthal_disarm_decr(0);
	rthal_critical_exit(flags);
}

static int cpu_timers_requested;

#ifdef CONFIG_GENERIC_CLOCKEVENTS

int rthal_timer_request(
	void (*tick_handler)(void),
	void (*mode_emul)(enum clock_event_mode mode,
			  struct clock_event_device *cdev),
	int (*tick_emul)(unsigned long delay,
			 struct clock_event_device *cdev),
	int cpu)
{
	unsigned long dummy, *tmfreq = &dummy;
	int tickval, err, res;

	if (rthal_timerfreq_arg == 0)
		tmfreq = &rthal_tunables.timer_freq;

	res = ipipe_request_tickdev("decrementer", mode_emul, tick_emul, cpu,
				    tmfreq);
	/*
	 * Ignore the returned timer freq; the timebase freq is more
	 * accurate (CPU_FREQ == timebase freq for this port).
	 */
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

	/*
	 * The rest of the initialization should only be performed
	 * once by a single CPU.
	 */
	if (cpu_timers_requested++ > 0)
		goto out;

	err = rthal_irq_request(RTHAL_TIMER_IRQ,
				(rthal_irq_handler_t) tick_handler,
				NULL, NULL);
	if (err)
		return err;

#ifdef CONFIG_SMP
	err = rthal_irq_request(RTHAL_TIMER_IPI,
				(rthal_irq_handler_t) tick_handler,
				NULL, NULL);
	if (err)
		return err;
#endif

	rthal_timer_set_oneshot(1);

out:
	return tickval;
}

void rthal_timer_release(int cpu)
{
	ipipe_release_tickdev(cpu);

	if (--cpu_timers_requested > 0)
		return;

#ifdef CONFIG_SMP
	rthal_irq_release(RTHAL_TIMER_IPI);
#endif /* CONFIG_SMP */
	rthal_irq_release(RTHAL_TIMER_IRQ);

	if (rthal_ktimer_saved_mode == KTIMER_MODE_PERIODIC)
		rthal_timer_set_periodic();
	else if (rthal_ktimer_saved_mode == KTIMER_MODE_ONESHOT)
		rthal_timer_set_oneshot(0);
}

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

#else /* !CONFIG_GENERIC_CLOCKEVENTS */

#ifdef CONFIG_SMP
static void rthal_smp_relay_tick(unsigned irq, void *cookie)
{
	rthal_irq_host_pend(RTHAL_TIMER_IRQ);
}
#endif

int rthal_timer_request(void (*handler)(void), int cpu)
{
	int err;
	/*
	 * The rest of the initialization should only be performed
	 * once by a single CPU.
	 */
	if (cpu_timers_requested++ > 0)
		return 0;

	rthal_ktimer_saved_mode = KTIMER_MODE_PERIODIC;

	if (rthal_timerfreq_arg == 0)
		rthal_tunables.timer_freq = rthal_cpufreq_arg;

	err = rthal_irq_request(RTHAL_TIMER_IRQ,
				(rthal_irq_handler_t) handler,
				NULL, NULL);
	if (err)
		return err;

#ifdef CONFIG_SMP
	err = rthal_irq_request(RTHAL_TIMER_IPI,
				(rthal_irq_handler_t) handler,
				NULL, NULL);
	if (err)
		return err;
	err = rthal_irq_request(RTHAL_HOST_TIMER_IPI,
				rthal_smp_relay_tick,
				NULL, NULL);
	if (err)
		return err;
#endif

	rthal_timer_set_oneshot(1);

	return 0;
}

void rthal_timer_release(int cpu)
{
	if (--cpu_timers_requested > 0)
		return;

#ifdef CONFIG_SMP
	rthal_irq_release(RTHAL_HOST_TIMER_IPI);
	rthal_irq_release(RTHAL_TIMER_IPI);
#endif /* CONFIG_SMP */
	rthal_irq_release(RTHAL_TIMER_IRQ);
	rthal_timer_set_periodic();
}

#endif /* !CONFIG_GENERIC_CLOCKEVENTS */

unsigned long rthal_timer_calibrate(void)
{
	return 1000000000 / RTHAL_CPU_FREQ;
}

int rthal_irq_host_request(unsigned irq,
                           rthal_irq_host_handler_t handler,
                           char *name, void *dev_id)
{
	unsigned long flags;

	if (irq >= IPIPE_NR_XIRQS || !handler)
		return -EINVAL;

	spin_lock_irqsave(&rthal_irq_descp(irq)->lock, flags);

	if (rthal_linux_irq[irq].count++ == 0 && rthal_irq_descp(irq)->action) {
		rthal_linux_irq[irq].flags = rthal_irq_descp(irq)->action->flags;
		rthal_irq_descp(irq)->action->flags |= IRQF_SHARED;
	}

	spin_unlock_irqrestore(&rthal_irq_descp(irq)->lock, flags);

	return request_irq(irq, handler, IRQF_SHARED, name, dev_id);
}

int rthal_irq_host_release(unsigned irq, void *dev_id)
{
	unsigned long flags;

	if (irq >= IPIPE_NR_XIRQS || rthal_linux_irq[irq].count == 0)
		return -EINVAL;

	free_irq(irq, dev_id);

	spin_lock_irqsave(&rthal_irq_descp(irq)->lock, flags);

	if (--rthal_linux_irq[irq].count == 0 && rthal_irq_descp(irq)->action)
		rthal_irq_descp(irq)->action->flags = rthal_linux_irq[irq].flags;

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

	printk(KERN_INFO "Xenomai: hal/powerpc started.\n");
}

RTHAL_DECLARE_DOMAIN(rthal_domain_entry);

int rthal_arch_init(void)
{
#ifdef CONFIG_ALTIVEC
	if (!cpu_has_feature(CPU_FTR_ALTIVEC)) {
		printk
			("Xenomai: ALTIVEC support enabled in kernel but no hardware found.\n"
			 "         Disable CONFIG_ALTIVEC in the kernel configuration.\n");
		return -ENODEV;
	}
#endif /* CONFIG_ALTIVEC */

	if (rthal_cpufreq_arg == 0)
		/* The CPU frequency is expressed as the timebase frequency
		   for this port. */
		rthal_cpufreq_arg = (unsigned long)rthal_get_cpufreq();

	return 0;
}

void rthal_arch_cleanup(void)
{
	/* Nothing to cleanup so far. */
	printk(KERN_INFO "Xenomai: hal/powerpc stopped.\n");
}

/*@}*/

EXPORT_SYMBOL(rthal_arch_init);
EXPORT_SYMBOL(rthal_arch_cleanup);
EXPORT_SYMBOL(rthal_thread_switch);
EXPORT_SYMBOL(rthal_thread_trampoline);

#ifdef CONFIG_XENO_HW_FPU
EXPORT_SYMBOL(rthal_init_fpu);
EXPORT_SYMBOL(rthal_save_fpu);
EXPORT_SYMBOL(rthal_restore_fpu);
#endif /* CONFIG_XENO_HW_FPU */
