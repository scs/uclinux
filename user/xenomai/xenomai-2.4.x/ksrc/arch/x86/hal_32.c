/**
 *   @ingroup hal
 *   @file
 *
 *   Adeos-based Real-Time Abstraction Layer for x86.
 *
 *   Inspired from original RTAI/x86 HAL interface: \n
 *   Copyright &copy; 2000 Paolo Mantegazza, \n
 *   Copyright &copy; 2000 Steve Papacharalambous, \n
 *   Copyright &copy; 2000 Stuart Hughes, \n
 *
 *   RTAI/x86 rewrite over Adeos: \n
 *   Copyright &copy; 2002-2007 Philippe Gerum.
 *   NMI watchdog, SMI workaround: \n
 *   Copyright &copy; 2004 Gilles Chanteperdrix.
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
 * i386-specific HAL services.
 *
 *@{*/

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/bitops.h>
#include <asm/system.h>
#include <asm/hardirq.h>
#include <asm/desc.h>
#include <asm/io.h>
#include <asm/delay.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/xenomai/hal.h>
#include <stdarg.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#if !defined(CONFIG_X86_TSC) && defined(CONFIG_VT)
#include <linux/vt_kern.h>

static void (*old_mksound) (unsigned int hz, unsigned int ticks);

static void dummy_mksound(unsigned int hz, unsigned int ticks)
{
}
#endif /* !CONFIG_X86_TSC && CONFIG_VT */
#else /* Linux < 2.6 */
#include <asm/nmi.h>
#endif

#ifdef CONFIG_X86_LOCAL_APIC

unsigned long rthal_timer_calibrate(void)
{
	unsigned long flags, v;
	rthal_time_t t, dt;
	int i;

	flags = rthal_critical_enter(NULL);

	t = rthal_rdtsc();

	for (i = 0; i < 20; i++) {
		v = apic_read(APIC_TMICT);
		apic_write(APIC_TMICT, v);
	}

	dt = (rthal_rdtsc() - t) / 2;

	rthal_critical_exit(flags);

#ifdef CONFIG_IPIPE_TRACE_IRQSOFF
	/* Reset the max trace, since it contains the calibration time now. */
	rthal_trace_max_reset();
#endif /* CONFIG_IPIPE_TRACE_IRQSOFF */

	return rthal_imuldiv(dt, 20, RTHAL_CPU_FREQ);
}

#ifdef CONFIG_XENO_HW_NMI_DEBUG_LATENCY

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)

#include <linux/vt_kern.h>

extern void show_registers(struct pt_regs *regs);

extern spinlock_t nmi_print_lock;

void die_nmi(struct pt_regs *regs, const char *msg)
{
	spin_lock(&nmi_print_lock);
	/*
	 * We are in trouble anyway, lets at least try
	 * to get a message out.
	 */
	bust_spinlocks(1);
	printk(msg);
	show_registers(regs);
	printk("console shuts up ...\n");
	console_silent();
	spin_unlock(&nmi_print_lock);
	bust_spinlocks(0);
	do_exit(SIGSEGV);
}

#endif /* Linux < 2.6 */

void rthal_latency_above_max(struct pt_regs *regs)
{
	/* Try to report via latency tracer first, then fall back to panic. */
	if (rthal_trace_user_freeze(rthal_maxlat_us, 1) < 0) {
		char buf[128];

		snprintf(buf,
			 sizeof(buf),
			 "NMI watchdog detected timer latency above %u us\n",
			 rthal_maxlat_us);
		die_nmi(regs, buf);
	}
}

#endif /* CONFIG_XENO_HW_NMI_DEBUG_LATENCY */

#else /* !CONFIG_X86_LOCAL_APIC */

unsigned long rthal_timer_calibrate(void)
{
	unsigned long flags;
	rthal_time_t t, dt;
	int i, count;

	rthal_local_irq_save_hw(flags);

	/* Read the current latch value, whatever the current mode is. */

	outb_p(0x00, PIT_MODE);
	count = inb_p(PIT_CH0);
	count |= inb_p(PIT_CH0) << 8;

	if (count > LATCH) /* For broken VIA686a hardware. */
		count = LATCH - 1;
	/*
	 * We only want to measure the average time needed to program
	 * the next shot, so we basically don't care about the current
	 * PIT mode. We just rewrite the original latch value at each
	 * iteration.
	 */

	t = rthal_rdtsc();

	for (i = 0; i < 20; i++) {
		outb(count & 0xff, PIT_CH0);
		outb(count >> 8, PIT_CH0);
	}

	dt = rthal_rdtsc() - t;

	rthal_local_irq_restore_hw(flags);

#ifdef CONFIG_IPIPE_TRACE_IRQSOFF
	/* Reset the max trace, since it contains the calibration time now. */
	rthal_trace_max_reset();
#endif /* CONFIG_IPIPE_TRACE_IRQSOFF */

	return rthal_imuldiv(dt, 20, RTHAL_CPU_FREQ);
}

static void rthal_timer_set_oneshot(void)
{
	unsigned long flags;
	int count;

	rthal_local_irq_save_hw(flags);
	/*
	 * We should be running in rate generator mode (M2) on entry,
	 * so read the current latch value, in order to roughly
	 * restart the timing where we left it, after the switch to
	 * software strobe mode.
	 */
	outb_p(0x00, PIT_MODE);
	count = inb_p(PIT_CH0);
	count |= inb_p(PIT_CH0) << 8;

	if (count > LATCH) /* For broken VIA686a hardware. */
		count = LATCH - 1;
	/*
	 * Force software triggered strobe mode (M4) on PIT channel
	 * #0.  We also program an initial shot at a sane value to
	 * restart the timing cycle.
	 */
	udelay(10);
	outb_p(0x38, PIT_MODE);
	outb(count & 0xff, PIT_CH0);
	outb(count >> 8, PIT_CH0);
	rthal_local_irq_restore_hw(flags);
}

static void rthal_timer_set_periodic(void)
{
	unsigned long flags;

	rthal_local_irq_save_hw(flags);
	outb_p(0x34, PIT_MODE);
	outb(LATCH & 0xff, PIT_CH0);
	outb(LATCH >> 8, PIT_CH0);
	rthal_local_irq_restore_hw(flags);
}

int rthal_timer_request(
	void (*tick_handler)(void),
#ifdef CONFIG_GENERIC_CLOCKEVENTS
	void (*mode_emul)(enum clock_event_mode mode,
			  struct clock_event_device *cdev),
	int (*tick_emul)(unsigned long delay,
			 struct clock_event_device *cdev),
#endif
	int cpu)
{
	int tickval, err;

#ifdef CONFIG_GENERIC_CLOCKEVENTS
	unsigned long tmfreq;

#ifdef __IPIPE_FEATURE_REQUEST_TICKDEV
	int res = ipipe_request_tickdev("pit", mode_emul, tick_emul, cpu,
					&tmfreq);
#else
	int res = ipipe_request_tickdev("pit",
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
		return -ENOSYS;

	default:
		return res;
	}
	rthal_ktimer_saved_mode = res;

	if (rthal_timerfreq_arg == 0)
		rthal_tunables.timer_freq = tmfreq;
#else /* !CONFIG_GENERIC_CLOCKEVENTS */
	/*
	 * Out caller has to to emulate the periodic host tick by its
	 * own means once we will have grabbed the PIT.
	 */
	tickval = 1000000000UL / HZ;
	rthal_ktimer_saved_mode = KTIMER_MODE_PERIODIC;

	if (rthal_timerfreq_arg == 0)
		rthal_tunables.timer_freq = CLOCK_TICK_RATE;
#endif /* !CONFIG_GENERIC_CLOCKEVENTS */

	/*
	 * No APIC means that we can't be running in SMP mode, so this
	 * routine will be called only once, for CPU #0.
	 */

	rthal_timer_set_oneshot();

	err = rthal_irq_request(RTHAL_TIMER_IRQ,
				(rthal_irq_handler_t)tick_handler, NULL, NULL);

	return err ?: tickval;
}

void rthal_timer_release(int cpu)
{
#ifdef CONFIG_GENERIC_CLOCKEVENTS
	ipipe_release_tickdev(cpu);
#endif
	rthal_irq_release(RTHAL_TIMER_IRQ);

	if (rthal_ktimer_saved_mode == KTIMER_MODE_PERIODIC)
		rthal_timer_set_periodic();
	else if (rthal_ktimer_saved_mode == KTIMER_MODE_ONESHOT)
		/* We need to keep the timing cycle alive for the kernel. */
		rthal_trigger_irq(RTHAL_TIMER_IRQ);
}

#endif /* !CONFIG_X86_LOCAL_APIC */

#ifndef CONFIG_X86_TSC

static rthal_time_t rthal_tsc_8254;

static int rthal_last_8254_counter2;

/* TSC emulation using PIT channel #2. */

void rthal_setup_8254_tsc(void)
{
	unsigned long flags;
	int count;

	rthal_local_irq_save_hw(flags);

	outb_p(0x0, PIT_MODE);
	count = inb_p(PIT_CH0);
	count |= inb_p(PIT_CH0) << 8;
	outb_p(0xb4, PIT_MODE);
	outb_p(RTHAL_8254_COUNT2LATCH & 0xff, PIT_CH2);
	outb_p(RTHAL_8254_COUNT2LATCH >> 8, PIT_CH2);
	rthal_tsc_8254 = count + LATCH * jiffies;
	rthal_last_8254_counter2 = 0;
	/* Gate high, disable speaker */
	outb_p((inb_p(0x61) & ~0x2) | 1, 0x61);

	rthal_local_irq_restore_hw(flags);
}

rthal_time_t rthal_get_8254_tsc(void)
{
	unsigned long flags;
	int delta, count;
	rthal_time_t t;

	rthal_local_irq_save_hw(flags);

	outb(0xd8, PIT_MODE);
	count = inb(PIT_CH2);
	delta = rthal_last_8254_counter2 - (count |= (inb(PIT_CH2) << 8));
	rthal_last_8254_counter2 = count;
	rthal_tsc_8254 += (delta > 0 ? delta : delta + RTHAL_8254_COUNT2LATCH);
	t = rthal_tsc_8254;

	rthal_local_irq_restore_hw(flags);

	return t;
}

#endif /* !CONFIG_X86_TSC */

int rthal_arch_init(void)
{
#ifdef CONFIG_X86_LOCAL_APIC
	if (!boot_cpu_has(X86_FEATURE_APIC)) {
		printk("Xenomai: Local APIC absent or disabled!\n"
		       "         Disable APIC support or pass \"lapic=1\" as bootparam.\n");
		rthal_smi_restore();
		return -ENODEV;
	}
#ifdef CONFIG_GENERIC_CLOCKEVENTS
	if (nmi_watchdog == NMI_IO_APIC) {
		printk("Xenomai: NMI kernel watchdog set to NMI_IO_APIC (nmi_watchdog=1).\n"
		       "         This will disable the LAPIC as a clock device, and\n"
		       "         cause Xenomai to fail providing any timing service.\n"
		       "         Use NMI_LOCAL_APIC (nmi_watchdog=2), or disable the\n"
		       "         NMI support entirely (nmi_watchdog=0).");
		return -ENODEV;
	}
#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && !defined(CONFIG_X86_TSC) && defined(CONFIG_VT)
	/* Prevent the speaker code from bugging our TSC emulation, also
	   based on PIT channel 2. kd_mksound is exported by the Adeos
	   patch. */
	old_mksound = kd_mksound;
	kd_mksound = &dummy_mksound;
#endif /* !CONFIG_X86_LOCAL_APIC && Linux < 2.6 && !CONFIG_X86_TSC && CONFIG_VT */

	if (rthal_cpufreq_arg == 0)
#ifdef CONFIG_X86_TSC
		/* FIXME: 4Ghz barrier is close... */
		rthal_cpufreq_arg = rthal_get_cpufreq();
#else /* ! CONFIG_X86_TSC */
		rthal_cpufreq_arg = CLOCK_TICK_RATE;

	rthal_setup_8254_tsc();
#endif /* CONFIG_X86_TSC */

	return 0;
}

void rthal_arch_cleanup(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) && !defined(CONFIG_X86_TSC) && defined(CONFIG_VT)
	/* Restore previous PC speaker code. */
	kd_mksound = old_mksound;
#endif /* Linux < 2.6 && !CONFIG_X86_TSC && CONFIG_VT */
	printk(KERN_INFO "Xenomai: hal/i386 stopped.\n");
}

/*@}*/

EXPORT_SYMBOL(rthal_arch_init);
EXPORT_SYMBOL(rthal_arch_cleanup);
#ifndef CONFIG_X86_TSC
EXPORT_SYMBOL(rthal_get_8254_tsc);
#endif /* !CONFIG_X86_TSC */
