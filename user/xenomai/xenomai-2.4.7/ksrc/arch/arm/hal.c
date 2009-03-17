/**
 *   @ingroup hal
 *   @file
 *
 *   Adeos-based Real-Time Abstraction Layer for PowerPC.
 *
 *   ARM port
 *     Copyright (C) 2005 Stelian Pop
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
 * ARM-specific HAL services.
 *
 *@{*/

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/mm.h>
#include <asm/system.h>
#include <asm/hardirq.h>
#include <asm/irq.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/xenomai/hal.h>
#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#endif /* CONFIG_PROC_FS */
#include <stdarg.h>

static struct {
    unsigned long flags;
    int count;
} rthal_linux_irq[IPIPE_NR_XIRQS];

enum rthal_ktimer_mode rthal_ktimer_saved_mode;

int rthal_timer_request(void (*handler)(void),
#ifdef CONFIG_GENERIC_CLOCKEVENTS
			void (*mode_emul)(enum clock_event_mode mode,
					  struct clock_event_device *cdev),
			int (*tick_emul)(unsigned long delay,
					 struct clock_event_device *cdev),
#endif /* CONFIG_GENERIC_CLOCKEVENTS */
			int cpu)
{
    int tickval, err;
    unsigned long flags;

#ifdef CONFIG_GENERIC_CLOCKEVENTS
    unsigned long dummy, *tmfreq = &dummy;

    if (rthal_timerfreq_arg == 0)
        tmfreq = &rthal_tunables.timer_freq;

    int res = ipipe_request_tickdev(RTHAL_TIMER_DEVICE, mode_emul,
				    tick_emul, cpu, tmfreq);
    
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
#else /* !CONFIG_GENERIC_CLOCKEVENTS */
    tickval = 1000000000UL / HZ;
    rthal_ktimer_saved_mode = KTIMER_MODE_PERIODIC;

    if (rthal_timerfreq_arg == 0)
	    rthal_tunables.timer_freq = CLOCK_TICK_RATE;
#endif /* !CONFIG_GENERIC_CLOCKEVENTS */

    flags = rthal_critical_enter(NULL);

    __ipipe_mach_timerstolen = 1;

    rthal_timer_program_shot(__ipipe_mach_ticks_per_jiffy);

    rthal_irq_release(RTHAL_TIMER_IRQ);

    err = rthal_irq_request(RTHAL_TIMER_IRQ,
                            (rthal_irq_handler_t) handler, NULL, NULL);

    rthal_critical_exit(flags);

    return err ?: tickval;
}

void rthal_timer_release(int cpu)
{
    unsigned long flags;

#ifdef CONFIG_GENERIC_CLOCKEVENTS
    ipipe_release_tickdev(cpu);
#endif    

    flags = rthal_critical_enter(NULL);

    __ipipe_mach_release_timer();

    rthal_irq_release(RTHAL_TIMER_IRQ);

    __ipipe_mach_timerstolen = 0;

    rthal_critical_exit(flags);
}

#ifdef CONFIG_GENERIC_CLOCKEVENTS
void rthal_timer_notify_switch(enum clock_event_mode mode,
			       struct clock_event_device *cdev)
{
	rthal_ktimer_saved_mode = mode;
}

EXPORT_SYMBOL(rthal_timer_notify_switch);
#endif

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

    spin_lock_irqsave(rthal_irq_desc_lock(irq), flags);

    if (rthal_linux_irq[irq].count++ == 0 && rthal_irq_descp(irq)->action) {
        rthal_linux_irq[irq].flags = rthal_irq_descp(irq)->action->flags;
        rthal_irq_descp(irq)->action->flags |= IRQF_SHARED;
    }

    spin_unlock_irqrestore(rthal_irq_desc_lock(irq), flags);

    return request_irq(irq, handler, IRQF_SHARED, name, dev_id);
}

int rthal_irq_host_release(unsigned irq, void *dev_id)
{
    unsigned long flags;

    if (irq >= IPIPE_NR_XIRQS || rthal_linux_irq[irq].count == 0)
        return -EINVAL;

    free_irq(irq, dev_id);

    spin_lock_irqsave(rthal_irq_desc_lock(irq), flags);

    if (--rthal_linux_irq[irq].count == 0 && rthal_irq_descp(irq)->action)
        rthal_irq_descp(irq)->action->flags = rthal_linux_irq[irq].flags;

    spin_unlock_irqrestore(rthal_irq_desc_lock(irq), flags);

    return 0;
}

int rthal_irq_enable(unsigned irq)
{
    if (irq >= IPIPE_NR_XIRQS)
        return -EINVAL;

    /* We don't care of disable nesting level: real-time IRQ channels
       are not meant to be shared with the regular kernel. */
    rthal_mark_irq_enabled(irq);
    return rthal_irq_chip_enable(irq);
}

int rthal_irq_disable(unsigned irq)
{
    if (irq >= IPIPE_NR_XIRQS)
        return -EINVAL;

    rthal_mark_irq_disabled(irq);
    return rthal_irq_chip_disable(irq);
}

int rthal_irq_end(unsigned irq)
{
    if (irq >= IPIPE_NR_XIRQS)
        return -EINVAL;

    return rthal_irq_chip_end(irq);
}

void __rthal_arm_fault_range(struct vm_area_struct *vma)
{
	unsigned long addr;
	for (addr = vma->vm_start; addr != vma->vm_end; addr += PAGE_SIZE)
		handle_mm_fault(vma->vm_mm, vma, addr, 1);
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

    printk(KERN_INFO "Xenomai: hal/arm started.\n");
}

RTHAL_DECLARE_DOMAIN(rthal_domain_entry);

int rthal_arch_init(void)
{
    if (rthal_cpufreq_arg == 0)
        /* The CPU frequency is expressed as the timebase frequency
           for this port. */
        rthal_cpufreq_arg = (unsigned long)rthal_get_cpufreq();

    if (rthal_timerfreq_arg == 0)
        rthal_timerfreq_arg = rthal_get_timerfreq();

    return 0;
}

void rthal_arch_cleanup(void)
{
    /* Nothing to cleanup so far. */
    printk(KERN_INFO "Xenomai: hal/arm stopped.\n");
}

/*@}*/

EXPORT_SYMBOL(rthal_arch_init);
EXPORT_SYMBOL(rthal_arch_cleanup);
EXPORT_SYMBOL(rthal_thread_switch);
EXPORT_SYMBOL(rthal_thread_trampoline);
EXPORT_SYMBOL(__rthal_arm_fault_range);
#if defined(CONFIG_VFP) && defined(CONFIG_XENO_HW_FPU)
EXPORT_SYMBOL(last_VFP_context);
EXPORT_SYMBOL(rthal_vfp_save);
EXPORT_SYMBOL(rthal_vfp_load);
#endif /* CONFIG_VFP && CONFIG_XENO_HW_FPU */

// vim: ts=4 et sw=4 sts=4
