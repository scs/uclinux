/**
 *   @ingroup hal
 *   @file
 *
 *   Adeos-based Real-Time Abstraction Layer for ia64.
 *
 *   Copyright &copy; 2002-2004 Philippe Gerum
 *   Copyright &copy; 2004 The HYADES project <http://www.hyades-itea.org>
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
 * ia64-specific HAL services.
 *
 *@{*/

#include <linux/version.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/module.h>
#include <linux/console.h>
#include <asm/system.h>
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

static void rthal_adjust_before_relay(unsigned irq, void *cookie)
{
    rthal_itm_next[rthal_processor_id()] = ia64_get_itc();
    rthal_propagate_irq(irq);
}

static void rthal_set_itv(void)
{
    rthal_itm_next[rthal_processor_id()] = ia64_get_itc();
    ia64_set_itv(irq_to_vector(rthal_tick_irq));
}

static void rthal_timer_set_irq(unsigned tick_irq)
{
    unsigned long flags;

    flags = rthal_critical_enter(&rthal_set_itv);
    rthal_tick_irq = tick_irq;
    rthal_set_itv();
    rthal_critical_exit(flags);
}

int rthal_timer_request(void (*handler) (void), int cpu)
{
    unsigned long flags;

    if (cpu > 0)
	    goto out;

    flags = rthal_critical_enter(NULL);

    rthal_irq_release(RTHAL_TIMER_IRQ);

    ipipe_tune_timer(0, IPIPE_GRAB_TIMER);

    if (rthal_irq_request(RTHAL_TIMER_IRQ,
                          (rthal_irq_handler_t) handler, NULL, NULL) < 0) {
        rthal_critical_exit(flags);
        return -EINVAL;
    }

    if (rthal_irq_request(RTHAL_HOST_TIMER_IRQ,
                          &rthal_adjust_before_relay, NULL, NULL) < 0) {
        rthal_critical_exit(flags);
        return -EINVAL;
    }

    rthal_critical_exit(flags);

    rthal_timer_set_irq(RTHAL_TIMER_IRQ);

out:

    return 0;
}

void rthal_timer_release(int cpu)
{
    unsigned long flags;

    if (cpu > 0)
	    return;

    rthal_timer_set_irq(RTHAL_HOST_TIMER_IRQ);
    ipipe_tune_timer(0, IPIPE_RESET_TIMER);
    flags = rthal_critical_enter(NULL);
    rthal_irq_release(RTHAL_TIMER_IRQ);
    rthal_irq_release(RTHAL_HOST_TIMER_IRQ);
    rthal_critical_exit(flags);
}

unsigned long rthal_timer_calibrate(void)
{
    unsigned long flags, delay;
    rthal_time_t t, dt;
    int i;

    delay = RTHAL_CPU_FREQ;     /* 1s */

    flags = rthal_critical_enter(NULL);

    t = rthal_rdtsc();

    for (i = 0; i < 10000; i++)
        rthal_timer_program_shot(delay);

    dt = rthal_rdtsc() - t;

    rthal_critical_exit(flags);

    return rthal_imuldiv(dt, 100000, RTHAL_CPU_FREQ);
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
    if (irq >= IPIPE_NR_XIRQS)
        return -EINVAL;

    if (rthal_irq_descp(irq)->handler == NULL ||
        rthal_irq_descp(irq)->handler->enable == NULL)
        return -ENODEV;

    rthal_irq_descp(irq)->status &= ~IRQ_DISABLED;
    rthal_irq_descp(irq)->handler->enable(irq);

    return 0;
}

int rthal_irq_disable(unsigned irq)
{

    if (irq >= IPIPE_NR_XIRQS)
        return -EINVAL;

    if (rthal_irq_descp(irq)->handler == NULL ||
        rthal_irq_descp(irq)->handler->disable == NULL)
        return -ENODEV;

    rthal_irq_descp(irq)->handler->disable(irq);
    rthal_irq_descp(irq)->status |= IRQ_DISABLED;

    return 0;
}

int rthal_irq_end(unsigned irq)
{
    if (irq >= IPIPE_NR_XIRQS)
        return -EINVAL;

    if (rthal_irq_descp(irq)->handler == NULL ||
        rthal_irq_descp(irq)->handler->enable == NULL)
        return -ENODEV;

    rthal_irq_descp(irq)->handler->enable(irq);

    return 0;
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

    printk(KERN_INFO "Xenomai: hal/ia64 started.\n");
}

RTHAL_DECLARE_DOMAIN(rthal_domain_entry);

int rthal_arch_init(void)
{
    if (rthal_cpufreq_arg == 0)
        rthal_cpufreq_arg = (unsigned long)rthal_get_cpufreq();

    if (rthal_timerfreq_arg == 0)
        rthal_timerfreq_arg = rthal_cpufreq_arg;

    return 0;
}

void rthal_arch_cleanup(void)
{
    /* Nothing to cleanup so far. */
    printk(KERN_INFO "Xenomai: hal/ia64 stopped.\n");
}

/*@}*/

EXPORT_SYMBOL(rthal_arch_init);
EXPORT_SYMBOL(rthal_arch_cleanup);
EXPORT_SYMBOL(rthal_thread_switch);
EXPORT_SYMBOL(rthal_prepare_stack);
