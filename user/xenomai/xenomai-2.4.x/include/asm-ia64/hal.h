/**
 *   @ingroup hal
 *   @file
 *
 *   Real-Time Hardware Abstraction Layer for the ia64 architecture.
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
 *   along with Xenomai; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

#ifndef _XENO_ASM_IA64_HAL_H
#define _XENO_ASM_IA64_HAL_H

#include <asm-generic/xenomai/hal.h>	/* Read the generic bits. */

#define RTHAL_TIMER_DEVICE	"itm"
#define RTHAL_CLOCK_DEVICE	"itc"

typedef unsigned long long rthal_time_t;

static inline __attribute_const__ unsigned long ffnz (unsigned long ul)
{
    unsigned long r;
    asm ("popcnt %0=%1" : "=r" (r) : "r" ((ul-1) & ~ul));
    return r;
}

#ifndef __cplusplus
#include <asm/system.h>
#include <asm/xenomai/atomic.h>
#include <asm/processor.h>
#include <asm/delay.h>          /* For ia64_get_itc / ia64_set_itm */

#define RTHAL_TIMER_VECTOR      IPIPE_SERVICE_VECTOR3
#define RTHAL_TIMER_IRQ         IPIPE_SERVICE_IPI3
#define RTHAL_HOST_TIMER_VECTOR IA64_TIMER_VECTOR
#define RTHAL_HOST_TIMER_IRQ    __ia64_local_vector_to_irq(IA64_TIMER_VECTOR)

#define rthal_irq_descp(irq)  irq_descp(irq)
#define rthal_itm_next        __ipipe_itm_next
#define rthal_tick_irq        __ipipe_tick_irq

#define rthal_grab_control()     do { } while(0)
#define rthal_release_control()  do { } while(0)

static inline unsigned long long rthal_rdtsc (void)
{
    unsigned long long t;
    rthal_read_tsc(t);
    return t;
}

static inline void rthal_timer_program_shot (unsigned long delay)
{
/* With head-optimization, callers are expected to have switched off
   hard-IRQs already -- no need for additional protection in this case. */
#ifndef CONFIG_XENO_OPT_PIPELINE_HEAD
    unsigned long flags;

    rthal_local_irq_save_hw(flags);
#endif /* CONFIG_XENO_OPT_PIPELINE_HEAD */
    if (!delay)
	rthal_trigger_irq(RTHAL_TIMER_IRQ);
    else
	ia64_set_itm(ia64_get_itc() + delay);
#ifndef CONFIG_XENO_OPT_PIPELINE_HEAD
    rthal_local_irq_restore_hw(flags);
#endif /* CONFIG_XENO_OPT_PIPELINE_HEAD */
}

    /* Private interface -- Internal use only */

void rthal_thread_switch(__u64 *prev_ksp,
			 __u64 *next_ksp,
			 int user_p);

void rthal_prepare_stack(__u64 stackbase);

static const char *const rthal_fault_labels[] = {
    [0] = "General exception",
    [1] = "FPU disabled",
    [2] = "NaT consumption",
    [3] = "Unsupported data reference",
    [4] = "Debug",
    [5] = "FPU fault",
    [6] = "Unimplemented instruction address",
    [7] = "ia32 exception",
    [8] = "Generic fault",
    [9] = "Page fault",
    [10] = NULL
};

#endif /* !__cplusplus */

#endif /* !_XENO_ASM_IA64_HAL_H */
