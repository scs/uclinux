/**
 *   @ingroup hal
 *   @file
 *
 *   Real-Time Hardware Abstraction Layer for ARM.
 *
 *   Copyright &copy; 2002-2004 Philippe Gerum.
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
 *   along with Xenomai; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

#ifndef _XENO_ASM_ARM_HAL_H
#define _XENO_ASM_ARM_HAL_H

#include <asm-generic/xenomai/hal.h>	/* Read the generic bits. */
#include <asm/byteorder.h>

#ifdef CONFIG_ARCH_AT91
#include <linux/stringify.h>
#define RTHAL_TIMER_DEVICE	"TC" __stringify(CONFIG_IPIPE_AT91_TC) " RC"
#define RTHAL_CLOCK_DEVICE	"TC" __stringify(CONFIG_IPIPE_AT91_TC) " CV"
#elif defined(CONFIG_ARCH_IMX)
#define RTHAL_TIMER_DEVICE	"TCMP"
#define RTHAL_CLOCK_DEVICE	"TCN"
#elif defined(CONFIG_ARCH_IMX21)
#define RTHAL_TIMER_DEVICE	"TCMP"
#define RTHAL_CLOCK_DEVICE	"TCN"
#elif defined(CONFIG_ARCH_INTEGRATOR)
#define RTHAL_TIMER_DEVICE	"TIMER1"
#define RTHAL_CLOCK_DEVICE	"TIMER1"
#elif defined(CONFIG_ARCH_IXP4XX)
#define RTHAL_TIMER_DEVICE	"OSRT1"
#define RTHAL_CLOCK_DEVICE	"OSTS"
#elif defined(CONFIG_ARCH_PXA)
#define RTHAL_TIMER_DEVICE	"OSMR0"
#define RTHAL_CLOCK_DEVICE	"OSCR"
#elif defined(CONFIG_ARCH_S3C2410)
#define RTHAL_TIMER_DEVICE	"TCNTB4"
#define RTHAL_CLOCK_DEVICE	"TCNTO3"
#elif defined(CONFIG_ARCH_SA1100)
#define RTHAL_TIMER_DEVICE	"OSMR0"
#define RTHAL_CLOCK_DEVICE	"OSCR"
#endif /* CONFIG_ARCH_SA1100 */

typedef unsigned long long rthal_time_t;

#if __LINUX_ARM_ARCH__ < 5
static inline __attribute_const__ unsigned long ffnz (unsigned long x)
{
	int r = 0;

	if (!x)
		return 0;
	if (!(x & 0xffff)) {
		x >>= 16;
		r += 16;
	}
	if (!(x & 0xff)) {
		x >>= 8;
		r += 8;
	}
	if (!(x & 0xf)) {
		x >>= 4;
		r += 4;
	}
	if (!(x & 3)) {
		x >>= 2;
		r += 2;
	}
	if (!(x & 1)) {
		x >>= 1;
		r += 1;
	}
	return r;
}
#else
static inline __attribute_const__ unsigned long ffnz (unsigned long ul)
{
	int __r;
	__asm__("clz\t%0, %1" : "=r" (__r) : "r"(ul & (-ul)) : "cc");
	return 31 - __r;
}
#endif

#ifndef __cplusplus
#include <asm/system.h>
#include <asm/timex.h>
#include <asm/xenomai/atomic.h>
#include <asm/processor.h>
#include <asm/ipipe.h>
#include <asm/mach/irq.h>

#define RTHAL_TIMER_IRQ   __ipipe_mach_timerint

#define rthal_grab_control()     do { } while(0)
#define rthal_release_control()  do { } while(0)

static inline unsigned long long rthal_rdtsc (void)
{
    unsigned long long t;
    rthal_read_tsc(t);
    return t;
}

static inline struct task_struct *rthal_current_host_task (int cpuid)
{
    return current;
}

static inline void rthal_timer_program_shot (unsigned long delay)
{
    if(!delay)
	rthal_trigger_irq(RTHAL_TIMER_IRQ);
    else
	__ipipe_mach_set_dec(delay);
}

static inline struct mm_struct *rthal_get_active_mm(void)
{
#ifdef TIF_MMSWITCH_INT
	return per_cpu(ipipe_active_mm, smp_processor_id());
#else /* !TIF_MMSWITCH_INT */
	return current->active_mm;
#endif /* !TIF_MMSWITCH_INT */
}

    /* Private interface -- Internal use only */

asmlinkage void rthal_thread_switch(struct task_struct *prev,
				    struct thread_info *out,
				    struct thread_info *in);

asmlinkage void rthal_thread_trampoline(void);

#ifdef CONFIG_XENO_HW_FPU

typedef struct rthal_fpenv {

    /*
     * This layout must follow exactely the definition of the FPU
     *  area in the ARM thread_info structure. 'tp_value' is also
     *  saved even if it is not needed, but it shouldn't matter.
     */
    __u8                    used_cp[16];    /* thread used copro */
    unsigned long           tp_value;
    union fp_state          fpstate;
    union vfp_state         vfpstate;
} rthal_fpenv_t;

static inline void rthal_init_fpu(rthal_fpenv_t *fpuenv)
{
    fp_init(&fpuenv->fpstate);
#if defined(CONFIG_VFP)
    vfp_flush_thread(&fpuenv->vfpstate);
#endif
}

static inline void rthal_save_fpu(rthal_fpenv_t *fpuenv)
{
}

static inline void rthal_restore_fpu(rthal_fpenv_t *fpuenv)
{
}

#define rthal_get_fpu_owner(cur) ({                                         \
    struct task_struct * _cur = (cur);                                      \
    ((task_thread_info(_cur)->used_cp[1] | task_thread_info(_cur)->used_cp[2])    \
        ? _cur : NULL);                                                     \
})

#define rthal_disable_fpu() \
	task_thread_info(current)->used_cp[1] = task_thread_info(current)->used_cp[2] = 0;

#define rthal_enable_fpu() \
	task_thread_info(current)->used_cp[1] = task_thread_info(current)->used_cp[2] = 1;

#endif /* CONFIG_XENO_HW_FPU */

static const char *const rthal_fault_labels[] = {
    [IPIPE_TRAP_ACCESS] = "Data or instruction access",
    [IPIPE_TRAP_SECTION] = "Section fault",
    [IPIPE_TRAP_DABT] = "Generic data abort",
    [IPIPE_TRAP_UNKNOWN] = "Unknown exception",
    [IPIPE_TRAP_BREAK] = "Instruction breakpoint",
    [IPIPE_TRAP_FPU] = "Floating point exception",
    [IPIPE_TRAP_VFP] = "VFP Floating point exception",
    [IPIPE_TRAP_UNDEFINSTR] = "Undefined instruction",
#ifdef IPIPE_TRAP_ALIGNMENT
    [IPIPE_TRAP_ALIGNMENT] = "Unaligned access exception",
#endif /* IPIPE_TRAP_ALIGNMENT */
    [IPIPE_NR_FAULTS] = NULL
};

#endif /* !__cplusplus */

#endif /* !_XENO_ASM_ARM_HAL_H */

// vim: ts=4 et sw=4 sts=4
