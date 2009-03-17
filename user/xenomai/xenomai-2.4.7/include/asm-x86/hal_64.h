/**
 * @ingroup hal
 * @file
 *
 * Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 */

#ifndef _XENO_ASM_X86_HAL_64_H
#define _XENO_ASM_X86_HAL_64_H

#define RTHAL_ARCH_NAME			"x86_64"
#define RTHAL_TIMER_DEVICE		"lapic"
#define RTHAL_CLOCK_DEVICE		"tsc"

#include <asm/xenomai/wrappers.h>
#include <asm-generic/xenomai/hal.h>    /* Read the generic bits. */

typedef unsigned long rthal_time_t;

static inline __attribute_const__ unsigned long ffnz(unsigned long ul)
{
        __asm__("bsfq %1, %0":"=r"(ul):"rm"(ul));
	return ul;
}

#ifndef __cplusplus
#include <asm/system.h>
#include <asm/io.h>
#include <asm/timex.h>
#include <asm/processor.h>
#include <asm/fixmap.h>
#include <asm/apic.h>
#include <asm/msr.h>
#include <asm/xenomai/atomic.h>
#include <asm/xenomai/smi.h>

#define RTHAL_APIC_TIMER_VECTOR		RTHAL_SERVICE_VECTOR3
#define RTHAL_APIC_TIMER_IPI		RTHAL_SERVICE_IPI3
#define RTHAL_APIC_ICOUNT		((RTHAL_TIMER_FREQ + HZ/2)/HZ)
#define RTHAL_TIMER_IRQ			RTHAL_APIC_TIMER_IPI
#define RTHAL_NMICLK_FREQ		RTHAL_CPU_FREQ
#define RTHAL_HOST_TICK_IRQ		ipipe_apic_vector_irq(LOCAL_TIMER_VECTOR)
#define RTHAL_BCAST_TICK_IRQ		0

static inline void rthal_grab_control(void)
{
	rthal_smi_init();
	rthal_smi_disable();
}

static inline void rthal_release_control(void)
{
	rthal_smi_restore();
}

static inline unsigned long long rthal_rdtsc(void)
{
	unsigned long long t;
	rthal_read_tsc(t);
	return t;
}

static inline void rthal_timer_program_shot(unsigned long delay)
{
/* With head-optimization, callers are expected to have switched off
   hard-IRQs already -- no need for additional protection in this
   case. */
#ifndef CONFIG_XENO_OPT_PIPELINE_HEAD
	unsigned long flags;

	rthal_local_irq_save_hw(flags);
#endif /* CONFIG_XENO_OPT_PIPELINE_HEAD */
	if (likely(delay))
		apic_write(APIC_TMICT,delay);
	else
		/* Kick the timer interrupt immediately. */
		rthal_trigger_irq(RTHAL_APIC_TIMER_IPI);
#ifndef CONFIG_XENO_OPT_PIPELINE_HEAD
	rthal_local_irq_restore_hw(flags);
#endif /* CONFIG_XENO_OPT_PIPELINE_HEAD */
}

static const char *const rthal_fault_labels[] = {
    [0] = "Divide error",
    [1] = "Debug",
    [2] = "",   /* NMI is not pipelined. */
    [3] = "Int3",
    [4] = "Overflow",
    [5] = "Bounds",
    [6] = "Invalid opcode",
    [7] = "FPU not available",
    [8] = "Double fault",
    [9] = "FPU segment overrun",
    [10] = "Invalid TSS",
    [11] = "Segment not present",
    [12] = "Stack segment",
    [13] = "General protection",
    [14] = "Page fault",
    [15] = "Spurious interrupt",
    [16] = "FPU error",
    [17] = "Alignment check",
    [18] = "Machine check",
    [19] = "SIMD error",
    [20] = NULL,
};

#ifdef CONFIG_X86_LOCAL_APIC

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,26)
#include <asm/mach_apic.h>
#else
#include <asm/apic.h>
#include <mach_ipi.h>
#endif

static inline void rthal_setup_periodic_apic(int count, int vector)
{
	apic_write(APIC_LVTT, APIC_LVT_TIMER_PERIODIC | vector);
	apic_write(APIC_TMICT, count);
}

static inline void rthal_setup_oneshot_apic(int vector)
{
	apic_write(APIC_LVTT, vector);
}

#endif /* !CONFIG_X86_LOCAL_APIC */

#endif /* !__cplusplus */

long rthal_strncpy_from_user(char *dst,
			     const char __user *src,
			     long count);

#endif /* !_XENO_ASM_X86_HAL_64_H */
