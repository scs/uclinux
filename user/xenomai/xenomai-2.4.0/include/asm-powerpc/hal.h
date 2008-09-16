/**
 *   @ingroup hal
 *   @file
 *
 *   Real-Time Hardware Abstraction Layer for PowerPC.
 *
 *   Copyright &copy; 2002-2004 Philippe Gerum.
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
 *   along with Xenomai; if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 *   02111-1307, USA.
 */

#ifndef _XENO_ASM_POWERPC_HAL_H
#define _XENO_ASM_POWERPC_HAL_H

#include <asm-generic/xenomai/hal.h>	/* Read the generic bits. */

#define RTHAL_TIMER_DEVICE	"decrementer"
#define RTHAL_CLOCK_DEVICE	"timebase"

typedef unsigned long long rthal_time_t;

static inline __attribute_const__ unsigned long ffnz(unsigned long ul)
{
#ifdef CONFIG_PPC64
    __asm__ ("cntlzd %0, %1" : "=r" (ul) : "r" (ul & (-ul)));
    return 63 - ul;
#else
    __asm__ ("cntlzw %0, %1":"=r"(ul):"r"(ul & (-ul)));
    return 31 - ul;
#endif
}

#ifndef __cplusplus
#include <linux/irq.h>
#include <asm/system.h>
#include <asm/time.h>
#include <asm/timex.h>
#include <asm/xenomai/atomic.h>
#include <asm/processor.h>

#define RTHAL_TIMER_IRQ		IPIPE_TIMER_VIRQ
#ifdef CONFIG_SMP
#define RTHAL_TIMER_IPI		IPIPE_SERVICE_IPI3
#define RTHAL_HOST_TIMER_IPI	IPIPE_SERVICE_IPI4
#endif /* CONFIG_SMP */

#define rthal_grab_control()     do { } while(0)
#define rthal_release_control()  do { } while(0)

static inline unsigned long long rthal_rdtsc(void)
{
	unsigned long long t;
	rthal_read_tsc(t);
	return t;
}

static inline void rthal_timer_program_shot(unsigned long delay)
{
	if (!delay)
		rthal_trigger_irq(RTHAL_TIMER_IRQ);
	else
#ifdef CONFIG_40x
		mtspr(SPRN_PIT, delay);
#else /* !CONFIG_40x */
	        set_dec((int)delay);	/* decrementer is only 32-bits */
#endif /* CONFIG_40x */
}

    /* Private interface -- Internal use only */

#define RTHAL_SWITCH_FRAME_SIZE  (STACK_FRAME_OVERHEAD + sizeof(struct pt_regs))

#ifdef CONFIG_PPC64
asmlinkage struct task_struct *rthal_thread_switch(struct thread_struct *prev_t,
						   struct thread_struct *next_t,
						   int kthreadp);
#else /* !CONFIG_PPC64 */
asmlinkage struct task_struct *rthal_thread_switch(struct thread_struct *prev,
						   struct thread_struct *next);
#endif /* CONFIG_PPC64 */

asmlinkage void rthal_thread_trampoline(void);

#ifdef CONFIG_XENO_HW_FPU

typedef struct rthal_fpenv {

	/* This layout must follow exactely the definition of the FPU
	   backup area in a PPC thread struct available from
	   <asm-ppc/processor.h>. Specifically, fpr[] an fpscr words must
	   be contiguous in memory (see arch/powerpc/hal/fpu.S). */

	double fpr[32];
#ifndef CONFIG_PPC64
	unsigned long fpscr_pad;	/* <= Hi-word of the FPR used to */
#endif
	unsigned long fpscr;	/* retrieve the FPSCR. */

} rthal_fpenv_t;

void rthal_init_fpu(rthal_fpenv_t * fpuenv);

void rthal_save_fpu(rthal_fpenv_t * fpuenv);

void rthal_restore_fpu(rthal_fpenv_t * fpuenv);

#ifndef CONFIG_SMP
#define rthal_get_fpu_owner(cur) last_task_used_math
#else /* CONFIG_SMP */
#define rthal_get_fpu_owner(cur) ({                             \
    struct task_struct * _cur = (cur);                          \
    ((_cur->thread.regs && (_cur->thread.regs->msr & MSR_FP))   \
     ? _cur : NULL);                                            \
})
#endif /* CONFIG_SMP */

#ifdef CONFIG_PPC64
#define rthal_disable_fpu() ({                          \
    register unsigned long _msr;                        \
    __asm__ __volatile__ ( "mfmsr %0" : "=r"(_msr) );   \
    __asm__ __volatile__ ( "mtmsrd %0"                  \
                           : /* no output */            \
                           : "r"(_msr & ~(MSR_FP))      \
                           : "memory" );                \
})

#define rthal_enable_fpu() ({                           \
    register unsigned long _msr;                        \
    __asm__ __volatile__ ( "mfmsr %0" : "=r"(_msr) );   \
    __asm__ __volatile__ ( "mtmsrd %0"                  \
                           : /* no output */            \
                           : "r"(_msr | MSR_FP)         \
                           : "memory" );                \
})
#else /* !CONFIG_PPC64 */
#define rthal_disable_fpu() ({                          \
    register unsigned long _msr;                        \
    __asm__ __volatile__ ( "mfmsr %0" : "=r"(_msr) );   \
    __asm__ __volatile__ ( "mtmsr %0"                   \
                           : /* no output */            \
                           : "r"(_msr & ~(MSR_FP))      \
                           : "memory" );                \
})

#define rthal_enable_fpu() ({                           \
    register unsigned long _msr;                        \
    __asm__ __volatile__ ( "mfmsr %0" : "=r"(_msr) );   \
    __asm__ __volatile__ ( "mtmsr %0"                   \
                           : /* no output */            \
                           : "r"(_msr | MSR_FP)         \
                           : "memory" );                \
})
#endif /* CONFIG_PPC64 */

#endif /* CONFIG_XENO_HW_FPU */

static const char *const rthal_fault_labels[] = {
#ifdef CONFIG_PPC64
	[0] = "Data or instruction access",
	[1] = "Alignment",
	[2] = "AltiVec unavailable",
	[3] = "Program check exception",
	[4] = "Machine check exception",
	[5] = "Unknown",
	[6] = "Instruction breakpoint",
	[7] = "",
	[8] = "Single-step exception",
	[9] = "Non-recoverable exception",
	[10] = "",
	[11] = "",
	[12] = "",
	[13] = "AltiVec assist",
	[14] = "",
	[15] = "Kernel FP unavailable",
	[16] = NULL
#else /* !CONFIG_PPC64 */
	[0] = "Data or instruction access",
	[1] = "Alignment",
	[2] = "Altivec unavailable",
	[3] = "Program check exception",
	[4] = "Machine check exception",
	[5] = "Unknown",
	[6] = "Instruction breakpoint",
	[7] = "Run mode exception",
	[8] = "Single-step exception",
	[9] = "Non-recoverable exception",
	[10] = "Software emulation",
	[11] = "Debug",
	[12] = "SPE",
	[13] = "Altivec assist",
	[14] = "Cache-locking exception",
	[15] = "Kernel FP unavailable",
	[16] = NULL
#endif /* CONFIG_PPC64 */
};

#endif /* !__cplusplus */

#endif /* !_XENO_ASM_POWERPC_HAL_H */
