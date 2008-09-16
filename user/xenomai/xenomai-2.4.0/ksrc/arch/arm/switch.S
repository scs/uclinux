/*
 * Copyright (C) 2005 Stelian Pop.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 * USA; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <linux/linkage.h>
#include <linux/version.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>

/*
 * Switch context routine.
 *
 * Registers according to the ARM procedure call standard:
 *   Reg    Description
 *   r0-r3  argument/scratch registers
 *   r4-r9  variable register
 *   r10=sl stack limit/variable register
 *   r11=fp frame pointer/variable register
 *   r12=ip intra-procedure-call scratch register
 *   r13=sp stack pointer (auto preserved)
 *   r14=lr link register
 *   r15=pc program counter (auto preserved)
 *
 * rthal_thread_switch(struct thread_info *out, struct thread_info *in)
 */

    .text

/*
 * Copied from __switch_to, arch/arm/kernel/entry-armv.S.
 * Right now it is identical, but who knows what the
 * future reserves us...
 *
 * XXX: All the following config options are NOT tested:
 *      CONFIG_CPU_MPCORE
 *      CONFIG_CPU_XSCALE
 *      CONFIG_IWMMXT
 *      CONFIG_HAS_TLS_REG
 *      CONFIG_VFP
 *
 *  Calling args: 
 * r0 = previous task_struct, r1 = previous thread_info, r2 = next thread_info
 */
ENTRY(rthal_thread_switch)
    add     ip, r1, #TI_CPU_SAVE
    ldr     r3, [r2, #TI_TP_VALUE]
    stmia   ip!, {r4 - sl, fp, sp, lr}      @ Store most regs on stack
#ifdef CONFIG_MMU
    ldr     r6, [r2, #TI_CPU_DOMAIN]
#endif
#if __LINUX_ARM_ARCH__ >= 6
#ifdef CONFIG_CPU_MPCORE
    clrex
#else
    strex   r5, r4, [ip]                    @ Clear exclusive monitor
#endif
#endif
#if defined(CONFIG_CPU_XSCALE) && !defined(CONFIG_IWMMXT)
    mra     r4, r5, acc0
    stmia   ip, {r4, r5}
#endif
#if defined(CONFIG_HAS_TLS_REG)
    mcr     p15, 0, r3, c13, c0, 3          @ set TLS register
#elif !defined(CONFIG_TLS_REG_EMUL)
    mov     r4, #0xffff0fff
    str     r3, [r4, #-15]                  @ TLS val at 0xffff0ff0
#endif
#ifdef CONFIG_MMU
    mcr     p15, 0, r6, c3, c0, 0           @ Set domain register
#endif
#ifdef CONFIG_VFP
    @ Always disable VFP so we can lazily save/restore the old
    @ state. This occurs in the context of the previous thread.
    VFPFMRX r4, FPEXC
    bic     r4, r4, #FPEXC_ENABLE
    VFPFMXR FPEXC, r4
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 18) &&  defined(CONFIG_IWMMXT)
    bl      iwmmxt_task_switch
#endif
#if defined(CONFIG_CPU_XSCALE) && !defined(CONFIG_IWMMXT)
    add     r4, r2, #40                     @ cpu_context_save->extra
    ldmib   r4, {r4, r5}
    mar     acc0, r4, r5
#endif
    add	    r4, r2, #TI_CPU_SAVE
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 18) && defined(CONFIG_IWMMXT)
    mov	    r5, r0
    mov     r0, r2
    bl	    iwmmxt_task_switch
    mov	    r0, r5
#endif	
    ldmia   r4, {r4 - sl, fp, sp, pc}       @ Load all regs saved previously

/*
 * r4 = xnarch_thread_trampoline
 * r5 = xnarchtcb_t *
 */
ENTRY(rthal_thread_trampoline)
    mov     r0, r5
    mov     pc, r4

// vim: ts=4 et sw=4 sts=4
