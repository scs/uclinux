/*
 * Most of the following code has been lifted from the original _switch()
 * routine from linux/arch/ppc/kernel/entry.S, and adapted to perform hybrid
 * scheduling between kernel and user-space Xenomai threads.
 *
 * Xenomai updates Copyright (C) 2004 Philippe Gerum.
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

#include <linux/version.h>
#include <asm/processor.h>
#include <asm/page.h>
#include <asm/ppc_asm.h>
#include <asm/cputable.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,14)
#include <asm/offsets.h>
#else
#include <asm/asm-offsets.h>
#endif

/*
 * struct task_struct *rthal_thread_switch(struct thread_struct *prev, struct thread_struct *next)
 */
	.align	7
_GLOBAL(rthal_thread_switch)
	stwu	r1,-INT_FRAME_SIZE(r1)
	mflr	r0
	stw	r0,INT_FRAME_SIZE+4(r1)
	SAVE_NVGPRS(r1)
	stw	r0,_NIP(r1)	/* Return to switch caller */
	mfmsr	r11
	li	r0,MSR_FP	/* Disable floating-point */
#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	oris	r0,r0,MSR_VEC@h	/* Disable altivec */
	mfspr	r12,SPRN_VRSAVE	/* save vrsave register value */
	stw	r12,THREAD_VRSAVE(r3)
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */
#ifdef CONFIG_SPE
	oris	r0,r0,MSR_SPE@h	 /* Disable SPE */
	mfspr	r12,SPRN_SPEFSCR /* save spefscr register value */
	stw	r12,THREAD_SPEFSCR(r3)
#endif /* CONFIG_SPE */
	and.	r0,r0,r11	/* FP or altivec or SPE enabled? */
	beq+	1f
	andc	r11,r11,r0
	MTMSRD(r11)
	isync
1:	stw	r11,_MSR(r1)
	mfcr	r10
	stw	r10,_CCR(r1)
	stw	r1,KSP(r3)	/* Save old stack pointer */

#ifdef CONFIG_SMP
	sync
#endif /* CONFIG_SMP */

	lwz	r1,KSP(r4)	/* Load new stack pointer */

	mr	r3,r2
	lwz	r0,PGDIR(r4)
        cmpwi   r0, 0
        beq-	same_current

	tophys(r0,r4)
	CLR_TOP32(r0)
	mtspr	SPRN_SPRG3,r0	/* Update current THREAD phys addr */
	addi	r2,r4,-THREAD	/* Update current */

same_current:
		
#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	lwz	r0,THREAD_VRSAVE(r4)
	mtspr	SPRN_VRSAVE,r0		/* if G4, restore VRSAVE reg */
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */
#ifdef CONFIG_SPE
	lwz	r0,THREAD_SPEFSCR(r4)
	mtspr	SPRN_SPEFSCR,r0		/* restore SPEFSCR reg */
#endif /* CONFIG_SPE */

	lwz	r0,_CCR(r1)
	mtcrf	0xFF,r0
	REST_NVGPRS(r1)

	lwz	r4,_NIP(r1)
	mtlr	r4
	addi	r1,r1,INT_FRAME_SIZE
	blr

#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) */

#include "ppc_defs.h"

/*
 * void rthal_thread_switch(struct thread_struct *prev, struct thread_struct *next)
 */
	.align	7
_GLOBAL(rthal_thread_switch)
	stwu	r1,-INT_FRAME_SIZE(r1)
	stw	r0,GPR0(r1)
	lwz	r0,0(r1)
	stw	r0,GPR1(r1)
	SAVE_GPR(2, r1)
	SAVE_8GPRS(14, r1)
	SAVE_10GPRS(22, r1)
	mflr	r20		/* Return to switch caller */
	stw	r20,INT_FRAME_SIZE+4(r1)
	mfmsr	r22
	li	r0,MSR_FP	/* Disable floating-point */
#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	oris	r0,r0,MSR_VEC@h	/* Disable altivec */
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */
#ifdef CONFIG_SPE
	oris    r0,r0,MSR_SPE@h /* Disable SPE */
#endif /* CONFIG_SPE */
	and.	r0,r0,r22	/* FP or altivec enabled? */
	beq+	1f
	andc	r22,r22,r0
	mtmsr	r22
	isync
1:	stw	r20,_NIP(r1)
	stw	r22,_MSR(r1)
	stw	r20,_LINK(r1)
	mfcr	r20
	mfctr	r22
	mfspr	r23,XER
	stw	r20,_CCR(r1)
	stw	r22,_CTR(r1)
	stw	r23,_XER(r1)
	li	r0,0x0ff0
	stw	r0,TRAP(r1)
	stw	r1,KSP(r3)	/* Save old stack pointer */

	lwz	r1,KSP(r4)	/* Load new stack pointer */
		
	mr	r3,r2
	lwz	r0,PGDIR(r4)
        cmpwi   r0, 0
        beq-	same_current

	tophys(r0,r4)
	CLR_TOP32(r0)
	mtspr	SPRG3,r0	/* Update current THREAD phys addr */
	addi	r2,r4,-THREAD	/* Update current */

same_current:
	
	lwz	r0,_CCR(r1)
	mtcrf	0xFF,r0
	REST_2GPRS(14, r1)
	REST_8GPRS(16, r1)
	REST_8GPRS(24, r1)

	lwz	r4,_NIP(r1)
	mtlr	r4
	addi	r1,r1,INT_FRAME_SIZE
	blr

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) */

_GLOBAL(rthal_thread_trampoline)
	mtmsr	r14
	mtlr	r15
	mr	r3,r16
	blr
