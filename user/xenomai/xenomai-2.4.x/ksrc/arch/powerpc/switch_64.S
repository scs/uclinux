/*
 * Most of the following code has been lifted from the original _switch()
 * routine from linux/arch/powerpc/kernel/entry_64.S, and adapted to
 * perform hybrid scheduling between kernel and user-space Xenomai
 * threads.
 *
 * Xenomai updates Copyright (C) 2004 Philippe Gerum.
 *
 * 64-bit PowerPC adoption
 *   copyright (C) 2005 Taneli Vähäkangas and Heikki Lindholm 
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
#include <asm/thread_info.h>
#include <asm/cputable.h>
#include <asm/ppc_asm.h>
#include <asm/asm-offsets.h>
#include <asm/page.h>
#include <asm/mmu.h>

/*
 * void rthal_thread_switch(struct thread_struct *prev, struct thread_struct *next, int kthreadp)
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	.align	7
_GLOBAL(rthal_thread_switch)
	mflr	r0
	std	r0,16(r1)
	stdu	r1,-SWITCH_FRAME_SIZE(r1)
	SAVE_8GPRS(14, r1)
	SAVE_10GPRS(22, r1)
	mflr	r20		/* Return to switch caller */
	mfmsr	r22
	li	r0, MSR_FP
#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	oris	r0,r0,MSR_VEC@h	/* Disable altivec */
	mfspr	r24,SPRN_VRSAVE	/* save vrsave register value */
	std	r24,THREAD_VRSAVE(r3)
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */
	and.	r0,r0,r22
	beq+	1f
	andc	r22,r22,r0
	mtmsrd	r22
	isync
1:	std	r20,_NIP(r1)
	mfcr	r23
	std	r23,_CCR(r1)
	std	r1,KSP(r3)	/* Set old stack pointer */

#ifdef CONFIG_SMP
	sync
#endif /* CONFIG_SMP */

	ld	r8,KSP(r4)	/* new stack pointer */
	ld	r3,PACACURRENT(r13) /* we must return "prev" when paired to switch_to() */

	cmpwi	cr5,r5,0	/* is it a kernel thread */
        bne-	cr5,10f		/* if so, don't touch 'current' */

	addi	r6,r4,-THREAD	/* Convert THREAD to 'current' */
	std	r6,PACACURRENT(r13)	/* Set new 'current' */
10:
BEGIN_FTR_SECTION
	clrrdi	r6,r8,28	/* get its ESID */
	clrrdi	r9,r1,28	/* get current sp ESID */
	clrldi.	r0,r6,2		/* is new ESID c00000000? */
	cmpd	cr1,r6,r9	/* or is new ESID the same as current ESID? */
	cror	eq,4*cr1+eq,eq
	beq	2f		/* if yes, don't slbie it */

	/* Bolt in the new stack SLB entry */
	ld	r7,KSP_VSID(r4)	/* Get new stack's VSID */
	oris	r0,r6,(SLB_ESID_V)@h
	ori	r0,r0,(SLB_NUM_BOLTED-1)@l
	slbie	r6
	slbie	r6		/* Workaround POWER5 < DD2.1 issue */
	slbmte	r7,r0
	isync

2:
END_FTR_SECTION_IFSET(CPU_FTR_SLB)
	bne-	cr5,11f		/* kernel thread: don't touch 'current' */
	clrrdi	r7,r8,THREAD_SHIFT	/* base of new stack */
	/* Note: this uses SWITCH_FRAME_SIZE rather than INT_FRAME_SIZE
	   because we don't need to leave the 288-byte ABI gap at the
	   top of the kernel stack. */
	addi	r7,r7,THREAD_SIZE-SWITCH_FRAME_SIZE
	std	r7,PACAKSAVE(r13)
	
11:
	mr	r1,r8		/* start using new stack pointer */
		
	ld	r6,_CCR(r1)
	mtcrf	0xFF,r6

#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	ld	r0,THREAD_VRSAVE(r4)
	mtspr	SPRN_VRSAVE,r0		/* if G4, restore VRSAVE reg */
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */

	REST_8GPRS(14, r1)
	REST_10GPRS(22, r1)

	ld	r7,_NIP(r1)
	mtlr	r7
	addi	r1,r1,SWITCH_FRAME_SIZE
	blr

#else /* Linux >= 2.6.24 */

	.align	7
_GLOBAL(rthal_thread_switch)
	mflr	r0
	std	r0,16(r1)
	stdu	r1,-SWITCH_FRAME_SIZE(r1)
	/* r3-r13 are caller saved -- Cort */
	SAVE_8GPRS(14, r1)
	SAVE_10GPRS(22, r1)
	mflr	r20		/* Return to switch caller */
	mfmsr	r22
	li	r0, MSR_FP
#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	oris	r0,r0,MSR_VEC@h	/* Disable altivec */
	mfspr	r24,SPRN_VRSAVE	/* save vrsave register value */
	std	r24,THREAD_VRSAVE(r3)
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */
	and.	r0,r0,r22
	beq+	1f
	andc	r22,r22,r0
	mtmsrd	r22
	isync
1:	std	r20,_NIP(r1)
	mfcr	r23
	std	r23,_CCR(r1)
	std	r1,KSP(r3)	/* Set old stack pointer */

#ifdef CONFIG_SMP
	/* We need a sync somewhere here to make sure that if the
	 * previous task gets rescheduled on another CPU, it sees all
	 * stores it has performed on this one.
	 */
	sync
#endif /* CONFIG_SMP */

	ld	r8,KSP(r4)	/* new stack pointer */
	ld	r3,PACACURRENT(r13) /* we must return "prev" when paired to switch_to() */

	cmpwi	cr5,r5,0	/* is it a kernel thread */
        bne-	cr5,10f		/* if so, don't touch 'current' */

	addi	r6,r4,-THREAD	/* Convert THREAD to 'current' */
	std	r6,PACACURRENT(r13)	/* Set new 'current' */

10:
BEGIN_FTR_SECTION
	b	2f
END_FTR_SECTION_IFCLR(CPU_FTR_SLB)
BEGIN_FTR_SECTION
	clrrdi	r6,r8,28	/* get its ESID */
	clrrdi	r9,r1,28	/* get current sp ESID */
END_FTR_SECTION_IFCLR(CPU_FTR_1T_SEGMENT)
BEGIN_FTR_SECTION
	clrrdi	r6,r8,40	/* get its 1T ESID */
	clrrdi	r9,r1,40	/* get current sp 1T ESID */
END_FTR_SECTION_IFSET(CPU_FTR_1T_SEGMENT)
	clrldi.	r0,r6,2		/* is new ESID c00000000? */
	cmpd	cr1,r6,r9	/* or is new ESID the same as current ESID? */
	cror	eq,4*cr1+eq,eq
	beq	2f		/* if yes, don't slbie it */

	/* Bolt in the new stack SLB entry */
	ld	r7,KSP_VSID(r4)	/* Get new stack's VSID */
	oris	r0,r6,(SLB_ESID_V)@h
	ori	r0,r0,(SLB_NUM_BOLTED-1)@l
BEGIN_FTR_SECTION
	li	r9,MMU_SEGSIZE_1T	/* insert B field */
	oris	r6,r6,(MMU_SEGSIZE_1T << SLBIE_SSIZE_SHIFT)@h
	rldimi	r7,r9,SLB_VSID_SSIZE_SHIFT,0
END_FTR_SECTION_IFSET(CPU_FTR_1T_SEGMENT)

	/* Update the last bolted SLB.  No write barriers are needed
	 * here, provided we only update the current CPU's SLB shadow
	 * buffer.
	 */
	ld	r9,PACA_SLBSHADOWPTR(r13)
	li	r12,0
	std	r12,SLBSHADOW_STACKESID(r9) /* Clear ESID */
	std	r7,SLBSHADOW_STACKVSID(r9)  /* Save VSID */
	std	r0,SLBSHADOW_STACKESID(r9)  /* Save ESID */

	/* No need to check for CPU_FTR_NO_SLBIE_B here, since when
	 * we have 1TB segments, the only CPUs known to have the errata
	 * only support less than 1TB of system memory and we'll never
	 * actually hit this code path.
	 */

	slbie	r6
	slbie	r6		/* Workaround POWER5 < DD2.1 issue */
	slbmte	r7,r0
#ifdef CONFIG_PPC_PASEMI_A2_WORKAROUNDS
	mfmsr	r7		/* PA6T Ax workaround */
	mtmsrd	r7
#endif
	isync

2:
	bne-	cr5,11f		/* kernel thread: don't touch 'current' */

	clrrdi	r7,r8,THREAD_SHIFT	/* base of new stack */
	/* Note: this uses SWITCH_FRAME_SIZE rather than INT_FRAME_SIZE
	   because we don't need to leave the 288-byte ABI gap at the
	   top of the kernel stack. */
	addi	r7,r7,THREAD_SIZE-SWITCH_FRAME_SIZE

	std	r7,PACAKSAVE(r13)

11:
	mr	r1,r8		/* start using new stack pointer */
	ld	r6,_CCR(r1)
	mtcrf	0xFF,r6

#ifdef CONFIG_ALTIVEC
BEGIN_FTR_SECTION
	ld	r0,THREAD_VRSAVE(r4)
	mtspr	SPRN_VRSAVE,r0		/* if G4, restore VRSAVE reg */
END_FTR_SECTION_IFSET(CPU_FTR_ALTIVEC)
#endif /* CONFIG_ALTIVEC */

	/* r3-r13 are destroyed -- Cort */
	REST_8GPRS(14, r1)
	REST_10GPRS(22, r1)

	ld	r7,_NIP(r1)	/* Return to _switch caller in new task */
	mtlr	r7
	addi	r1,r1,SWITCH_FRAME_SIZE
	blr
	
#endif	

_GLOBAL(rthal_thread_trampoline)
	mtmsr	r14
	mtlr	r15
	mr	r2,r16
	mr	r3,r17
	blr
