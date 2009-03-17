/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum.
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

#include <asm/processor.h>
#include <asm/cputable.h>
#include <asm/ppc_asm.h>

#ifdef CONFIG_PPC601_SYNC_FIX
#define SYNC				\
BEGIN_FTR_SECTION			\
	sync;				\
	isync;				\
END_FTR_SECTION_IFSET(CPU_FTR_601)
#else /* !CONFIG_PPC601_SYNC_FIX */
#define	SYNC
#endif /* CONFIG_PPC601_SYNC_FIX */

#ifndef MTMSRD
#if defined(CONFIG_PPC64) || defined(CONFIG_PPC64BRIDGE)
#define MTMSRD(r)	.long	(0x7c000164 + ((r) << 21))	/* mtmsrd */
#else
#define MTMSRD(r)	mtmsr	r
#endif /* CONFIG_PPC64 || CONFIG_PPC64BRIDGE */
#endif

#define RTHAL_FPSAVE(n, base)	stfd n,8*(n)(base)
#define RTHAL_FPSAVE2(n, base)	RTHAL_FPSAVE(n, base); RTHAL_FPSAVE(n+1, base)
#define RTHAL_FPSAVE4(n, base)	RTHAL_FPSAVE2(n, base); RTHAL_FPSAVE2(n+2, base)
#define RTHAL_FPSAVE8(n, base)	RTHAL_FPSAVE4(n, base); RTHAL_FPSAVE4(n+4, base)
#define RTHAL_FPSAVE16(n, base)	RTHAL_FPSAVE8(n, base); RTHAL_FPSAVE8(n+8, base)
#define RTHAL_FPSAVE32(n, base)	RTHAL_FPSAVE16(n, base); RTHAL_FPSAVE16(n+16, base)

/* r3 = &tcb->fpuenv */
_GLOBAL(rthal_save_fpu)
	mfmsr	r5
	ori	r5,r5,MSR_FP		/* Re-enable use of FPU. */
#ifdef CONFIG_PPC64BRIDGE
	clrldi	r5,r5,1			/* Turn off 64-bit mode. */
#endif /* CONFIG_PPC64BRIDGE */
	SYNC
	MTMSRD(r5)			/* Enable use of fpu. */
	isync
	RTHAL_FPSAVE32(0,r3)
	mffs	fr0
	stfd	fr0,8*32(r3)
	blr

#define RTHAL_FPLOAD(n, base)	lfd n,8*(n)(base)
#define RTHAL_FPLOAD2(n, base)	RTHAL_FPLOAD(n, base); RTHAL_FPLOAD(n+1, base)
#define RTHAL_FPLOAD4(n, base)	RTHAL_FPLOAD2(n, base); RTHAL_FPLOAD2(n+2, base)
#define RTHAL_FPLOAD8(n, base)	RTHAL_FPLOAD4(n, base); RTHAL_FPLOAD4(n+4, base)
#define RTHAL_FPLOAD16(n, base)	RTHAL_FPLOAD8(n, base); RTHAL_FPLOAD8(n+8, base)
#define RTHAL_FPLOAD32(n, base)	RTHAL_FPLOAD16(n, base); RTHAL_FPLOAD16(n+16, base)

/* r3 = &tcb->fpuenv */
_GLOBAL(rthal_init_fpu)
	mfmsr	r5
	ori	r5,r5,MSR_FP|MSR_FE1	/* RT kernel threads always operate in */
	li	r4,MSR_FE0		/* imprecise non-recoverable exception mode. */
	andc	r5,r5,r4
	SYNC
	MTMSRD(r5)

	/* Fallback wanted. */
	
/* r3 = &tcb->fpuenv */
_GLOBAL(rthal_restore_fpu)
	mfmsr	r5
	ori	r5,r5,MSR_FP		/* Re-enable use of FPU. */
#ifdef CONFIG_PPC64BRIDGE
	clrldi	r5,r5,1			/* Turn off 64-bit mode. */
#endif /* CONFIG_PPC64BRIDGE */
	SYNC
	MTMSRD(r5)			/* Enable use of fpu. */
	isync
	lfd	fr0,8*32(r3)
	mtfsf	0xff,0
	RTHAL_FPLOAD32(0,r3)
	blr
