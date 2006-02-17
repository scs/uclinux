 /*
 * File:        arch/blackfin/mach-common/interrupt.S
 * Based on:
 * Author:      D. Jeff Dionne <jeff@ryeham.ee.ryerson.ca>
 *              Kenneth Albanowski <kjahds@kjahds.com>
 *              COPYRIGHT 2005 Analog Devices
 * Created:     ?
 * Description: Interrupt Entries
 *
 * Rev:
 *
 * Modified:    LG Soft India
 *
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#define ASSEMBLY

#include <asm/blackfin.h>
#include <asm/mach/irq.h>
#include <linux/autoconf.h>
#include <linux/linkage.h>
#include <asm/entry.h>
#include <asm/asm-offsets.h>

.text
.align 4 	/* just in case */

/*
 * initial interrupt handlers
 */

#ifndef CONFIG_KGDB
 	/* interrupt routine for emulation - 0 */
	/* Currently used only if GDB stub is not in - invalid */
	/* gdb-stub set the evt itself */
	/* save registers for post-mortem only */
ENTRY(_evt_emulation)
	SAVE_ALL_SYS
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	r0 = IRQ_EMU;
	r1 = sp;
	SP += -12;
	call _irq_panic;
	SP += 12;
	/* - GDB stub fills this in by itself (if defined) */
	rte;
#endif

/* interrupt routine for ivhw - 5 */
ENTRY(_evt_ivhw)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	p0.l = lo(TBUFCTL);
	p0.h = hi(TBUFCTL);
	r0 = 1;
	[p0] = r0;
	r0 = IRQ_HWERR;
	r1 = sp;

#ifdef CONFIG_PROFILING
	r7 = SEQSTAT;
	r7 = r7 >>> 0xe;
	r6 = 0x1F;
	r7 = r7 & r6;
	r5 = 0x12;
	cc = r7 == r5;
	if cc jump call_do_ovf; /*deal with performance counter overflow*/
#endif

	SP += -12;
	call _irq_panic;
	SP += 12;
	rti;
#ifdef CONFIG_PROFILING
call_do_ovf:

	SP += -12;
	call _pm_overflow;
	SP += 12;

        RESTORE_CONTEXT

	rti;
#endif
/* interrupt routine for core timer - 6 */
ENTRY(_evt_timer)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	/* SAVE_CONTEXT ignores IPEND; we need to save it since the user_mode
	   macro accesses it to determine where to account time.  */
	p2.l = lo(IPEND);
	p2.h = hi(IPEND);
	csync;
	r0 = [p2];
	[sp + PT_IPEND] = r0;

 	r0 = EVT_IVTMR_P;
	r1 =  sp;
	SP += -12;
	call _do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt2 - 2.  This is NMI.  */
ENTRY(_evt_evt2)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	r0 = IRQ_NMI;
	r1 =  sp;
	SP += -12;
	call _asm_do_IRQ;
	SP += 12;
	RESTORE_CONTEXT
	rtn;

/* interrupt routine for evt7 - 7 */
ENTRY(_evt_evt7)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
 	r0 = EVT_IVG7_P;
	r1 =  sp;
	SP += -12;
	call _do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt8 - 8 */
ENTRY(_evt_evt8)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	r0 = EVT_IVG8_P;
	r1 =  sp;
	SP += -12;
	call _do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt9 - 9 */
ENTRY(_evt_evt9)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	r0 = EVT_IVG9_P;
	r1 =  sp;
	SP += -12;
	call _do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt10	- 10 */
ENTRY(_evt_evt10)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	r0 = EVT_IVG10_P;
	r1 =  sp;
	SP += -12;
	call _do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt11	- 11 */
ENTRY(_evt_evt11)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	r0 = EVT_IVG11_P;
	r1 =  sp;
	SP += -12;
	call _do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt12	- 12 */
ENTRY(_evt_evt12)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	r0 = EVT_IVG12_P;
	r1 =  sp;
	SP += -12;
	call _do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

 /* interrupt routine for evt13	- 13 */
ENTRY(_evt_evt13)
	SAVE_CONTEXT
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	r0 = EVT_IVG13_P;
	r1 =  sp;
	SP += -12;
	call _do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

 /* interrupt routine for system_call - 15 */
ENTRY(_evt_system_call)
	SAVE_CONTEXT_SYSCALL
#ifdef CONFIG_FRAME_POINTER
	fp = 0;
#endif
	call system_call;
	RESTORE_CONTEXT
	rti;
