/* linux/arch/bfinnommu/mach-bf533/interrupt.S 
 *	 H/W interrupts
 *	 - assumes default interrupt configuration for the interrupts
 * 
 * Copyright (C) 2004  LG Soft India
 * Copyright (C) 2002  Arcturus Networks Ltd. Ted Ma <mated@sympatico.ca>
 * Copyright (C) 1998  D. Jeff Dionne <jeff@ryeham.ee.ryerson.ca>,
 *                     Kenneth Albanowski <kjahds@kjahds.com>,
 *                     The Silver Hammer Group, Ltd.
 *
 * (c) 1995, Dionne & Associates
 * (c) 1995, DKG Display Tech.
 *
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
ENTRY(evt_emulation)
	SAVE_ALL_SYS
	r0 = IRQ_EMU;
	r1 = sp;
	SP += -12;
	call irq_panic;
	SP += 12;
	/* - GDB stub fills this in by itself (if defined) */
	rte;
#endif

/* interrupt routine for nmi - 2.  */
ENTRY(evt_nmi)
	SAVE_ALL_SYS
	r0 = IRQ_NMI;
	r1 = sp;	    /* get return address (but not going back)  */
	SP += -12;
	call irq_panic;
	SP += 12;
	rtn;

/* interrupt routine for ivhw - 5 */
ENTRY(evt_ivhw)
	SAVE_CONTEXT
	r0 = IRQ_HWERR;
	r1 = sp;
	SP += -12;
	call irq_panic;
	SP += 12;
	rti;

/* interrupt routine for core timer - 6 */
ENTRY(evt_timer)
	SAVE_CONTEXT
 	r0 = EVT_IVTMR_P;
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt2 - 2.  This is NMI.  */
ENTRY(evt_evt2)
	SAVE_CONTEXT
	r0 = IRQ_NMI;
	r1 =  sp;
	SP += -12;
	call asm_do_IRQ;
	SP += 12;
	RESTORE_CONTEXT
	rtn;

/* interrupt routine for evt7 - 7 */
ENTRY(evt_evt7)
	SAVE_CONTEXT
 	r0 = EVT_IVG7_P;
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt8 - 8 */
ENTRY(evt_evt8)
	SAVE_CONTEXT
	r0 = EVT_IVG8_P;
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt9 - 9 */
ENTRY(evt_evt9)
	SAVE_CONTEXT
	r0 = EVT_IVG9_P;
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt10	- 10 */
ENTRY(evt_evt10)
	SAVE_CONTEXT
	r0 = EVT_IVG10_P;
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt11	- 11 */
ENTRY(evt_evt11)
	SAVE_CONTEXT
	r0 = EVT_IVG11_P;
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

/* interrupt routine for evt12	- 12 */
ENTRY(evt_evt12)
	SAVE_CONTEXT
	r0 = EVT_IVG12_P;
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

 /* interrupt routine for evt13	- 13 */
ENTRY(evt_evt13)
	SAVE_CONTEXT
	r0 = EVT_IVG13_P;
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	call return_from_int;
	RESTORE_CONTEXT
	rti;

 /* interrupt routine for system_call - 15 */
ENTRY(evt_system_call)
	SAVE_CONTEXT_SYSCALL
	call system_call;
	RESTORE_CONTEXT
	rti;

ENTRY(evt_soft_int1)
	SAVE_CONTEXT
	r0 = IRQ_SW_INT1;	/*Software Interrupt 1 */
	r1 =  sp;
	SP += -12;
	call do_irq;
	SP += 12;
	RESTORE_CONTEXT
	rti;
