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

#include <asm/hw_irq.h>
#include <linux/autoconf.h>
#include <asm/entry.h>

/* Global references*/
.global bfin_irq_panic	 /* go to panic in ints.c */
.global evt_emulation
.global evt_nmi
.global evt_evt2
.global evt_ivhw
.global evt_timer
.global evt_evt7
.global evt_evt8
.global evt_evt9
.global evt_evt10
.global evt_evt11
.global evt_evt12
.global evt_evt13
.global evt_system_call
.global evt_soft_int1
	 
	 
/*****************************************************************************/
/* Data areas */
.bss
/*
 *      Set up the usable of RAM stuff. Size of RAM is determined then
 *      an initial stack set up at the end.
 */
.align 4

.data
	 
.text
.align 4 	/* just in case */
/*
 * initial interrupt handlers
 */
#ifndef CONFIG_KGDB	
 	 /* interrupt routine for emulation - 0 */
	 /* Currently used only if GDB stub is not in - invalid	  */
	 /* gdb-stub set the evt itself */
	 /* save registers for post-mortem only */
evt_emulation:
	 SAVE_CONTEXT
	 r0 = IRQ_EMU;
	 r1 = sp;
	 SP += -12;	
	 call	bfin_irq_panic;	
	 SP += 12;	
	 /* - GDB stub fills this in by itself (if defined) */
	  rte; 
#endif

/* interrupt routine for nmi - 2 */
evt_nmi:
	 SAVE_CONTEXT
	r0 = IRQ_NMI;
	r1 = sp;	     /* get return address (but not going back)  */
	 SP += -12;	
	call bfin_irq_panic; 
	 SP += 12;	
	 rtn; 
			
irq_panic:
	 r0 = IRQ_EVX;
	 r1 =  sp;
	 SP += -12;	
	 call	bfin_irq_panic; 
	 SP += 12;	
	 /* panic doesn't return, so no restoration of context. */
	 
/* interrupt routine for ivhw - 5 */
evt_ivhw:
	 SAVE_CONTEXT
	 r0 = IRQ_HWERR; 
	 r1 = sp;
	 SP += -12;	
	 call	bfin_irq_panic; 
	 SP += 12;	
	 rti; 

/* interrupt routine for core timer - 6 */	 
evt_timer:
	SAVE_CONTEXT
	r0 = IRQ_CORETMR;  
	r1 = sp;	
	 SP += -12;	
	call process_int;  /* call do_timer; */ 
	 SP += 12;	
	RESTORE_CONTEXT
	rti; 

/* interrupt routine for evt2 - 2 */	 
evt_evt2:
	 SAVE_CONTEXT
	 r0 = 2;
	 r1 =  sp;
	 SP += -12;	
	 call	process_int; 
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 

/* interrupt routine for evt7 - 7 */	 
evt_evt7:
	 SAVE_CONTEXT
	 r0 = 7;
	 r1 =  sp;
	 SP += -12;	
	 call	process_int; 
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 

/* interrupt routine for evt8 - 8 */
evt_evt8:
	 SAVE_CONTEXT
	 r0 = 8;
	 r1 =  sp;
	 SP += -12;	
	 call	process_int; 
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 

/* interrupt routine for evt9 - 9 */	 
evt_evt9:
	 SAVE_CONTEXT
	 r0 = 9;
	 r1 =  sp;
	 SP += -12;	
	 call	process_int; 
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 

/* interrupt routine for evt10	- 10 */	 
evt_evt10:
	 SAVE_CONTEXT
	 r0 = 10;
	 r1 =  sp;
	 SP += -12;	
	 call	process_int; 
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 

/* interrupt routine for evt11	- 11 */	 
evt_evt11:
	 SAVE_CONTEXT
	 r0 = 11;
	 r1 =  sp;
	 SP += -12;	
	 call	process_int; 
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 

/* interrupt routine for evt12	- 12 */	 
evt_evt12:
	 SAVE_CONTEXT
	 r0 = 12;
	 r1 =  sp;
	 SP += -12;	
	 call	process_int; 
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 

 /* interrupt routine for evt13	- 13 */
evt_evt13:
	 SAVE_CONTEXT
	 r0 = 13;
	 r1 =  sp;
	 SP += -12;	
	 call	process_int;  
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 

 /* interrupt routine for system_call - 14 */	 
evt_system_call:
	SAVE_CONTEXT
	call system_call;
	RESTORE_CONTEXT
	rti;

evt_soft_int1:
	 SAVE_CONTEXT
	 r0 = IRQ_SW_INT1;	/*Software Interrupt 1 */
	 r1 =  sp;
	 SP += -12;	
	 call	process_int; 
	 SP += 12;	
	 RESTORE_CONTEXT
	 rti; 
