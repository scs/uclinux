/* arch/bfinnommu/mach-bf533/head.S
 *
 * Startup code for Blackfin BF533 
 *
 * Copyright 2001 (C) SED Systems, a Division of Calian Ltd.
 * Based on: arch/m68knommu/platform/68328/pilot/crt0_rom.S
 * Based on: arch/m68knommu/platform/68360/uCquicc/crt0_rom.S, 2.0.38.1.pre7
 *           uClinux Kernel
 * Copyright (C) Michael Leslie <mleslie@lineo.com>
 * Based on: arch/m68knommu/platform/68EZ328/ucsimm/crt0_rom.S
 * Copyright (C) 1998  D. Jeff Dionne <jeff@uclinux.org>,
 * 
 * Copyright (C) 2004 LG Soft India 
 * Based on: arch/bfinnommu/platform/535/ADI/crt0_ram.S
 *
 */

#include <linux/config.h>
#include <asm/board/bf533.h>
#include <asm/board/bf533_serial.h>

.global _rambase
.global _ramvec
.global _ramstart
.global _ramend
.global _stext
.global __bss_start

.global start
.global _start

.text 

_start:
start:
_stext:
	/* Set the SYSCFG register */	
	r0 = 0x30;
	SYSCFG = r0;

#ifdef CONFIG_BLKFIN_STAMP 

	cli r2;
	p0.h = (PLLCTL_ADDR >> 16);
	p0.l = (PLLCTL_ADDR & 0xFFFF);
	/*r0 = CCLK_550;*/	/* 550 MHz CCLK and 110 MHz SCLK*/
	r0 = 0x4800 ;
	w[p0] = r0;
	idle;
	sti r2;
	ssync;

/********************/

	p0.h = (PLLDIV_ADDR >> 16);
	p0.l = (PLLDIV_ADDR & 0xFFFF);
	r0 = 0x5 ;
	w[p0] = r0;

/************************/

	p1.l = DELAY_STMP;
	p1.h = 0x0;
	lsetup ( del_start,del_end ) lc0 = p1;

del_start:
	nop;
del_end:
	p0.h = (UART_GCTL_ADDR>>16);
	p0.l = (UART_GCTL_ADDR & 0xFFFF);
	r0 = UART_GCTL_UCEN;
	w[p0] = r0;	/* To enable UART clock */
	ssync;

	p0.h = (UART_LCR_ADDR >> 16);
	p0.l = (UART_LCR_ADDR & 0xFFFF);
	r0 = UART_LCR_DLAB;	
	w[p0] = r0;	/* To enable DLL writes */
	ssync;

	p0.h = (UART_DLL_ADDR >> 16);
	p0.l = (UART_DLL_ADDR & 0xFFFF);
	r0 = 0x6b;	/* sys clock with 99MHz */
	w[p0] = r0;
	ssync;

	p0.h = (UART_DLH_ADDR >> 16);
	p0.l = (UART_DLH_ADDR & 0xFFFF);
	r0 = 0x00;
	w[p0] = r0;
	ssync;

	p0.h = (UART_LCR_ADDR >> 16);
	p0.l = (UART_LCR_ADDR & 0xFFFF);	/* To enable writes to THR */
	r0 = UART_LCR_WLS8;	
	w[p0] = r0;
	ssync;
#endif
		
#ifdef CONFIG_EZKIT
	cli r2;
	p0.h = (PLLCTL_ADDR >> 16); 
	p0.l = (PLLCTL_ADDR & 0xFFFF);
	r0 = CCLK_594; /* 27 * 22 = 594MHZ core clock, sclk = 118.8MHz */
	w[p0] = r0;
	idle;
	sti r2;
	ssync;

	p1.l = DELAY_EZ;
	p1.h = 0x0;
	lsetup ( del_start,del_end ) lc0 = p1;

del_start:
	nop;
del_end:


#endif
	/* Code for initializing Async memory banks */

        p2.h = (EBIU_AMBCTL1_ADDR >> 16);
        p2.l = (EBIU_AMBCTL1_ADDR & 0xFFFF);
        r0.h = (AMBCTL1VAL >> 16); 
        r0.l = (AMBCTL1VAL & 0xffff); 
        [p2] = r0;
        ssync;

        p2.h = (EBIU_AMBCTL0_ADDR >> 16);
        p2.l = (EBIU_AMBCTL0_ADDR & 0xFFFF);
        r0.h = (AMBCTL0VAL >> 16); 
        r0.l = (AMBCTL0VAL & 0xffff);
        [p2] = r0;
        ssync;

        p2.h = (EBIU_AMGCTL_ADDR >> 16);
        p2.l = (EBIU_AMGCTL_ADDR & 0xffff);
        r0 = AMGCTLVAL; 
        w[p2] = r0;
        ssync;


	/* This section keeps the processor in supervisor mode
         * during kernel boot.  Switches to user mode at end of boot.
	 * See page 3-9 of Hardware Reference manual for documentation.
	 */

	/* EVT15 = _real_start */

	p0.l = (EVT_IVG15_ADDR & 0xFFFF);
	p0.h = (EVT_IVG15_ADDR >> 16);
	p1.l = _real_start;
	p1.h = _real_start;
	[p0] = p1;

	p0.l = (IMASK_ADDR & 0xFFFF);
	p0.h = (IMASK_ADDR >> 16);
	p1.l = IMASK_IVG15;
	p1.h = 0x0;
	[p0] = p1;

	raise 15;
	p0.l = WAIT_HERE;
	p0.h = WAIT_HERE;
	reti = p0;
	rti;
	
WAIT_HERE:
	jump WAIT_HERE;


.global _real_start; 
_real_start:
	[ -- sp ] = reti;
	p0.l = (WDOGCTL_ADDR & 0xFFFF);
	p0.h = (WDOGCTL_ADDR >> 16);
	r0 = 0xD6(z);
	w[p0] = r0;	/* watchdog off for now */

/* copy data section to RAM */

/*
 *	p1.l = ramdisk_begin;
 *	p1.h = ramdisk_begin;
 *	p2.l = 0x0000;
 *	p2.h = 0x0060;
 *	r0.h = 0x0020;
 *	r0.l = 0xd000;	
*loop:	r1 = [p1];
 *	[p2] = r1;
 *	p3=0x4;
 *	p1=p1+p3;	
 *	p2=p2+p3;
 *	r2=0x4;	
 *	r0=r0-r2;
 *	cc=r0==0x0;
 *	if !cc jump loop;
 */

	/* Code update for BSS size == 0
	 * Zero out the bss region.
	 */

	p1.l = _sbss;
	p1.h = _sbss;
	p2.l = _ebss;
	p2.h = _ebss;
	lsetup (_clear_bss, _clear_bss_end ) lc1 = p2 - p1;
	CC = p2<=p1;
	if CC jump _clear_bss_skip;
	r0 = 0;
_clear_bss:
_clear_bss_end:
	[p1++] = r0;
_clear_bss_skip:	/* to skip bss clear */

	p1.l = _rambase;
	p1.h = _rambase;
	r0.l = _sdata ;
	r0.h = _sdata ;
	[p1] = r0;

	p1.l = _ramstart;
	p1.h = _ramstart;
	r0.l = _end;
	r0.h = _end;
	[p1] = r0;
#ifdef CONFIG_BLKFIN_STAMP
	r0.l = 0x0000;
	r0.h = 0x0100;
#endif
#ifdef CONFIG_EZKIT
	r0.l = 0x0000;
	r0.h = 0x0100;
#endif
	p1.l = _ramend;
	p1.h = _ramend; 
	[p1] = r0;

	/*
	 *  load the current task pointer and stack
	 */
	r1.l = init_thread_union;	
	r1.h = init_thread_union;
	p1.l = _current_task;
	p1.h = _current_task;
	[p1] = r1;

/* Use kernel stack instead of an l1 stack. l1 stack might overflow.
 * For this time being this should be sufficient.
 */
	r2.l = 0x2000; 
	r2.h = 0x0000; 
	r1 = r1 + r2;
	sp = r1; 
	call	start_kernel;
_exit:

	jump.s	_exit;

	
.data

/*
 *      Set up the usable of RAM stuff. Size of RAM is determined then
 *      an initial stack set up at the end.
 */

.align 4
_ramvec:
.long   0
_rambase:
.long   0
_ramstart:
.long   0
_ramend:
.long   0
env:
.long	0;
