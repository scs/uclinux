/* arch/bfinnommu/mach-bf533/head.S
 *
 * Startup code for Blackfin BF533 
 *
 * Copyright (C) 1998  D. Jeff Dionne <jeff@uclinux.org>
 * Copyright (C) 2004 LG Soft India 
 *
 */

#include <linux/config.h>
#include <asm/blackfin.h>

.global _rambase
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
	r0 = 0;
	LC0 = r0;
	LC1 = r0;
	L0 = r0;
	L1 = r0;
	L2 = r0;
	L3 = r0;
	
	R0 = SYSCFG;		/* Enable the Cycle counter */
	BITSET(R0,1);
	SYSCFG = R0;

	/* Set the port preferences of DAG0 and DAG1 to be
	 different. this gives better performance when
	 performing daul-dag operations on SDRAM.*/
	
	P0.L = DMEM_CONTROL & 0xFFFF;
	P0.H = DMEM_CONTROL >> 16;
	R0 = [P0];
	BITCLR(R0, 12);
	BITSET(R0, 13);
	[P0] = R0;
	CSYNC;

#ifdef CONFIG_BLKFIN_STAMP 

	cli r2;
	p0.h = (PLL_CTL >> 16);
	p0.l = (PLL_CTL & 0xFFFF);
	/*r0 = CCLK_550;*/	/* 550 MHz CCLK and 110 MHz SCLK*/
	r0 = 0x4800 ;
	w[p0] = r0;
	idle;
	sti r2;
	ssync;

/********************/

	p0.h = (PLL_DIV >> 16);
	p0.l = (PLL_DIV & 0xFFFF);
	r0 = 0x5 ;
	w[p0] = r0;
	ssync;

/**********************/

	p1.l = DELAY_STMP;
	p1.h = 0x0;
	lsetup ( del_start,del_start ) lc0 = p1;

del_start:
	nop;
del_end:
	p0.h = (UART_GCTL>>16);
	p0.l = (UART_GCTL & 0xFFFF);
	r0 = UCEN;
	w[p0] = r0;	/* To enable UART clock */
	ssync;

	p0.h = (UART_LCR >> 16);
	p0.l = (UART_LCR & 0xFFFF);
	r0 = DLAB;	
	w[p0] = r0;	/* To enable DLL writes */
	ssync;

	p0.h = (UART_DLL >> 16);
	p0.l = (UART_DLL & 0xFFFF);
	r0 = 0x6b;	/* sys clock with 99MHz */
	w[p0] = r0;
	ssync;

	p0.h = (UART_DLH >> 16);
	p0.l = (UART_DLH & 0xFFFF);
	r0 = 0x00;
	w[p0] = r0;
	ssync;

	p0.h = (UART_LCR >> 16);
	p0.l = (UART_LCR & 0xFFFF);	/* To enable writes to THR */
	r0 = WLS(8);	
	w[p0] = r0;
	ssync;
#endif
		
#ifdef CONFIG_EZKIT
	cli r2;
	p0.h = (PLL_CTL >> 16); 
	p0.l = (PLL_CTL & 0xFFFF);
	r0 = CCLK_594; /* 27 * 22 = 594MHZ core clock, sclk = 118.8MHz */
	w[p0] = r0;
	idle;
	sti r2;
	ssync;

	p1.l = DELAY_EZ;
	p1.h = 0x0;
	lsetup ( del_start,del_start ) lc0 = p1;

del_start:
	nop;
del_end:


#endif
	/* Code for initializing Async memory banks */

        p2.h = (EBIU_AMBCTL1 >> 16);
        p2.l = (EBIU_AMBCTL1 & 0xFFFF);
        r0.h = (AMBCTL1VAL >> 16); 
        r0.l = (AMBCTL1VAL & 0xffff); 
        [p2] = r0;
        ssync;

        p2.h = (EBIU_AMBCTL0 >> 16);
        p2.l = (EBIU_AMBCTL0 & 0xFFFF);
        r0.h = (AMBCTL0VAL >> 16); 
        r0.l = (AMBCTL0VAL & 0xffff);
        [p2] = r0;
        ssync;

        p2.h = (EBIU_AMGCTL >> 16);
        p2.l = (EBIU_AMGCTL & 0xffff);
        r0 = AMGCTLVAL; 
        w[p2] = r0;
        ssync;


	/* This section keeps the processor in supervisor mode
         * during kernel boot.  Switches to user mode at end of boot.
	 * See page 3-9 of Hardware Reference manual for documentation.
	 */

	/* EVT15 = _real_start */

	p0.l = (EVT15 & 0xFFFF);
	p0.h = (EVT15 >> 16);
	p1.l = _real_start;
	p1.h = _real_start;
	[p0] = p1;
	csync;

	p0.l = (IMASK & 0xFFFF);
	p0.h = (IMASK >> 16);
	p1.l = IMASK_IVG15;
	p1.h = 0x0;
	[p0] = p1;
	csync;

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
	p0.l = (WDOG_CTL & 0xFFFF);
	p0.h = (WDOG_CTL >> 16);
	r0 = 0xAD6(z);
	w[p0] = r0;	/* watchdog off for now */
	ssync;

	/* Code update for BSS size == 0
	 * Zero out the bss region.
	 */

	p1.l = _sbss;
	p1.h = _sbss;
	p2.l = _ebss;
	p2.h = _ebss;
	r0 = 0;
	p2 -= p1; 
	lsetup (_clear_bss, _clear_bss ) lc0 = p2;
_clear_bss:
	B[p1++] = r0;

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
	r0.l = (RAM_END & 0xFFFF);
	r0.h = (RAM_END >> 16);
	p1.l = _ramend;
	p1.h = _ramend; 
	[p1] = r0;

	/*
	 *  load the current thread pointer and stack
	 */
	r1.l = init_thread_union;	
	r1.h = init_thread_union;

/* Use kernel stack instead of an l1 stack. l1 stack might overflow.
 * For this time being this should be sufficient.
 */
	r2.l = 0x2000; 
	r2.h = 0x0000; 
	r1 = r1 + r2;
	sp = r1; 
	usp = sp;
	fp = sp;
	call	start_kernel;
_exit:
	jump.s	_exit;
	
.data

/*
 *      Set up the usable of RAM stuff. Size of RAM is determined then
 *      an initial stack set up at the end.
 */

.align 4
_rambase:
.long   0
_ramstart:
.long   0
_ramend:
.long   0
