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
#include <asm/board/mem_init.h>

.global _rambase
.global _ramstart
.global _ramend
.global _stext
.global _start

.text 

_start:
_stext:
	/* Set the SYSCFG register */	
	R0 = 0x36; 		/*Enable Cycle Counter and Nesting Of Interrupts(3rd Bit)*/
	SYSCFG = r0;
	R0 = 0;

/*Clear Out All the data and pointer  Registers*/	
	R1 = R0;
	R2 = R0;
	R3 = R0;
	R4 = R0;
	R5 = R0;
	R6 = R0;
	R7 = R0;

	P0 = R0;
	P1 = R0;
	P2 = R0;
	P3 = R0;
	P4 = R0;
	P5 = R0;

	LC0 = r0;
	LC1 = r0;
	L0 = r0;
	L1 = r0;
	L2 = r0;
	L3 = r0;

/*Clear Out All the DAG Registers*/	
	B0 = r0;
	B1 = r0;
	B2 = r0;
	B3 = r0;

	I0 = r0;
	I1 = r0;
	I2 = r0;
	I3 = r0;

	M0 = r0;
	M1 = r0;
	M2 = r0;
	M3 = r0;

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

	p0.h = (UART_LCR >> 16);
	p0.l = (UART_LCR & 0xFFFF);
	r0 = 0x0(Z);	
	w[p0] = r0.L;	/* To enable DLL writes */
	ssync;

	p0.h = (UART_DLL >> 16);
	p0.l = (UART_DLL & 0xFFFF);
	r0 = 0x0(Z);
	w[p0] = r0.L;
	ssync;

	p0.h = (UART_DLH >> 16);
	p0.l = (UART_DLH & 0xFFFF);
	r0 = 0x00(Z);
	w[p0] = r0.L;
	ssync;
	
	p0.h = (UART_GCTL>>16);
	p0.l = (UART_GCTL & 0xFFFF);
	r0 = 0x0(Z);
	w[p0] = r0.L;	/* To enable UART clock */
	ssync;

/**************************************PLL Setup ************************************/
	/*
         *  Set PLL_CTL
         *   - [14:09] = MSEL[5:0] : CLKIN / VCO multiplication factors
         *   - [8]     = BYPASS    : BYPASS the PLL, run CLKIN into CCLK/SCLK
         *   - [7]     = output delay (add 200ps of delay to mem signals)
         *   - [6]     = input delay (add 200ps of input delay to mem signals)
         *   - [5]     = PDWN      : 1=All Clocks off
         *   - [3]     = STOPCK    : 1=Core Clock off
         *   - [1]     = PLL_OFF   : 1=Disable Power to PLL
         *   - [0]     = DF        : 1=Pass CLKIN/2 to PLL / 0=Pass CLKIN to PLL
         *   all other bits set to zero
         */
	
	p0.h = hi(PLL_LOCKCNT);
	p0.l = lo(PLL_LOCKCNT);
	r0 = 0x300(Z);
	w[p0] = r0.l;
	ssync;

	SSYNC;
        P2.H = hi(EBIU_SDGCTL);
        P2.L = lo(EBIU_SDGCTL);
        R0 = [P2];
        BITSET (R0, 24);
        [P2] = R0;
        SSYNC;

        r0 = CONFIG_VCO_MULT;           /* Load the VCO multiplier         */
        r0 = r0 << 9;                   /* Shift it over,                  */
        r1 = CLKIN_HALF;        /* Do we need to divide CLKIN by 2?*/
        r0 = r1 | r0;
        r1 = PLL_BYPASS;         /* Bypass the PLL?                 */
        r1 = r1 << 8;                   /* Shift it over                   */
        r0 = r1 | r0;                   /* add them all together           */

        p0.h = (PLL_CTL >> 16);
        p0.l = (PLL_CTL & 0xFFFF);      /* Load the address                */
        cli r2;                         /* Disable interrupts              */
	ssync;
        w[p0] = r0.l;                     /* Set the value                   */
        idle;                           /* Wait for the PLL to stablize    */
        sti r2;                         /* Enable interrupts               */

check_again:
	p0.h = hi(PLL_STAT);
	p0.l = lo(PLL_STAT);
	R0 = W[P0](Z);
	CC = BITTST(R0,5);
	if ! CC jump check_again;

	/* Configure SCLK & CCLK Dividers */
       	r2 = (CONFIG_CCLK_ACT_DIV | CONFIG_SCLK_DIV);
        p0.h = (PLL_DIV >> 16);
        p0.l = (PLL_DIV & 0xFFFF);
        w[p0] = r2.l;
        ssync;

	p0.l = (EBIU_SDRRC & 0xFFFF);
        p0.h = (EBIU_SDRRC >> 16);
        r0 = mem_SDRRC;
        w[p0] = r0.l;
        ssync;

	P2.H = hi(EBIU_SDGCTL);
        P2.L = lo(EBIU_SDGCTL);
        R0 = [P2];
        BITCLR (R0, 24);
        [P2] = R0;
        SSYNC;

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
