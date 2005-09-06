/* arch/bfinnommu/mach-bf533/head.S
 *
 * Startup code for Blackfin BF533
 *
 * Copyright (C) 1998  D. Jeff Dionne <jeff@uclinux.org>
 * Copyright (C) 2004 LG Soft India
 *
 */
#include <linux/linkage.h>
#include <asm/blackfin.h>
#include <asm/mach/mem_init.h>

.global _rambase
.global _ramstart
.global _ramend
.extern _ebss
.extern bf53x_relocate_l1_mem

#define FILE_HEAD_START	0x00000404

.text

ENTRY(_start)
ENTRY(_stext)
/*  R0: argument of command line string, passed from uboot, save it */
	R7 = R0;
	/* Set the SYSCFG register */
	R0 = 0x36;
	SYSCFG = R0; 		/*Enable Cycle Counter and Nesting Of Interrupts(3rd Bit)*/
	R0 = 0;

/*Clear Out All the data and pointer  Registers*/
	R1 = R0;
	R2 = R0;
	R3 = R0;
	R4 = R0;
	R5 = R0;
	R6 = R0;

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

/*Initialise UART*/
	p0.h = hi(UART_LCR);
	p0.l = lo(UART_LCR);
	r0 = 0x0(Z);
	w[p0] = r0.L;	/* To enable DLL writes */
	ssync;

	p0.h = hi(UART_DLL);
	p0.l = lo(UART_DLL);
	r0 = 0x0(Z);
	w[p0] = r0.L;
	ssync;

	p0.h = hi(UART_DLH);
	p0.l = lo(UART_DLH);
	r0 = 0x00(Z);
	w[p0] = r0.L;
	ssync;
	
	p0.h = hi(UART_GCTL);
	p0.l = lo(UART_GCTL);
	r0 = 0x0(Z);
	w[p0] = r0.L;	/* To enable UART clock */
	ssync;

	/*Put The Code for PLL Programming and SDRAM Programming in L1 ISRAM*/
	call bf53x_relocate_l1_mem;
	call start_dma_code;

	/* Code for initializing Async memory banks */

        p2.h = hi(EBIU_AMBCTL1);
        p2.l = lo(EBIU_AMBCTL1);
        r0.h = hi(AMBCTL1VAL);
        r0.l = lo(AMBCTL1VAL);
        [p2] = r0;
        ssync;

        p2.h = hi(EBIU_AMBCTL0);
        p2.l = lo(EBIU_AMBCTL0);
        r0.h = hi(AMBCTL0VAL);
        r0.l = lo(AMBCTL0VAL);
        [p2] = r0;
        ssync;

        p2.h = hi(EBIU_AMGCTL);
        p2.l = lo(EBIU_AMGCTL);
        r0 = AMGCTLVAL;
        w[p2] = r0;
        ssync;

	/* This section keeps the processor in supervisor mode
         * during kernel boot.  Switches to user mode at end of boot.
	 * See page 3-9 of Hardware Reference manual for documentation.
	 */

	/* EVT15 = _real_start */

	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = _real_start;
	p1.h = _real_start;
	[p0] = p1;
	csync;

	p0.l = lo(IMASK);
	p0.h = hi(IMASK);
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

ENTRY(_real_start)
	[ -- sp ] = reti;
	p0.l = lo(WDOG_CTL);
	p0.h = hi(WDOG_CTL);
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

	/* In case there is a NULL pointer reference
	 * Zero out region before stext
	 */

	p1.l = 0x0;
	p1.h = 0x0;
	r0.l = _stext;
	r0.h = _stext;
	r0 = r0 >> 1;
	p2 = r0;
	r0 = 0;
	lsetup (_clear_zero, _clear_zero ) lc0 = p2;
_clear_zero:
	W[p1++] = r0;

/* pass the uboot arguments to the global value command line */
	R0 = R7;
	call cmdline_init;

	p1.l = _rambase;
	p1.h = _rambase;
	r0.l = _sdata ;
	r0.h = _sdata ;
	[p1] = r0;

	p1.l = _ramstart;
	p1.h = _ramstart;
	p3.l = _ebss;
	p3.h = _ebss;
#if defined(CONFIG_ROOTFS_TIED_TO_KERNEL)
	r0 = p3;
	r1.l = lo(FILE_HEAD_START);
	r1.h = hi(FILE_HEAD_START);
	r0 = r0 + r1;
	p2 = r0;
	r1 = [p2];
	r0 = 1024;
	r1 *= r0;
	r0.l = _end;
	r0.h = _end;
	r1 = r0 + r1;
	[p1] = r1;
#else
	r1 = p3;
	[p1] = r1;
#endif

	r0.l = lo(RAM_END);
	r0.h = hi(RAM_END);
	p1.l = _ramend;
	p1.h = _ramend;
	[p1] = r0;

	/*
	 *  load the current thread pointer and stack
	 */
	r1.l = init_thread_union;
	r1.h = init_thread_union;

	r2.l = 0x2000; 
	r2.h = 0x0000;
	r1 = r1 + r2;
	sp = r1;
	usp = sp;
	fp = sp;
	call start_kernel;
_exit:
	jump.s	_exit;
	
.section .text.l1
ENTRY(start_dma_code)
	p0.h = hi(SIC_IWR);
	p0.l = lo(SIC_IWR);
	r0.l = 0x1;
	[p0] = r0;
	SSYNC;
	
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

        P2.H = hi(EBIU_SDGCTL);
        P2.L = lo(EBIU_SDGCTL);
        R0 = [P2];
        BITSET (R0, 24);
        [P2] = R0;
        SSYNC;

        r0 = CONFIG_VCO_MULT & 63; /* Load the VCO multiplier         */
        r0 = r0 << 9;                   /* Shift it over,                  */
        r1 = CLKIN_HALF;        /* Do we need to divide CLKIN by 2?*/
        r0 = r1 | r0;
        r1 = PLL_BYPASS;         /* Bypass the PLL?                 */
        r1 = r1 << 8;                   /* Shift it over                   */
        r0 = r1 | r0;                   /* add them all together           */
	
        p0.h = hi(PLL_CTL);
        p0.l = lo(PLL_CTL);      /* Load the address                */
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
       	r0 = (CONFIG_CCLK_ACT_DIV | CONFIG_SCLK_DIV);
        p0.h = hi(PLL_DIV);
        p0.l = lo(PLL_DIV);
        w[p0] = r0.l;
        ssync;

	p0.l = lo(EBIU_SDRRC);
        p0.h = hi(EBIU_SDRRC);
        r0 = mem_SDRRC;
        w[p0] = r0.l;
        ssync;

        p0.l = (EBIU_SDBCTL & 0xFFFF);
        p0.h = (EBIU_SDBCTL >> 16);     /* SDRAM Memory Bank Control Register */
        r0 = mem_SDBCTL;
        w[p0] = r0.l;
        ssync;

	P2.H = hi(EBIU_SDGCTL);
        P2.L = lo(EBIU_SDGCTL);
        R0 = [P2];
        BITCLR (R0, 24);
	p0.h = hi(EBIU_SDSTAT);
	p0.l = lo(EBIU_SDSTAT);
	r2.l = w[p0];
	cc = bittst(r2,3);
	if !cc jump skip;
    NOP;
	BITSET (R0, 23);
skip:
	[P2] = R0;
        SSYNC;

        R0.L = lo(mem_SDGCTL);
        R0.H = hi(mem_SDGCTL);
	R1 = [p2];
	R1 = R1 | R0;
	[P2] = R1;
        SSYNC;

	RTS;

ENTRY(reset)
	/* No more interrupts to be handled*/
	CLI R6;
	SSYNC;

	/* Clear the bits 13-15 in SWRST if they werent cleared */
	p0.h = hi(SWRST);
	p0.l = lo(SWRST);
	csync;
	r0.l = w[p0];

	/* Clear the IMASK register */
	p0.h = hi(IMASK);
	p0.l = lo(IMASK);
	r0 = 0x0;
	[p0] = r0;

	/* Clear the ILAT register */
	p0.h = hi(ILAT);
	p0.l = lo(ILAT);
	r0 = [p0];
	[p0] = r0;
	SSYNC;
	
	/* Disable the WDOG TIMER */
	p0.h = hi(WDOG_CTL);
	p0.l = lo(WDOG_CTL);
	r0.l = 0xAD6;
	w[p0] = r0.l;
	SSYNC;
	
	/* Clear the sticky bit incase it is already set */	
	p0.h = hi(WDOG_CTL);
	p0.l = lo(WDOG_CTL);
	r0.l = 0x8AD6;
	w[p0] = r0.l;
	SSYNC;

	/* Program the count value */
	R0.l = 0x100;
	R0.h = 0x0;
	P0.h = hi(WDOG_CNT);
	P0.l = lo(WDOG_CNT);
	[P0] = R0;
	SSYNC;

	/* Program WDOG_STAT if necessary */
	P0.h = hi(WDOG_CTL);
	P0.l = lo(WDOG_CTL);
	R0 = W[P0](Z);
	CC = BITTST(R0,1);
	if !CC JUMP WRITESTAT;
	CC = BITTST(R0,2);
	if !CC JUMP WRITESTAT;
	JUMP SKIP_WRITE;

WRITESTAT:
	/* When watch dog timer is enabled, a write to STAT will load the contents of CNT to STAT */
	R0 = 0x0000(z);
	P0.h = hi(WDOG_STAT);
	P0.l = lo(WDOG_STAT)
	[P0] = R0;
	SSYNC;

SKIP_WRITE:
	/* Enable the reset event */
	P0.h = hi(WDOG_CTL);
        P0.l = lo(WDOG_CTL);
        R0 = W[P0](Z);
        BITCLR(R0,1);
        BITCLR(R0,2);
        W[P0] = R0.L;
        SSYNC;
        NOP;

	/* Enable the wdog counter */
        R0 = W[P0](Z);
        BITCLR(R0,4);
        W[P0] = R0.L;
        SSYNC;
	
	IDLE;

	RTS;

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
