/*
 * File:         arch/blackfin/kernel/traps.c
 * Based on:
 * Author:       Hamish Macdonald
 *
 * Created:
 * Description:  uses S/W interrupt 15 for the system calls
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2005 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http:    //blackfin.uclinux.org/
 *
 * This program is free software ;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation ;  either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY ;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program ;  see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/blackfin.h>
#include <linux/interrupt.h>

/*
 *  . EXCEPTION TRAPS DEBUGGING LEVELS
 *  .
 *  0 for normal operation without any error messages
 *  1 for serious error messages
 *  2 for errors but handled somwhere else
 * >2 for various levels of hopefully increasingly useless information
 */

#define TRAPS_DEBUG 1		/* Must be defined here or in in Makefile */

#if (TRAPS_DEBUG > 2 )
#define DPRINTK3(args...) printk(args)
#else
#define DPRINTK3(args...)
#endif

#if TRAPS_DEBUG > 1
#define DPRINTK2(args...) printk(args)
#else
#define DPRINTK2(args...)
#endif

#ifdef TRAPS_DEBUG
#define DPRINTK(args...) printk(args)
#else
#define DPRINTK(args...)
#endif

/* assembler routines */
asmlinkage void evt_system_call(void);
asmlinkage void evt_soft_int1(void);
asmlinkage void trap(void);

extern void dump(struct pt_regs *fp, void *);
extern void _cplb_hdr(void);

/* Initiate the event table handler */
void __init trap_init(void)
{
	__builtin_bfin_csync();
	*pEVT3 = trap;
	__builtin_bfin_csync();
}

asmlinkage void trap_c(struct pt_regs *fp);

int kstack_depth_to_print = 48;

#ifdef CONFIG_KALLSYMS
#include <linux/kallsyms.h>
int printk_address(unsigned long address)
{
	unsigned long offset = 0, symsize;
	const char *symname;
	char *modname;
	char *delim = ":";
	char namebuf[128];

	symname =
	    kallsyms_lookup(address, &symsize, &offset, &modname, namebuf);
	if (!symname) {
		if (current->mm) {
			if ( (address > current->mm->start_code) && 
				(address < current->mm->end_code)) {
				 return printk("<%08lx>{%s+0x%x}",
					address,
					current->comm,
					(int)(address - current->mm->start_code));
			}
		}
		return printk("[<%08lx>]", address);
	}
	if (!modname)
		modname = delim = "";
	return printk("<%08lx>{%s%s%s%s%+ld}",
		      address, delim, modname, delim, symname, offset);
}
#else
int printk_address(unsigned long address)
{
	return printk("[<%08lx>]", address);
}
#endif

/* Used by the assembly entry point to work around an anomaly.  */
void *last_cplb_fault_retx;

asmlinkage void trap_c(struct pt_regs *fp)
{
	int j, sig = 0;
	siginfo_t info;

	j = *pTBUFCTL;
	*pTBUFCTL = j & 0x1D;

	/* trap_c() will be called for exceptions. During exceptions
	   processing, the pc value should be set with retx value.
	   With this change we can cleanup some code in signal.c- TODO */
	fp->orig_pc = fp->retx;

	/* send the appropriate signal to the user program */
	switch (fp->seqstat & 0x3f) {
	case VEC_STEP:
		info.si_code = TRAP_STEP;
		sig = SIGTRAP;
		break;
	case VEC_EXCPT01:	/* gdb breakpoint */
		info.si_code = TRAP_ILLTRAP;
		sig = SIGTRAP;
		break;
	case VEC_EXCPT03:	/* Atomic test and set service */
		info.si_code = SEGV_STACKFLOW;
		sig = SIGSEGV;
		DPRINTK(EXC_0x03);
		break;
	case VEC_EXCPT04:	/* Atomic test and set service */
		panic("Exception 4");
		goto nsig;
	case VEC_UNDEF_I:
		info.si_code = ILL_ILLOPC;
		sig = SIGILL;
		DPRINTK(EXC_0x21);
		break;
	case VEC_OVFLOW:
		info.si_code = TRAP_TRACEFLOW;
		sig = SIGTRAP;
		DPRINTK(EXC_0x11);
		break;
	case VEC_ILGAL_I:
		info.si_code = ILL_ILLPARAOP;
		sig = SIGILL;
		DPRINTK(EXC_0x22);
		break;
	case VEC_ILL_RES:
		info.si_code = ILL_PRVOPC;
		sig = SIGILL;
		DPRINTK(EXC_0x2E);
		break;
	case VEC_MISALI_D:
		info.si_code = BUS_ADRALN;
		sig = SIGBUS;
		DPRINTK(EXC_0x24);
		DPRINTK("DCPLB_FAULT_ADDR=%p\n", *pDCPLB_FAULT_ADDR);
		break;
	case VEC_MISALI_I:
		info.si_code = BUS_ADRALN;
		sig = SIGBUS;
		DPRINTK(EXC_0x2A);
		DPRINTK("ICPLB_FAULT_ADDR=%p\n", *pICPLB_FAULT_ADDR);
		break;
	case VEC_UNCOV:
		info.si_code = ILL_ILLEXCPT;
		sig = SIGILL;
		DPRINTK(EXC_0x25);
		break;
	case VEC_WATCH:
		info.si_code = TRAP_WATCHPT;
		sig = SIGTRAP;
		DPRINTK3(EXC_0x28);
		break;
	case VEC_ISTRU_VL:	/* ADSP-BF535 only (MH) */
		info.si_code = BUS_OPFETCH;
		sig = SIGBUS;
		break;
	case VEC_CPLB_I_VL:
		DPRINTK2(EXC_0x2B);
		DPRINTK2("ICPLB_FAULT_ADDR: %p\n", *pICPLB_FAULT_ADDR);
	case VEC_CPLB_VL:
		info.si_code = ILL_CPLB_VI;
		DPRINTK3(EXC_0x23);
		DPRINTK3("DCPLB_FAULT_ADDR=%p\n", *pDCPLB_FAULT_ADDR);
		_cplb_hdr();
		goto nsig;
		sig = SIGILL;
		break;
	case VEC_CPLB_I_M:
		DPRINTK3(EXC_0x2C);
		DPRINTK3("ICPLB_FAULT_ADDR=%p\n", *pICPLB_FAULT_ADDR);
	case VEC_CPLB_M:
		info.si_code = IlL_CPLB_MISS;
		DPRINTK3(EXC_0x26);
		DPRINTK3("DCPLB_FAULT_ADDR=%p\n", *pDCPLB_FAULT_ADDR);
		/*Call the handler to replace the CPLB */
		_cplb_hdr();
		goto nsig;
	case VEC_CPLB_I_MHIT:
		info.si_code = ILL_CPLB_MULHIT;
		sig = SIGILL;
		DPRINTK3(EXC_0x2D);
		DPRINTK3("ICPLB_FAULT_ADDR=%p\n", *pICPLB_FAULT_ADDR);
		break;
	case VEC_CPLB_MHIT:
		info.si_code = ILL_CPLB_MULHIT;
		sig = SIGILL;
		DPRINTK3(EXC_0x27);
		DPRINTK3("DCPLB_FAULT_ADDR=%p\n", *pDCPLB_FAULT_ADDR);
		break;
	default:
		info.si_code = TRAP_ILLTRAP;
		sig = SIGTRAP;
		break;
	}
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_addr = (void *)fp->pc;
	force_sig_info(sig, &info, current);
	if (sig != 0 && sig != SIGTRAP) {
		dump(fp, (void *)fp->retx);
		dump_stack();

	}
      nsig:
	*pTBUFCTL = j;
	return;
}

/* Typical exception handling routines	*/
void show_stack(struct task_struct *task, unsigned long *esp)
{
	unsigned long *stack, *endstack, addr;
	extern char _start, _etext;
	int i;

	if (esp == NULL)
		esp = (unsigned long *)&esp;

	stack = esp;
	addr = (unsigned long)esp;
	endstack = (unsigned long *)PAGE_ALIGN(addr);

	printk(KERN_EMERG "Stack from %08lx:", (unsigned long)stack);
	for (i = 0; i < kstack_depth_to_print; i++) {
		if (stack + 1 > endstack)
			break;
		if (i % 8 == 0)
			printk(KERN_EMERG "\n       ");
		printk(KERN_EMERG " %08lx", *stack++);
	}

	printk(KERN_EMERG "\nCall Trace:");
	i = 0;
	while (stack + 1 <= endstack) {
		addr = *stack++;
		/*
		 * If the address is either in the text segment of the
		 * kernel, or in the region which contains vmalloc'ed
		 * memory, it *may* be the address of a calling
		 * routine; if so, print it so that someone tracing
		 * down the cause of the crash will be able to figure
		 * out the call path that was taken.
		 */
		if (addr >= (unsigned long)&_start
		    && addr <= (unsigned long)&_etext) {
			if (i % 4 == 0)
				printk(KERN_EMERG "\n       ");
			printk(KERN_EMERG " [<%08lx>]", addr);
			i++;
		}
	}
	printk(KERN_EMERG "\n");
}

void dump_stack(void)
{
	unsigned long stack;
	show_stack(current, &stack);
}

void dump(struct pt_regs *fp, void *retaddr)
{
	int i;

	printk("\nCURRENT PROCESS:\n\n");
	printk("COMM=%s PID=%d\n", current->comm, current->pid);
	if (current->mm) {
		printk("TEXT=%08x-%08x DATA=%08x-%08x BSS=%08x-%08x\n",
		       (int)current->mm->start_code,
		       (int)current->mm->end_code,
		       (int)current->mm->start_data,
		       (int)current->mm->end_data,
		       (int)current->mm->end_data, (int)current->mm->brk);
		printk("USER-STACK=%08x\n\n", (int)current->mm->start_stack);
	}
	printk("return address: %08lx; contents of [PC-16...PC+8[:\n", (long)retaddr);
	for (i = -16; i < 8; i++) {
		unsigned short x;
		get_user(x, (unsigned short *)retaddr + i);
		if (i == -8)
			printk("\n");
		if (i == 0)
			printk("X\n");
		printk("%04x ", x);
	}
	printk("\n\n");

	printk("RETE:  %08lx  RETN: %08lx  RETX: %08lx  RETS: %08lx\n",
	       fp->rete, fp->retn, fp->retx, fp->rets);
	printk("IPEND: %04lx  SYSCFG: %04lx\n", fp->ipend, fp->syscfg);
	printk("SEQSTAT: %08lx    SP: %08lx\n", (long)fp->seqstat, (long)fp);
	printk("R0: %08lx    R1: %08lx    R2: %08lx    R3: %08lx\n",
	       fp->r0, fp->r1, fp->r2, fp->r3);
	printk("R4: %08lx    R5: %08lx    R6: %08lx    R7: %08lx\n",
	       fp->r4, fp->r5, fp->r6, fp->r7);
	printk("P0: %08lx    P1: %08lx    P2: %08lx    P3: %08lx\n",
	       fp->p0, fp->p1, fp->p2, fp->p3);
	printk("P4: %08lx    P5: %08lx    FP: %08lx\n", fp->p4, fp->p5, fp->fp);
	printk("A0.w: %08lx    A0.x: %08lx    A1.w: %08lx    A1.x: %08lx\n",
	       fp->a0w, fp->a0x, fp->a1w, fp->a1x);

	printk("LB0: %08lx  LT0: %08lx  LC0: %08lx\n", fp->lb0, fp->lt0,
	       fp->lc0);
	printk("LB1: %08lx  LT1: %08lx  LC1: %08lx\n", fp->lb1, fp->lt1,
	       fp->lc1);
	printk("B0: %08lx  L0: %08lx  M0: %08lx  I0: %08lx\n", fp->b0, fp->l0,
	       fp->m0, fp->i0);
	printk("B1: %08lx  L1: %08lx  M1: %08lx  I1: %08lx\n", fp->b1, fp->l1,
	       fp->m1, fp->i1);
	printk("B2: %08lx  L2: %08lx  M2: %08lx  I2: %08lx\n", fp->b2, fp->l2,
	       fp->m2, fp->i2);
	printk("B3: %08lx  L3: %08lx  M3: %08lx  I3: %08lx\n", fp->b3, fp->l3,
	       fp->m3, fp->i3);

	printk("\nUSP: %08lx   ASTAT: %08lx\n", rdusp(), fp->astat);

	printk("\n\n");
	if (*pTBUFSTAT) {
		printk(KERN_EMERG "Hardware Trace:\n");
		for (i = 0; i <= *pTBUFSTAT; i++) {
			printk(KERN_EMERG "%2i Target : ", i);
			printk_address((unsigned long)*pTBUF);
			printk(KERN_EMERG "\n   Source : ");
			printk_address((unsigned long)*pTBUF);
			printk(KERN_EMERG "\n");
		}
	}
}

asmlinkage int sys_bfin_spinlock(int *spinlock)
{
	int ret = 0;
	local_irq_disable();
	if (*spinlock)
		ret = 1;
	*spinlock = 1;
	local_irq_enable();
	return ret;
}
