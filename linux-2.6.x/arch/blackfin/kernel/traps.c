/*
 *  linux/arch/bfinnommu/kernel/traps.c
 *
 *  Copyright (C) 1993, 1994 by Hamish Macdonald
 *
 *  Copyright (c) 2002 Arcturus Networks Inc. (www.arcturusnetworks.com)
 *		-BlackFin/BFIN uses S/W interrupt 15 for the system calls
 *  Copyright (c) 2004 LG Soft India. 
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Sets up all exception vectors
 *
 */

#include <linux/config.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/a.out.h>
#include <linux/user.h>
#include <linux/string.h>
#include <linux/linkage.h>
#include <linux/init.h>

#include <asm/setup.h>
#include <asm/system.h>
#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/pgtable.h>
#include <asm/machdep.h>
#include <asm/siginfo.h>
#include <asm/blackfin.h>

/*
.
. EXCEPTION TRAPS DEBUGGING LEVELS
.
0 for normal operation without any error messages
1 for serious error messages 
2 for errors but handled somwehre else 
>2 for various levels of hopefully increasingly useless information
.
 .*/
#define TRAPS_DEBUG 1 /* Must be defined here or in in Makefile */

//#undef TRAPS_DEBUG

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

extern void dump(struct pt_regs *fp);
extern void _cplb_hdr(void);

static void __init bfin_trap_init (void)
{
	asm("csync;");
	*pEVT3= trap;
	asm("csync;");
	*pEVT14 = evt_system_call;
	asm("csync;");
	*pEVT15 = evt_soft_int1;
	asm("csync;");
}

/* Initiate the event table handler */
void __init trap_init (void)
{
	bfin_trap_init();
}

void die_if_kernel(char *,struct pt_regs *,int);
asmlinkage int do_page_fault(struct pt_regs *regs, unsigned long address,
                             unsigned long error_code);

asmlinkage void trap_c(struct pt_regs *fp);

int kstack_depth_to_print = 48;

asmlinkage void trap_c(struct pt_regs *fp)
{
	int sig = 0;
	siginfo_t info;

 	/* trap_c() will be called for exceptions. During exceptions
 	   processing, the pc value should be set with retx value.  
 	   With this change we can cleanup some code in signal.c- TODO */
 	fp->orig_pc = fp->retx;      

	/* send the appropriate signal to the user program */
	switch (fp->seqstat & 0x3f) {
	    case VEC_STEP:
		info.si_code = TRAP_STEP;
		fp->pc = fp->retx;      /* gdb wants the value of the pc                         */
		sig = SIGTRAP;
		break;
	    case VEC_EXCPT01 : /* gdb breakpoint */
		info.si_code = TRAP_ILLTRAP;
		fp->retx -=2;		/* For Service, proessor increments to next instruction. */
		fp->pc = fp->retx;      /* gdb wants the value of the pc                         */
		sig = SIGTRAP;
		break;
	    case VEC_UNDEF_I:
		info.si_code = ILL_ILLOPC;
		sig = SIGILL;
		break;
	    case VEC_OVFLOW:
		info.si_code = TRAP_TRACEFLOW;
		sig = SIGTRAP;
		DPRINTK(EXC_0x21);
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
	    	break;
	    case VEC_MISALI_I:
		info.si_code = BUS_ADRALN;
		sig = SIGBUS;
		DPRINTK(EXC_0x2A);
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
	    case VEC_ISTRU_VL:                /* ADSP-BF535 only (MH)*/
		info.si_code = BUS_OPFETCH;
		sig = SIGBUS;
                break;
	    case VEC_CPLB_I_VL:
		DPRINTK2(EXC_0x2B);
	    case VEC_CPLB_VL:
		info.si_code = ILL_CPLB_VI;
		DPRINTK3(EXC_0x23);
		_cplb_hdr();
		goto nsig;
		sig = SIGILL;
                break;
	    case VEC_CPLB_I_M:
		DPRINTK3(EXC_0x2C);
	    case VEC_CPLB_M:
		info.si_code = IlL_CPLB_MISS;
		/*Call the handler to replace the CPLB*/
		DPRINTK3(EXC_0x26);
		_cplb_hdr();
		goto nsig;
	    case VEC_CPLB_I_MHIT:
		DPRINTK3(EXC_0x26);
	    case VEC_CPLB_MHIT:
		info.si_code = ILL_CPLB_MULHIT;
		sig = SIGILL;
		DPRINTK3(EXC_0x27);
                break;
	    default:
		info.si_code = TRAP_ILLTRAP;
		sig = SIGTRAP;
		break;
	}
	info.si_signo = sig;
	info.si_errno = 0;
	info.si_addr = (void *) fp->pc;
	force_sig_info (sig, &info, current);
	if (sig) {
        	dump(fp);
	        dump_stack();
	}
nsig:	
	return;
}

void die_if_kernel (char *str, struct pt_regs *fp, int nr)
{
	if (!(fp->ipend))
		return;

	console_verbose();
	printk(KERN_EMERG "%s: %08x\n",str,nr);
	printk(KERN_EMERG "PC: [<%08lu>]    SEQSTAT: %04lu\n",
	       fp->pc, fp->seqstat);
	printk(KERN_EMERG "r0: %08lx    r1: %08lx    r2: %08lx    r3: %08lx\n",
	       fp->r0, fp->r1, fp->r2, fp->r3);
	printk(KERN_EMERG "r4: %08lx    r5: %08lx    r6: %08lx    r7: %08lx\n",
	       fp->r4, fp->r5, fp->r6, fp->r7);
	printk(KERN_EMERG "p0: %08lx    p1: %08lx    p2: %08lx    p3: %08lx\n",
	       fp->p0, fp->p1, fp->p2, fp->p3);
	printk(KERN_EMERG "p4: %08lx    p5: %08lx    fp: %08lx\n",
	       fp->p4, fp->p5, fp->fp);
	printk(KERN_EMERG "aow: %08lx    a0.x: %08lx    a1w: %08lx    a1.x: %08lx\n",
	       fp->a0w, fp->a0x, fp->a1w, fp->a1x);

	printk(KERN_EMERG "Process %s (pid: %d, stackpage=%08lx)\n",
		current->comm, current->pid, PAGE_SIZE+(unsigned long)current);
	show_stack(NULL, (unsigned long *)fp);
	do_exit(SIGSEGV);
}

/* Typical exception handling routines	*/
void show_stack(struct task_struct *task, unsigned long *esp)
{
	unsigned long *stack, *endstack, addr;
	extern char _start, _etext;
	int i;

	if (esp == NULL)
		esp = (unsigned long *) &esp;

	stack = esp;
	addr = (unsigned long) esp;
	endstack = (unsigned long *) PAGE_ALIGN(addr);

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
		if (((addr >= (unsigned long) &_start) &&
		     (addr <= (unsigned long) &_etext))) {
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
