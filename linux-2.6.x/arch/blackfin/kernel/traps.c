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

/* assembler routines */
asmlinkage void system_call(void);
asmlinkage void trap(void);

extern void _cplb_hdr(void);

enum {
#undef REG
#define REG(name, pos) reg_##name,
#include <asm/regs.h>
};

#define EXITCODE  *(char volatile *)0xFF7EEEEE

static void __init bfin_trap_init (void)
{
    asm("p0.l = 0x2000; p0.h = 0xffe0;"
	"p1.h = trap;" 
	"p1.l = trap;"
	"[p0+(4*3)] = p1;"
	"csync;"  
	"p1.l = system_call;"
	"p1.h = system_call;"
	"[p0+(4*15)] = p1;"
	"csync;"); 
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

/* MODULE_RANGE is a guess of how much space is likely to be vmalloced.  */
#define MODULE_RANGE (8*1024*1024)

asmlinkage void trap_c(struct pt_regs *fp)
{
	int sig = 0;
	siginfo_t info;

	/* send the appropriate signal to the user program */
	switch (fp->seqstat & 0x3f) {
	    case VEC_STEP:
		info.si_code = TRAP_STEP;
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
		break;
	    case VEC_ILGAL_I:
		info.si_code = ILL_ILLPARAOP;
		sig = SIGILL;
		break;
	    case VEC_ILL_RES:
		info.si_code = ILL_PRVOPC;
		sig = SIGILL;
                break;
	    case VEC_MISALI_D:
	    case VEC_MISALI_I:
		info.si_code = BUS_ADRALN;
		sig = SIGBUS;
		break;
	    case VEC_UNCOV:
		info.si_code = ILL_ILLEXCPT;
		sig = SIGILL;
		break;
	    case VEC_WATCH:
		info.si_code = TRAP_WATCHPT;
		sig = SIGTRAP;
		break;
	    case VEC_ISTRU_VL:
		info.si_code = BUS_OPFETCH;
		sig = SIGBUS;
                break;
	    case VEC_CPLB_I_VL:
	    case VEC_CPLB_VL:
		info.si_code = ILL_CPLB_VI;
		_cplb_hdr();
		goto nsig;
		sig = SIGILL;
                break;
	    case VEC_CPLB_I_M:
	    case VEC_CPLB_M:
		info.si_code = IlL_CPLB_MISS;
		/*Call the handler to replace the CPLB*/
		_cplb_hdr();
		goto nsig;
	    case VEC_CPLB_I_MHIT:
	    case VEC_CPLB_MHIT:
		info.si_code = ILL_CPLB_MULHIT;
		sig = SIGILL;
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
nsig:	
	return;
}

void die_if_kernel (char *str, struct pt_regs *fp, int nr)
{
	if (!(fp->seqstat & PS_S))
		return;

	console_verbose();
	printk("%s: %08x\n",str,nr);
	printk("PC: [<%08lu>]    SEQSTAT: %04lu\n",
	       fp->pc, fp->seqstat);
	printk("r0: %08lx    r1: %08lx    r2: %08lx    r3: %08lx\n",
	       fp->r0, fp->r1, fp->r2, fp->r3);
	printk("r4: %08lx    r5: %08lx    r6: %08lx    r7: %08lx\n",
	       fp->r4, fp->r5, fp->r6, fp->r7);
	printk("p0: %08lx    p1: %08lx    p2: %08lx    p3: %08lx\n",
	       fp->p0, fp->p1, fp->p2, fp->p3);
	printk("p4: %08lx    p5: %08lx    fp: %08lx\n",
	       fp->p4, fp->p5, fp->fp);
	printk("aow: %08lx    a0.x: %08lx    a1w: %08lx    a1.x: %08lx\n",
	       fp->a0w, fp->a0x, fp->a1w, fp->a1x);

	printk("Process %s (pid: %d, stackpage=%08lx)\n",
		current->comm, current->pid, PAGE_SIZE+(unsigned long)current);
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
