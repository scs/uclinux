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
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <asm/uaccess.h>
#include <asm/traps.h>
#include <asm/cacheflush.h>
#include <asm/blackfin.h>
#include <asm/uaccess.h>
#include <linux/interrupt.h>
#include <linux/module.h>

extern unsigned long memory_end, physical_mem_end;

/* assembler routines */
asmlinkage void evt_system_call(void);
asmlinkage void evt_soft_int1(void);
asmlinkage void trap(void);

/* Initiate the event table handler */
void __init trap_init(void)
{
	__builtin_bfin_csync();
	bfin_write_EVT3(trap);
	__builtin_bfin_csync();
}

asmlinkage void trap_c(struct pt_regs *fp);

int kstack_depth_to_print = 48;

#ifdef CONFIG_KALLSYMS
#include <linux/kallsyms.h>
static int printk_address(unsigned long address)
{
	unsigned long offset = 0, symsize;
	const char *symname;
	char *modname;
	char *delim = ":";
	char namebuf[128];

	/* look up the address and see if we are in kernel space */
	symname = kallsyms_lookup(address, &symsize, &offset, &modname, namebuf);

	if (symname) {
		/* yeah! kernel space! */
		if (!modname)
			modname = delim = "";
		return printk("<0x%p> { %s%s%s%s + 0x%lx }",
			      (void*)address, delim, modname, delim, symname, (unsigned long)offset);

	} else {
		/* looks like we're off in user-land, so let's walk all the
		 * mappings of all our processes and see if we can't be a whee
		 * bit more specific
		 */
		struct vm_list_struct *vml;
		struct task_struct *p;
		struct mm_struct *mm;

		write_lock_irq(&tasklist_lock);
		for_each_process (p) {
			mm = get_task_mm(p);
			if (!mm)
				continue;

			vml = mm->context.vmlist;
			while (vml) {
				struct vm_area_struct *vma = vml->vma;

				if ((address >= vma->vm_start) && (address < vma->vm_end)) {
					char *name = p->comm;
					struct file *file = vma->vm_file;
					if (file) {
						char _tmpbuf[256];
						name = d_path(file->f_dentry, file->f_vfsmnt, _tmpbuf, sizeof(_tmpbuf));
					}

					write_unlock_irq(&tasklist_lock);
					return printk("<0x%p> [ %s + 0x%lx ]",
						      (void*)address,
						      name,
						      (unsigned long)((address - vma->vm_start) + (vma->vm_pgoff << PAGE_SHIFT)));
				}

				vml = vml->next;
			}
		}
		write_unlock_irq(&tasklist_lock);
	}

	/* we were unable to find this address anywhere */
	return printk("[<0x%p>]", (void*)address);
}
#else
static int printk_address(unsigned long address)
{
	return printk("[<0x%p>]", (void*)address);
}
#endif

#define trace_buffer_save(x) \
	do { \
		(x) = bfin_read_TBUFCTL(); \
		bfin_write_TBUFCTL((x) & ~TBUFEN); \
	} while (0)
#define trace_buffer_restore(x) \
	do { \
		bfin_write_TBUFCTL((x));	\
	} while (0)

asmlinkage void trap_c(struct pt_regs *fp)
{
	int j, sig = 0;
	siginfo_t info;

	trace_buffer_save(j);

	/* trap_c() will be called for exceptions. During exceptions
	 * processing, the pc value should be set with retx value.
	 * With this change we can cleanup some code in signal.c- TODO
	 */
	fp->orig_pc = fp->retx;

	/* send the appropriate signal to the user program */
	switch (fp->seqstat & SEQSTAT_EXCAUSE) {

	/* This table works in conjuction with the one in ./mach-common/entry.S
	 * Some exceptions are handled there (in assembly, in exception space)
	 * Some are handled here, (in C, in interrupt space)
	 * Some, like CPLB, are handled in both, where the normal path is
	 * handled in assembly/exception space, and the error path is handled
	 * here
	 */

	/* 0x00 - Linux Syscall, getting here is an error */
	/* 0x01 - userspace gdb breakpoint, handled here */
	case VEC_EXCPT01:
		info.si_code = TRAP_ILLTRAP;
		sig = SIGTRAP;
		/* Check if this is a breakpoint in kernel space */
		if (fp->ipend & 0xffc0)
			return;
		else
			break;
	/* 0x02 - User Defined, Caught by default */
	/* 0x03  - Atomic test and set */
	case VEC_EXCPT03:
		info.si_code = SEGV_STACKFLOW;
		sig = SIGSEGV;
		printk(KERN_EMERG EXC_0x03);
		break;
	/* 0x04 - spinlock - handled by _ex_spinlock,
		getting here is an error */
	/* 0x05 - User Defined, Caught by default */
	/* 0x06 - User Defined, Caught by default */
	/* 0x07 - User Defined, Caught by default */
	/* 0x08 - User Defined, Caught by default */
	/* 0x09 - User Defined, Caught by default */
	/* 0x0A - User Defined, Caught by default */
	/* 0x0B - User Defined, Caught by default */
	/* 0x0C - User Defined, Caught by default */
	/* 0x0D - User Defined, Caught by default */
	/* 0x0E - User Defined, Caught by default */
	/* 0x0F - User Defined, Caught by default */
	/* 0x10 HW Single step, handled here */
	case VEC_STEP:
		info.si_code = TRAP_STEP;
		sig = SIGTRAP;
		/* Check if this is a single step in kernel space */
		if (fp->ipend & 0xffc0)
			return;
		else
			break;
	/* 0x11 - Trace Buffer Full, handled here */
	case VEC_OVFLOW:
		info.si_code = TRAP_TRACEFLOW;
		sig = SIGTRAP;
		printk(KERN_EMERG EXC_0x11);
		break;
	/* 0x12 - Reserved, Caught by default */
	/* 0x13 - Reserved, Caught by default */
	/* 0x14 - Reserved, Caught by default */
	/* 0x15 - Reserved, Caught by default */
	/* 0x16 - Reserved, Caught by default */
	/* 0x17 - Reserved, Caught by default */
	/* 0x18 - Reserved, Caught by default */
	/* 0x19 - Reserved, Caught by default */
	/* 0x1A - Reserved, Caught by default */
	/* 0x1B - Reserved, Caught by default */
	/* 0x1C - Reserved, Caught by default */
	/* 0x1D - Reserved, Caught by default */
	/* 0x1E - Reserved, Caught by default */
	/* 0x1F - Reserved, Caught by default */
	/* 0x20 - Reserved, Caught by default */
	/* 0x21 - Undefined Instruction, handled here */
	case VEC_UNDEF_I:
		info.si_code = ILL_ILLOPC;
		sig = SIGILL;
		printk(KERN_EMERG EXC_0x21);
		break;
	/* 0x22 - Illegal Instruction Combination, handled here */
	case VEC_ILGAL_I:
		info.si_code = ILL_ILLPARAOP;
		sig = SIGILL;
		printk(KERN_EMERG EXC_0x22);
		break;
	/* 0x23 - Data CPLB Protection Violation,
		 normal case is handled in _cplb_hdr */
	case VEC_CPLB_VL:
		info.si_code = ILL_CPLB_VI;
		sig = SIGILL;
		printk(KERN_EMERG EXC_0x23);
		break;
	/* 0x24 - Data access misaligned, handled here */
	case VEC_MISALI_D:
		info.si_code = BUS_ADRALN;
		sig = SIGBUS;
		printk(KERN_EMERG EXC_0x24);
		break;
	/* 0x25 - Unrecoverable Event, handled here */
	case VEC_UNCOV:
		info.si_code = ILL_ILLEXCPT;
		sig = SIGILL;
		printk(KERN_EMERG EXC_0x25);
		break;
	/* 0x26 - Data CPLB Miss, normal case is handled in _cplb_hdr,
		error case is handled here */
	case VEC_CPLB_M:
		info.si_code = BUS_ADRALN;
		sig = SIGBUS;
		printk(KERN_EMERG EXC_0x26);
		break;
	/* 0x27 - Data CPLB Multiple Hits - Linux Trap Zero, handled here */
	case VEC_CPLB_MHIT:
		info.si_code = ILL_CPLB_MULHIT;
#ifdef CONFIG_DEBUG_HUNT_FOR_ZERO
		sig = SIGSEGV;
		printk(KERN_EMERG "\n\nNULL pointer access (probably)\n");
#else
		sig = SIGILL;
		printk(KERN_EMERG EXC_0x27);
#endif
		break;
	/* 0x28 - Emulation Watchpoint, handled here */
	case VEC_WATCH:
		info.si_code = TRAP_WATCHPT;
		sig = SIGTRAP;
		pr_debug(EXC_0x28);
		/* Check if this is a watchpoint in kernel space */
		if (fp->ipend & 0xffc0)
			return;
		else
			break;
#ifdef CONFIG_BF535
	/* 0x29 - Instruction fetch access error (535 only) */
	case VEC_ISTRU_VL:      /* ADSP-BF535 only (MH) */
		info.si_code = BUS_OPFETCH;
		sig = SIGBUS;
		printk(KERN_EMERG "BF535: VEC_ISTRU_VL\n");
		break;
#else
	/* 0x29 - Reserved, Caught by default */
#endif
	/* 0x2A - Instruction fetch misaligned, handled here */
	case VEC_MISALI_I:
		info.si_code = BUS_ADRALN;
		sig = SIGBUS;
		printk(KERN_EMERG EXC_0x2A);
		break;
	/* 0x2B - Instruction CPLB protection Violation,
		handled in _cplb_hdr */
	case VEC_CPLB_I_VL:
		info.si_code = ILL_CPLB_VI;
		sig = SIGILL;
		printk(KERN_EMERG EXC_0x2B);
		break;
	/* 0x2C - Instruction CPLB miss, handled in _cplb_hdr */
	case VEC_CPLB_I_M:
		info.si_code = ILL_CPLB_MISS;
		sig = SIGBUS;
		printk(KERN_EMERG EXC_0x2C);
		break;
	/* 0x2D - Instruction CPLB Multiple Hits, handled here */
	case VEC_CPLB_I_MHIT:
		info.si_code = ILL_CPLB_MULHIT;
#ifdef CONFIG_DEBUG_HUNT_FOR_ZERO
		sig = SIGSEGV;
		printk(KERN_EMERG "\n\nJump to address 0 - 0x0fff\n");
#else
		sig = SIGILL;
		printk(KERN_EMERG EXC_0x2D);
#endif
		break;
	/* 0x2E - Illegal use of Supervisor Resource, handled here */
	case VEC_ILL_RES:
		info.si_code = ILL_PRVOPC;
		sig = SIGILL;
		printk(KERN_EMERG EXC_0x2E);
		break;
	/* 0x2F - Reserved, Caught by default */
	/* 0x30 - Reserved, Caught by default */
	/* 0x31 - Reserved, Caught by default */
	/* 0x32 - Reserved, Caught by default */
	/* 0x33 - Reserved, Caught by default */
	/* 0x34 - Reserved, Caught by default */
	/* 0x35 - Reserved, Caught by default */
	/* 0x36 - Reserved, Caught by default */
	/* 0x37 - Reserved, Caught by default */
	/* 0x38 - Reserved, Caught by default */
	/* 0x39 - Reserved, Caught by default */
	/* 0x3A - Reserved, Caught by default */
	/* 0x3B - Reserved, Caught by default */
	/* 0x3C - Reserved, Caught by default */
	/* 0x3D - Reserved, Caught by default */
	/* 0x3E - Reserved, Caught by default */
	/* 0x3F - Reserved, Caught by default */
	default:
		info.si_code = TRAP_ILLTRAP;
		sig = SIGTRAP;
		printk(KERN_EMERG "Caught Unhandled Exception, code = %08lx\n",
			(fp->seqstat & SEQSTAT_EXCAUSE));
		break;
	}

	info.si_signo = sig;
	info.si_errno = 0;
	info.si_addr = (void *)fp->pc;
	force_sig_info(sig, &info, current);
	if (sig != 0 && sig != SIGTRAP) {
		unsigned long stack;
		dump_bfin_regs(fp, (void *)fp->retx);
		show_stack(current, &stack);
		if (current->mm == NULL)
			panic("Kernel exception");
	}

	/* if the address that we are about to return to is not valid, set it
	 * to a valid address, if we have a current application or panic
	 */
	if (!fp->pc <= physical_mem_end
#if L1_CODE_LENGTH != 0
	    || (fp->pc >= L1_CODE_START &&
	        fp->pc <= (L1_CODE_START + L1_CODE_LENGTH))
#endif
	) {
		if (current->mm) {
			fp->pc = current->mm->start_code;
		} else {
			printk(KERN_EMERG "I can't return to memory that doesn't exist - bad things happen\n");
			panic("Help- I have fallen and can't get up\n");
		}
	}

	trace_buffer_restore(j);
	return;
}

/* Typical exception handling routines	*/

void dump_bfin_trace_buffer(void)
{
	if (likely(bfin_read_TBUFSTAT() & TBUFCNT)) {
		int i;
		printk(KERN_EMERG "Hardware Trace:\n");
		for (i = 0; bfin_read_TBUFSTAT() & TBUFCNT; i++) {
			printk(KERN_EMERG "%2i Target : ", i);
			printk_address((unsigned long)bfin_read_TBUF());
			printk("\n" KERN_EMERG "   Source : ");
			printk_address((unsigned long)bfin_read_TBUF());
			printk("\n");
		}
	}
}
EXPORT_SYMBOL(dump_bfin_trace_buffer);

void show_stack(struct task_struct *task, unsigned long *stack)
{
	unsigned long *endstack, addr;
	int i;

	dump_bfin_trace_buffer();

	if (!stack) {
		if (task)
			stack = (unsigned long *)task->thread.ksp;
		else
			stack = (unsigned long *)&stack;
	}

	addr = (unsigned long)stack;
	endstack = (unsigned long *)PAGE_ALIGN(addr);

	printk(KERN_EMERG "Stack from %08lx:", (unsigned long)stack);
	for (i = 0; i < kstack_depth_to_print; i++) {
		if (stack + 1 > endstack)
			break;
		if (i % 8 == 0)
			printk("\n" KERN_EMERG "       ");
		printk(" %08lx", *stack++);
	}

	printk("\n" KERN_EMERG "Call Trace:\n");
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
		    && addr <= (unsigned long)_etext) {
			printk(KERN_EMERG "       ");
			printk_address(addr);
			printk("\n");
			i++;
		}
	}
	printk(KERN_EMERG "\n");
}

void dump_stack(void)
{
	unsigned long stack;
	int j;
	trace_buffer_save(j);
	show_stack(current, &stack);
	trace_buffer_restore(j);
}

EXPORT_SYMBOL(dump_stack);

void dump_bfin_regs(struct pt_regs *fp, void *retaddr)
{

	if (current->pid) {
		printk("\nCURRENT PROCESS:\n\n");
		printk("COMM=%s PID=%d\n", current->comm, current->pid);
	} else {
		printk("\nNo Valid pid - Either things are really messed up, or you are in the kernel\n");
	}

	if (current->mm) {
		printk("TEXT = 0x%p-0x%p  DATA = 0x%p-0x%p\n"
		       "BSS = 0x%p-0x%p   USER-STACK = 0x%p\n\n",
		       (void*)current->mm->start_code,
		       (void*)current->mm->end_code,
		       (void*)current->mm->start_data,
		       (void*)current->mm->end_data,
		       (void*)current->mm->end_data,
		       (void*)current->mm->brk,
		       (void*)current->mm->start_stack);
	}

	printk("return address: 0x%p; contents of [PC-16...PC+8]:\n", retaddr);
	if (retaddr != 0
#if L1_CODE_LENGTH != 0
	    /* FIXME: Copy the code out of L1 Instruction SRAM through dma
	       memcpy.  */
	    && !(retaddr >= (void*)L1_CODE_START
		 && retaddr < (void*)(L1_CODE_START + L1_CODE_LENGTH))
#endif
		&& retaddr <= (void*)physical_mem_end
	    ) {
		int i;
		unsigned short x;
		for (i = -16; i < 8; i++) {
			get_user(x, (unsigned short *)retaddr + i);
#ifndef CONFIG_DEBUG_HWERR
			/* If one of the last few instructions was a STI
			 * it is likily that the error occured awhile ago
			 * and we just noticed
			 */
			if (x >= 0x0040 && x <= 0x0047 && i <= 0)
				panic("\n\nWARNING : You should reconfigure the kernel to turn on\n"
					" 'Hardware error interrupt debugging'\n"
					" The rest of this error is meanless\n");
#endif

			if (i == -8)
				printk("\n");
			if (i == 0)
				printk("X\n");
			printk("%04x ", x);
		}
	} else {
		printk("Can't look at the [PC] now - sorry\n");
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
	if ((long)fp->seqstat & SEQSTAT_EXCAUSE) {
		printk(KERN_EMERG "DCPLB_FAULT_ADDR=%p\n", (void*)bfin_read_DCPLB_FAULT_ADDR());
		printk(KERN_EMERG "ICPLB_FAULT_ADDR=%p\n", (void*)bfin_read_ICPLB_FAULT_ADDR());
	}

	printk("\n\n");
}

asmlinkage int sys_bfin_spinlock(int *spinlock)
{
	int ret = 0;
	int tmp;

	local_irq_disable();
	get_user(tmp, spinlock);
	if (tmp)
		ret = 1;
	tmp = 1;
	put_user(tmp, spinlock);
	local_irq_enable();
	return ret;
}

void panic_cplb_error(int cplb_panic, struct pt_regs *fp)
{

	switch (cplb_panic) {
	case CPLB_NO_UNLOCKED:
		printk(KERN_EMERG "All CPLBs are locked\n");
		break;
	case CPLB_PROT_VIOL:
		return;
	case CPLB_NO_ADDR_MATCH:
		return;
	case CPLB_UNKNOWN_ERR:
		printk(KERN_EMERG "Unknown CPLB Exception\n");
		break;
	}

	printk(KERN_EMERG "DCPLB_FAULT_ADDR=%p\n", (void*)bfin_read_DCPLB_FAULT_ADDR());
	printk(KERN_EMERG "ICPLB_FAULT_ADDR=%p\n", (void*)bfin_read_ICPLB_FAULT_ADDR());
	dump_bfin_regs(fp, (void *)fp->retx);
	dump_stack();
	panic("Unrecoverable event\n");
}
