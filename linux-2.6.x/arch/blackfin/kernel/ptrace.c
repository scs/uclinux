/*
 * File:         arch/blackfin/kernel/ptrace.c
 * Based on:     Taken from linux/kernel/ptrace.c
 * Author:       linux/kernel/ptrace.c is by Ross Biro 1/23/92, edited by Linus Torvalds
 *
 * Created:      1/23/92
 * Description:
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

#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/smp.h>
#include <linux/smp_lock.h>
#include <linux/errno.h>
#include <linux/ptrace.h>
#include <linux/user.h>
#include <linux/config.h>
#include <linux/signal.h>

/*#define DEBUG*/

#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <asm/asm-offsets.h>

#define MAX_SHARED_LIBS 3
#define TEXT_OFFSET 0
/*
 * does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

/* determines which bits in the SYSCFG reg the user has access to. */
/* 1 = access 0 = no access */
#define SYSCFG_MASK 0x0007	/* SYSCFG reg */
/* sets the trace bits. */
#define TRACE_BITS 0x0001

/* Find the stack offset for a register, relative to thread.esp0. */
#define PT_REG(reg)	((long)&((struct pt_regs *)0)->reg)

/*
 * Get the address of the live pt_regs for the specified task.
 * These are saved onto the top kernel stack when the process
 * is not running.
 *
 * Note: if a user thread is execve'd from kernel space, the
 * kernel stack will not be empty on entry to the kernel, so
 * ptracing these tasks will fail.
 */
static inline struct pt_regs *get_user_regs(struct task_struct *task)
{
	return (struct pt_regs *)
	    ((unsigned long)task->thread_info +
	     (THREAD_SIZE - sizeof(struct pt_regs)));
}

/*
 * Get all user integer registers.
 */
static inline int ptrace_getregs(struct task_struct *tsk, void __user * uregs)
{
	struct pt_regs *regs = get_user_regs(tsk);
	return copy_to_user(uregs, regs, sizeof(struct pt_regs)) ? -EFAULT : 0;
}

/* Mapping from PT_xxx to the stack offset at which the register is
   saved.  Notice that usp has no stack-slot and needs to be treated
   specially (see get_reg/put_reg below). */

/*
 * Get contents of register REGNO in task TASK.
 */
static inline long get_reg(struct task_struct *task, int regno)
{
	unsigned char *reg_ptr;

	struct pt_regs *regs =
	    (struct pt_regs *)((unsigned long)task->thread_info +
			       (THREAD_SIZE - sizeof(struct pt_regs)));
	reg_ptr = (char *)regs;

	switch (regno) {
	case PT_USP:
		return task->thread.usp;
	default:
		if (regno <= 216)
			return *(long *)(reg_ptr + regno);
	}
	/* slight mystery ... never seems to come here but kernel misbehaves without this code! */

	printk(KERN_WARNING "Request to get for unknown register %d\n", regno);
	return 0;
}

/*
 * Write contents of register REGNO in task TASK.
 */
static inline int
put_reg(struct task_struct *task, int regno, unsigned long data)
{
	char * reg_ptr;

	struct pt_regs *regs =
	    (struct pt_regs *)((unsigned long)task->thread_info +
			       (THREAD_SIZE - sizeof(struct pt_regs)));
	reg_ptr = (char *)regs;

	switch (regno) {
	case PT_PC:
		/*********************************************************************/
		/* At this point the kernel is most likely in exception.             */
		/* The RETX register will be used to populate the pc of the process. */
		/*********************************************************************/
		regs->retx = data;
		regs->pc = data;
		break;
	case PT_RETX:
		break;		/* regs->retx = data; break; */
	case PT_USP:
		regs->usp = data;
		task->thread.usp = data;
		break;
	default:
		if (regno <= 216)
		        *(long *)(reg_ptr + regno) = data;
	}
	return 0;
}

/*
 * Called by kernel/ptrace.c when detaching..
 *
 * Make sure the single step bit is not set.
 */
void ptrace_disable(struct task_struct *child)
{
	unsigned long tmp;
	/* make sure the single step bit is not set. */
	tmp = get_reg(child, PT_SR) & ~(TRACE_BITS << 16);
	put_reg(child, PT_SR, tmp);
}

long arch_ptrace(struct task_struct *child, long request, long addr, long data)
{
	int ret;
	int add = 0;

	switch (request) {
		/* when I and D space are separate, these will need to be fixed. */
	case PTRACE_PEEKDATA:
#ifdef DEBUG
		printk("PTRACE_PEEKDATA\n");
#endif
		add = MAX_SHARED_LIBS * 4;	/* space between text and data */
		/* fall through */
	case PTRACE_PEEKTEXT:	/* read word at location addr. */
		{
			unsigned long tmp = 0;
			int copied;

#ifdef DEBUG
			printk("PEEKTEXT at addr %x + add %d %d", addr, add,
			       sizeof(data));
#endif
			copied =
			    access_process_vm(child, addr + add, &tmp,
					      sizeof(tmp), 0);
#ifdef DEBUG
			printk(" bytes %x\n", data);
#endif
			ret = -EIO;
			if (copied != sizeof(tmp))
				break;
			ret = put_user(tmp, (unsigned long *)data);
			break;
		}

		/* read the word at location addr in the USER area. */
	case PTRACE_PEEKUSR:
		{
			unsigned long tmp;
			ret = -EIO;
			tmp = 0;
			if ((addr & 3) || (addr > (sizeof(struct pt_regs) + 16))) {
				printk
				    ("ptrace error : PEEKUSR : temporarily returning 0 - %x sizeof(pt_regs) is %lx\n",
				     (int)addr, sizeof(struct pt_regs));
				break;
			}
			if (addr == sizeof(struct pt_regs)) {
				tmp = child->mm->start_code + TEXT_OFFSET;
			} else if (addr == (sizeof(struct pt_regs) + 4)) {
				// should really just be start_data but the .gdb file has data starting
				// at an offset and gdb refuses to reduce the start value
				tmp =
				    child->mm->start_data -
				    (child->mm->end_code -
				     child->mm->start_code);
			} else if (addr == (sizeof(struct pt_regs) + 8)) {
				// should really just be end_data but the .gdb file has data starting
				// at an offset and gdb refuses to reduce the start value
				tmp =
				    child->mm->end_data - (child->mm->end_code -
							   child->mm->
							   start_code);
#ifdef CONFIG_BINFMT_ELF_FDPIC
			} else if (addr == (sizeof(struct pt_regs) + 12)) {
				tmp = child->mm->context.exec_fdpic_loadmap;
			} else if (addr == (sizeof(struct pt_regs) + 16)) {
				tmp = child->mm->context.interp_fdpic_loadmap;
#endif
			} else {
				tmp = get_reg(child, addr);
			}
			ret = put_user(tmp, (unsigned long *)data);
			break;
		}

		/* when I and D space are separate, this will have to be fixed. */
	case PTRACE_POKEDATA:
		printk(KERN_NOTICE "ptrace: PTRACE_PEEKDATA\n");
		/* fall through */
	case PTRACE_POKETEXT:	/* write the word at location addr. */
		{
			ret = 0;
#ifdef DEBUG
			printk("POKETEXT at addr %x + add %d %d bytes %x\n",
			       addr, add, sizeof(data), data);
#endif
			if (access_process_vm(child, addr + add,
					      &data, sizeof(data),
					      1) == sizeof(data))
				break;
			ret = -EIO;
			break;
		}

	case PTRACE_POKEUSR:	/* write the word at location addr in the USER area */
		ret = -EIO;
		if ((addr & 3) || (addr > (sizeof(struct pt_regs) + 16))) {
			printk
			    ("ptrace error : POKEUSR: temporarily returning 0\n");
			break;
		}

		if (addr >= (sizeof(struct pt_regs))) {
			ret = 0;
			break;
		}
		if (addr == PT_SYSCFG) {
			data &= SYSCFG_MASK;
			data |= get_reg(child, PT_SYSCFG);
		}
		ret = put_reg(child, addr, data);
		break;

	case PTRACE_SYSCALL:	/* continue and stop at next (return from) syscall */
	case PTRACE_CONT:
		{		/* restart after signal. */
			long tmp;
#ifdef DEBUG
			printk("ptrace_cont\n");
#endif

			ret = -EIO;
			if (!valid_signal(data))
				break;
			if (request == PTRACE_SYSCALL)
				set_tsk_thread_flag(child, TIF_SYSCALL_TRACE);
			else
				clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);

			child->exit_code = data;
			/* make sure the single step bit is not set. */
			tmp = get_reg(child, PT_SYSCFG) & ~(TRACE_BITS);
			put_reg(child, PT_SYSCFG, tmp);
#ifdef DEBUG
			printk("before wake_up_process\n");
#endif
			wake_up_process(child);
			ret = 0;
			break;
		}

/*
 * make the child exit.  Best I can do is send it a sigkill.
 * perhaps it should be put in the status that it wants to
 * exit.
 */
	case PTRACE_KILL:
		{
			long tmp;
			ret = 0;
			if (child->exit_state == EXIT_ZOMBIE)	/* already dead */
				break;
			child->exit_code = SIGKILL;
			/* make sure the single step bit is not set. */
			tmp = get_reg(child, PT_SYSCFG) & ~(TRACE_BITS);
			put_reg(child, PT_SYSCFG, tmp);
			wake_up_process(child);
			break;
		}

	case PTRACE_SINGLESTEP:
		{		/* set the trap flag. */
			long tmp;
#ifdef DEBUG
			printk("single step\n");
#endif
			ret = -EIO;
			if (!valid_signal(data))
				break;
			clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);

			tmp = get_reg(child, PT_SYSCFG) | (TRACE_BITS);
			put_reg(child, PT_SYSCFG, tmp);

			child->exit_code = data;
			/* give it a chance to run. */
			wake_up_process(child);
			ret = 0;
			break;
		}

	case PTRACE_DETACH:
		{		/* detach a process that was attached. */
			ret = ptrace_detach(child, data);
			break;
		}

	case PTRACE_GETREGS:
		{

			/* Get all gp regs from the child. */
			ret = ptrace_getregs(child, (void __user *)data);
			break;
		}

	case PTRACE_SETREGS:
		{
			printk(KERN_NOTICE "ptrace: SETREGS: **** NOT IMPLEMENTED ***\n");
			/* Set all gp regs in the child. */
			ret = 0;
			break;
		}
	default:
		printk(KERN_NOTICE "ptrace: *** Unhandled case **** %d\n", (int)request);
		ret = -EIO;
		break;
	}

	return ret;
}

asmlinkage void syscall_trace(void)
{

	if (!test_thread_flag(TIF_SYSCALL_TRACE))
		return;

	if (!(current->ptrace & PT_PTRACED))
		return;

	/* the 0x80 provides a way for the tracing parent to distinguish
	   between a syscall stop and SIGTRAP delivery */
	ptrace_notify(SIGTRAP | ((current->ptrace & PT_TRACESYSGOOD)
				 ? 0x80 : 0));

	/*
	 * this isn't the same as continuing with a signal, but it will do
	 * for normal use.  strace only continues with a signal if the
	 * stopping signal is not SIGTRAP.  -brl
	 */
	if (current->exit_code) {
		send_sig(current->exit_code, current, 1);
		current->exit_code = 0;
	}
}
