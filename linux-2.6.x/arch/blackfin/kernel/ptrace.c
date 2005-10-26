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
	unsigned long *addr;

	struct pt_regs *regs =
	    (struct pt_regs *)((unsigned long)task->thread_info +
			       (THREAD_SIZE - sizeof(struct pt_regs)));
	switch (regno) {
	case PT_ORIG_PC:
		return regs->orig_pc;
	case PT_PC:
		return regs->pc;
	case PT_R0:
		return regs->r0;
	case PT_ORIG_P0:
		return regs->orig_p0;
	case PT_R1:
		return regs->r1;
	case PT_R2:
		return regs->r2;
	case PT_R3:
		return regs->r3;
	case PT_R4:
		return regs->r4;
	case PT_R5:
		return regs->r5;
	case PT_R6:
		return regs->r6;
	case PT_R7:
		return regs->r7;
	case PT_P0:
		return regs->p0;
	case PT_P1:
		return regs->p1;
	case PT_P2:
		return regs->p2;
	case PT_P3:
		return regs->p3;
	case PT_P4:
		return regs->p4;
	case PT_P5:
		return regs->p5;
	case PT_A0W:
		return regs->a0w;
	case PT_A1W:
		return regs->a1w;
	case PT_A0X:
		return regs->a0x;
	case PT_A1X:
		return regs->a1x;
	case PT_IPEND:
		return regs->ipend;
	case PT_SYSCFG:
		return regs->syscfg;
	case PT_SEQSTAT:
		return regs->seqstat;
		/*case PT_RETE : return task->mm->start_code + TEXT_OFFSET; */
	case PT_RETE:
		return regs->rete;
	case PT_RETN:
		return regs->retn;
	case PT_RETX:
		return regs->retx;
	case PT_RETS:
		return regs->rets;
	case PT_RESERVED:
		return regs->reserved;
	case PT_ASTAT:
		return regs->astat;
	case PT_LB0:
		return regs->lb0;
	case PT_LB1:
		return regs->lb1;
	case PT_LT0:
		return regs->lt0;
	case PT_LT1:
		return regs->lt1;
	case PT_LC0:
		return regs->lc0;
	case PT_LC1:
		return regs->lc1;
	case PT_B0:
		return regs->b0;
	case PT_B1:
		return regs->b1;
	case PT_B2:
		return regs->b2;
	case PT_B3:
		return regs->b3;
	case PT_L0:
		return regs->l0;
	case PT_L1:
		return regs->l1;
	case PT_L2:
		return regs->l2;
	case PT_L3:
		return regs->l3;
	case PT_M0:
		return regs->m0;
	case PT_M1:
		return regs->m1;
	case PT_M2:
		return regs->m2;
	case PT_M3:
		return regs->m3;
	case PT_I0:
		return regs->i0;
	case PT_I1:
		return regs->i1;
	case PT_I2:
		return regs->i2;
	case PT_I3:
		return regs->i3;
	case PT_USP:
		return task->thread.usp;
	case PT_FP:
		return regs->fp;
		//case PT_VECTOR : return regs->pc;
	}
	/* slight mystery ... never seems to come here but kernel misbehaves without this code! */

	printk("did not return for %d\n", regno);
	if (regno == PT_USP) {
		addr = &task->thread.usp;
	} else if (regno < 208) {
		addr = (unsigned long *)(task->thread.esp0 + regno);
	} else {
		printk("Request to get for unknown register\n");
		return 0;
	}
	return *addr;

}

/*
 * Write contents of register REGNO in task TASK.
 */
static inline int
put_reg(struct task_struct *task, int regno, unsigned long data)
{
	struct pt_regs *regs =
	    (struct pt_regs *)((unsigned long)task->thread_info +
			       (THREAD_SIZE - sizeof(struct pt_regs)));
	switch (regno) {
	case PT_ORIG_PC:
		regs->orig_pc = data;
		break;
	case PT_PC:
		/*********************************************************************/
		/* At this point the kernel is most likely in exception.             */
		/* The RETX register will be used to populate the pc of the process. */
		/*********************************************************************/
		regs->retx = data;
		regs->pc = data;
		break;
	case PT_R0:
		regs->r0 = data;
		break;
	case PT_ORIG_P0:
		regs->orig_p0 = data;
		break;
	case PT_R1:
		regs->r1 = data;
		break;
	case PT_R2:
		regs->r2 = data;
		break;
	case PT_R3:
		regs->r3 = data;
		break;
	case PT_R4:
		regs->r4 = data;
		break;
	case PT_R5:
		regs->r5 = data;
		break;
	case PT_R6:
		regs->r6 = data;
		break;
	case PT_R7:
		regs->r7 = data;
		break;
	case PT_P0:
		regs->p0 = data;
		break;
	case PT_P1:
		regs->p1 = data;
		break;
	case PT_P2:
		regs->p2 = data;
		break;
	case PT_P3:
		regs->p3 = data;
		break;
	case PT_P4:
		regs->p4 = data;
		break;
	case PT_P5:
		regs->p5 = data;
		break;
	case PT_A0W:
		regs->a0w = data;
		break;
	case PT_A1W:
		regs->a1w = data;
		break;
	case PT_A0X:
		regs->a0x = data;
		break;
	case PT_A1X:
		regs->a1x = data;
		break;
	case PT_IPEND:
		regs->ipend = data;
		break;
	case PT_SYSCFG:
		regs->syscfg = data;
		break;
	case PT_SEQSTAT:
		regs->seqstat = data;
		break;
	case PT_RETE:
		regs->rete = data;
		break;
	case PT_RETN:
		regs->retn = data;
		break;
	case PT_RETX:
		break;		//regs->retx = data; break;
	case PT_RETS:
		regs->rets = data;
		break;
	case PT_RESERVED:
		regs->reserved = data;
		break;
	case PT_ASTAT:
		regs->astat = data;
		break;
	case PT_LB0:
		regs->lb0 = data;
		break;
	case PT_LB1:
		regs->lb1 = data;
		break;
	case PT_LT0:
		regs->lt0 = data;
		break;
	case PT_LT1:
		regs->lt1 = data;
		break;
	case PT_LC0:
		regs->lc0 = data;
		break;
	case PT_LC1:
		regs->lc1 = data;
		break;
	case PT_B0:
		regs->b0 = data;
		break;
	case PT_B1:
		regs->b1 = data;
		break;
	case PT_B2:
		regs->b2 = data;
		break;
	case PT_B3:
		regs->b3 = data;
		break;
	case PT_L0:
		regs->l0 = data;
		break;
	case PT_L1:
		regs->l1 = data;
		break;
	case PT_L2:
		regs->l2 = data;
		break;
	case PT_L3:
		regs->l3 = data;
		break;
	case PT_M0:
		regs->m0 = data;
		break;
	case PT_M1:
		regs->m1 = data;
		break;
	case PT_M2:
		regs->m2 = data;
		break;
	case PT_M3:
		regs->m3 = data;
		break;
	case PT_I0:
		regs->i0 = data;
		break;
	case PT_I1:
		regs->i1 = data;
		break;
	case PT_I2:
		regs->i2 = data;
		break;
	case PT_I3:
		regs->i3 = data;
		break;
	case PT_USP:
		regs->usp = data;
		task->thread.usp = data;
		break;
	case PT_FP:
		regs->fp = data;
		break;
		//case PT_VECTOR : regs->pc = data; break;
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

asmlinkage int sys_ptrace(long request, long pid, long addr, long data)
{
	struct task_struct *child;
	int ret;
	int add = 0;

	lock_kernel();
	ret = -EPERM;
	if (request == PTRACE_TRACEME) {
		/* are we already being traced? */
		if (current->ptrace & PT_PTRACED)
			goto out;
		/* set the ptrace bit in the process flags. */
		current->ptrace |= PT_PTRACED;
		ret = 0;
		goto out;
	}
	ret = -ESRCH;
	read_lock(&tasklist_lock);
	child = find_task_by_pid(pid);
	if (child)
		get_task_struct(child);
	read_unlock(&tasklist_lock);	/* FIXME!!! */
	if (!child)
		goto out;
	ret = -EPERM;
	if (pid == 1)		/* you may not mess with init */
		goto out_tsk;
	if (request == PTRACE_ATTACH) {

		ret = ptrace_attach(child);
		goto out_tsk;
	}

	ret = ptrace_check_attach(child, request == PTRACE_KILL);
	if (ret < 0)
		goto out_tsk;

	switch (request) {
		/* when I and D space are separate, these will need to be fixed. */
	case PTRACE_PEEKDATA:
		printk("PTRACE_PEEKDATA\n");
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
				goto out_tsk;
			ret = put_user(tmp, (unsigned long *)data);
			goto out_tsk;
		}

		/* read the word at location addr in the USER area. */
	case PTRACE_PEEKUSR:
		{
			unsigned long tmp;
			ret = -EIO;
			tmp = 0;
			if ((addr & 3) || (addr > (sizeof(struct pt_regs) + 8))) {
				printk
				    ("ptrace error : PEEKUSR : temporarily returning 0 - %x sizeof(pt_regs) is %lx\n",
				     (int)addr, sizeof(struct pt_regs));
				goto out_tsk;
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
			} else {
				tmp = get_reg(child, addr);
			}
			ret = put_user(tmp, (unsigned long *)data);
			goto out_tsk;
		}

		/* when I and D space are separate, this will have to be fixed. */
	case PTRACE_POKEDATA:
		printk("PTRACE_PEEKDATA\n");
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
				goto out_tsk;
			ret = -EIO;
			goto out_tsk;
		}

	case PTRACE_POKEUSR:	/* write the word at location addr in the USER area */
		ret = -EIO;
		if ((addr & 3) || (addr > (sizeof(struct pt_regs) + 8))) {
			printk
			    ("ptrace error : POKEUSR: temporarily returning 0\n");
			goto out_tsk;
		}

		if (addr == PT_SYSCFG) {
			data &= SYSCFG_MASK;
			data |= get_reg(child, PT_SYSCFG);
		}
		ret = put_reg(child, addr, data);
		goto out_tsk;

	case PTRACE_SYSCALL:	/* continue and stop at next (return from) syscall */
	case PTRACE_CONT:
		{		/* restart after signal. */
			long tmp;
#ifdef DEBUG
			printk("ptrace_cont\n");
#endif

			ret = -EIO;
			if (!valid_signal(data))
				goto out_tsk;
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
			goto out_tsk;
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
				goto out_tsk;
			child->exit_code = SIGKILL;
			/* make sure the single step bit is not set. */
			tmp = get_reg(child, PT_SYSCFG) & ~(TRACE_BITS);
			put_reg(child, PT_SYSCFG, tmp);
			wake_up_process(child);
			goto out_tsk;
		}

	case PTRACE_SINGLESTEP:
		{		/* set the trap flag. */
			long tmp;
#ifdef DEBUG
			printk("single step\n");
#endif
			ret = -EIO;
			if (!valid_signal(data))
				goto out_tsk;
			clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);

			tmp = get_reg(child, PT_SYSCFG) | (TRACE_BITS);
			put_reg(child, PT_SYSCFG, tmp);

			child->exit_code = data;
			/* give it a chance to run. */
			wake_up_process(child);
			ret = 0;
			goto out;
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
			goto out_tsk;
		}

	case PTRACE_SETREGS:
		{

			printk("SETREGS : **** NOT IMPLEMENTED ***\n");
			/* Set all gp regs in the child. */
			ret = 0;
			goto out_tsk;
		}

	default:
		printk("Ptrace :  *** Unhandled case **** %d\n", (int)request);
		ret = -EIO;
		goto out_tsk;
	}
      out_tsk:
	put_task_struct(child);
      out:
	unlock_kernel();
	return ret;
}

asmlinkage void syscall_trace(void)
{

	if (!test_thread_flag(TIF_SYSCALL_TRACE))
		return;

	if (!(current->ptrace & PT_PTRACED))
		return;

	ptrace_notify(SIGTRAP);
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
