/*
 *  linux/arch/bfinnommu/kernel/ptrace.c
 *
 *  Taken from linux/kernel/ptrace.c and modified for blckfin.
 *  linux/kernel/ptrace.c is by Ross Biro 1/23/92, edited by Linus Torvalds
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file COPYING in the main directory of
 * this archive for more details.
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

#include <asm/uaccess.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/processor.h>
#include <asm/asm-offsets.h>


/*
 * does not yet catch signals sent when the child dies.
 * in exit.c or in signal.c.
 */

/* determines which bits in the ASTAT reg the user has access to. */
/* 1 = access 0 = no access */
/*#define ASTAT_MASK 0x017f*/   /* BFIN ASTAT reg */

/* determines which bits in the SYSCFG reg the user has access to. */
/* 1 = access 0 = no access */
#define SYSCFG_MASK 0x0007   /* BFIN SYSCFG reg */
/* sets the trace bits. */
#define TRACE_BITS 0x0001

/* Find the stack offset for a register, relative to thread.esp0. */
#define PT_REG(reg)	((long)&((struct pt_regs *)0)->reg)

/* Mapping from PT_xxx to the stack offset at which the register is
   saved.  Notice that usp has no stack-slot and needs to be treated
   specially (see get_reg/put_reg below). */
static int regoff[] = {
	PT_REG(r3), PT_REG(r4), PT_REG(r2), PT_REG(r1),
	PT_REG(p5), PT_REG(p4), PT_REG(p3), PT_REG(p2), PT_REG(p1), PT_REG(p0),
	PT_REG(r7), PT_REG(r6), PT_REG(r5),
	PT_REG(pc),
	PT_REG(seqstat), PT_REG(astat), PT_REG(rets),
	PT_REG(a1w),     PT_REG(a0w),   PT_REG(a1x), PT_REG(a0x),
	PT_REG(orig_r0), PT_REG(r0),
	PT_REG(usp), PT_REG(fp),
	PT_REG(ipend),
	PT_REG(syscfg)
};

/*
 * Get contents of register REGNO in task TASK.
 */
static inline long get_reg(struct task_struct *task, int regno)
{
	unsigned long *addr;
	regno /= 4;
	if (regno == PT_USP / 4)
		addr = &task->thread.usp;
	else if (regno < sizeof(regoff)/sizeof(regoff[0]))
		addr = (unsigned long *)(task->thread.esp0 + regoff[regno]);
	else
		return 0;
	return *addr;
}

/*
 * Write contents of register REGNO in task TASK.
 */
static inline int put_reg(struct task_struct *task, int regno,
			  unsigned long data)
{
	unsigned long *addr;
	regno /= 4;
	if (regno == PT_USP / 4)
		addr = &task->thread.usp;
	else if (regno < sizeof(regoff)/sizeof(regoff[0]))
		addr = (unsigned long *) (task->thread.esp0 + regoff[regno]);
	else
		return -1;
	*addr = data;
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
		ret = -ESRCH;
	if (!(child->ptrace & PT_PTRACED))
		goto out_tsk;
	if (child->state != TASK_STOPPED) {
		if (request != PTRACE_KILL)
			goto out_tsk;
	}
	ret = ptrace_check_attach(child, request == PTRACE_KILL);
	if (ret < 0)
		goto out_tsk;

	switch (request) {
	/* when I and D space are separate, these will need to be fixed. */
		case PTRACE_PEEKTEXT: /* read word at location addr. */ 
		case PTRACE_PEEKDATA: {
			unsigned long tmp;
			int copied;

			copied = access_process_vm(child, addr, &tmp, sizeof(tmp), 0);
			ret = -EIO;
			if (copied != sizeof(tmp))
				break;
			ret = put_user(tmp,(unsigned long *) data);
			break;
		}

	/* read the word at location addr in the USER area. */
		case PTRACE_PEEKUSR: {
			unsigned long tmp;
			
			ret = -EIO;
			if ((addr & 3) || addr < 0 || (addr >= sizeof(struct user_regs_struct)&&(addr!=(49*4))&&(addr!=(50*4))&&(addr!=(51*4))))
				break;

			tmp = 0;  /* Default return condition */
			addr = addr >> 2; /* temporary hack. */
			ret = -EIO;
			if (addr < 27) {
				tmp = get_reg(child, addr * 4);
			} else if (addr == 49) {
				tmp = child->mm->start_code;
			} else if (addr == 50) {
				tmp = child->mm->start_data;
			} else if (addr == 51) {
				tmp = child->mm->end_code;
			} else
				break;
			ret = put_user(tmp,(unsigned long *) data);
			break;
		}

      		/* when I and D space are separate, this will have to be fixed. */
		case PTRACE_POKETEXT: /* write the word at location addr. */
		case PTRACE_POKEDATA:
			ret = 0;
			if (access_process_vm(child, addr, &data, sizeof(data), 1) == sizeof(data))
				break;
			ret = -EIO;
			break;
		case PTRACE_POKEUSR: /* write the word at location addr in the USER area */
			ret = -EIO;
			if ((addr & 3) || addr < 0 || addr > sizeof(struct user) - 3)
				break;
		
			addr = addr >> 2; /* temporary hack. */
			if (addr == PT_SYSCFG) {
				data &= SYSCFG_MASK;
				data |= get_reg(child, PT_SYSCFG);
			}
			if (addr < 27 * 4) 
				ret = put_reg(child, addr, data);
			break;

		case PTRACE_SYSCALL: /* continue and stop at next (return from) syscall */
		case PTRACE_CONT: { /* restart after signal. */
			long tmp;

			ret = -EIO;
			if ((unsigned long) data > _NSIG)
				break;
			if (request == PTRACE_SYSCALL)
				set_tsk_thread_flag(child, TIF_SYSCALL_TRACE);
			else
				clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);

			child->exit_code = data;
			/* make sure the single step bit is not set. */
			tmp = get_reg(child, PT_SYSCFG) & ~(TRACE_BITS << 16);
			put_reg(child, PT_SYSCFG, tmp);
			wake_up_process(child);
			ret = 0;
			break;
		}

/*
 * make the child exit.  Best I can do is send it a sigkill. 
 * perhaps it should be put in the status that it wants to 
 * exit.
 */
		case PTRACE_KILL: {
			long tmp;

			ret = 0;
			if (child->state == TASK_ZOMBIE) /* already dead */
				break;
			child->exit_code = SIGKILL;
			/* make sure the single step bit is not set. */
			tmp = get_reg(child, PT_SYSCFG) & ~(TRACE_BITS << 16);
			put_reg(child, PT_SYSCFG, tmp);
			wake_up_process(child);
			break;
		}

		case PTRACE_SINGLESTEP: {  /* set the trap flag. */
			long tmp;

			ret = -EIO;
			if ((unsigned long) data > _NSIG)
				break;
			clear_tsk_thread_flag(child, TIF_SYSCALL_TRACE);

			tmp = get_reg(child, PT_SYSCFG) | (TRACE_BITS << 16);
			put_reg(child, PT_SYSCFG, tmp);

			child->exit_code = data;
			/* give it a chance to run. */
			wake_up_process(child);
			ret = 0;
			break;
		}

		case PTRACE_DETACH: { /* detach a process that was attached. */
			ret = ptrace_detach(child, data);
			break;
		}

		case PTRACE_GETREGS: {

		 /* Get all gp regs from the child. */
		  	int i;
			unsigned long tmp;
			for (i = 0; i < 42; i++) {
			    tmp = get_reg(child, i);
			    
			    if (put_user(tmp, (unsigned long *) data)) {
				ret = -EFAULT;
				break;
			    }
			    data += sizeof(long);
			}
			ret = 0;
			break;
		}

		case PTRACE_SETREGS: {

		 /* Set all gp regs in the child. */
			int i;
			unsigned long tmp;
			for (i = 0; i < 42; i++) {
			    if (get_user(tmp, (unsigned long *) data)) {
				ret = -EFAULT;
				break;
			    }
			    if (i == PT_SYSCFG) {
				tmp &= SYSCFG_MASK;
				tmp <<= 16;
				tmp |= get_reg(child, PT_SYSCFG) & ~(SYSCFG_MASK);
			    }
			    put_reg(child, i, tmp);
			    data += sizeof(long);
			}
			ret = 0;
			break;
		}
		default:
			ret = -EIO;
			break;
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
	
	current->exit_code = SIGTRAP;
	current->state = TASK_STOPPED;
	notify_parent(current, SIGCHLD);
	schedule();
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
