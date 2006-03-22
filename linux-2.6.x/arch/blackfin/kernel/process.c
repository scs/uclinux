/*
 * File:         arch/blackfin/kernel/process.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:  This file handles the architecture-dependent parts
 *              of process handling.
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2005 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
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

#include <linux/module.h>
#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/user.h>
#include <linux/a.out.h>

#include <asm/blackfin.h>
#include <asm/uaccess.h>

#define	LED_ON	0
#define	LED_OFF	1

inline void static leds_switch(int flag);
asmlinkage void ret_from_fork(void);

/*
 * Powermanagement idle function, if any..
 */
void (*pm_idle)(void) = NULL;
EXPORT_SYMBOL(pm_idle);

void (*pm_power_off)(void) = NULL;
EXPORT_SYMBOL(pm_power_off);

/*
 * The idle loop on BFIN
 */
inline static void default_idle(void)
{
	while (!need_resched()) {
		leds_switch(LED_OFF);
	      __asm__("nop;\n\t \
                         nop;\n\t \
                         nop;\n\t \
                         idle;\n\t": : :"cc");
		leds_switch(LED_ON);
	}
}

void (*idle)(void) = default_idle;

/*
 * The idle thread. There's no useful work to be
 * done, so just try to conserve power and have a
 * low exit latency (ie sit in a loop waiting for
 * somebody to say that they'd like to reschedule)
 */
void cpu_idle(void)
{
	/* endless idle loop with no priority at all */
	while (1) {
		idle();
		preempt_enable_no_resched();
		schedule();
		preempt_disable();
	}
}

void machine_restart(char *__unused)
{
#if defined(CONFIG_BLKFIN_CACHE)
	*pIMEM_CONTROL = 0x01;
	__builtin_bfin_ssync();
#endif
	bfin_reset();
	/* Dont do anything till the reset occurs */
	while (1) {
		__builtin_bfin_ssync();
	}
}

void machine_halt(void)
{
	for (;;)
		/* nothing */ ;
}

void machine_power_off(void)
{
	for (;;)
		/* nothing */ ;
}

void show_regs(struct pt_regs *regs)
{
	printk(KERN_NOTICE "\n");
	printk(KERN_NOTICE
	       "PC: %08lu  Status: %04lu  SysStatus: %04lu  RETS: %08lu\n",
	       regs->pc, regs->astat, regs->seqstat, regs->rets);
	printk(KERN_NOTICE
	       "A0.x: %08lx  A0.w: %08lx  A1.x: %08lx  A1.w: %08lx\n",
	       regs->a0x, regs->a0w, regs->a1x, regs->a1w);
	printk(KERN_NOTICE "P0: %08lx  P1: %08lx  P2: %08lx  P3: %08lx\n",
	       regs->p0, regs->p1, regs->p2, regs->p3);
	printk(KERN_NOTICE "P4: %08lx  P5: %08lx\n", regs->p4, regs->p5);
	printk(KERN_NOTICE "R0: %08lx  R1: %08lx  R2: %08lx  R3: %08lx\n",
	       regs->r0, regs->r1, regs->r2, regs->r3);
	printk(KERN_NOTICE "R4: %08lx  R5: %08lx  R6: %08lx  R7: %08lx\n",
	       regs->r4, regs->r5, regs->r6, regs->r7);

	if (!(regs->ipend))
		printk("USP: %08lx\n", rdusp());
}

/*
 * This gets run with P1 containing the
 * function to call, and R1 containing
 * the "args".  Note P0 is clobbered on the way here.
 */
void kernel_thread_helper(void);
__asm__(".section .text\n"
	".align 4\n"
	"_kernel_thread_helper:\n\t"
	"\tsp += -12;\n\t"
	"\tr0 = r1;\n\t" "\tcall (p1);\n\t" "\tcall _do_exit;\n" ".previous");

/*
 * Create a kernel thread.
 */
pid_t kernel_thread(int (*fn) (void *), void *arg, unsigned long flags)
{
	struct pt_regs regs;

	memset(&regs, 0, sizeof(regs));

	regs.r1 = (unsigned long)arg;
	regs.p1 = (unsigned long)fn;
	regs.pc = (unsigned long)kernel_thread_helper;
	regs.orig_p0 = -1;
	/* Set bit 2 to tell ret_from_fork we should be returning to kernel
	   mode.  */
	regs.ipend = 0x8002;
	__asm__ __volatile__("%0 = syscfg;":"=da"(regs.syscfg):);
	return do_fork(flags | CLONE_VM | CLONE_UNTRACED, 0, &regs, 0, NULL,
		       NULL);
}

void flush_thread(void)
{
}

asmlinkage int bfin_vfork(struct pt_regs *regs)
{
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, rdusp(), regs, 0, NULL,
		       NULL);
}

asmlinkage int bfin_clone(struct pt_regs *regs)
{
	unsigned long clone_flags;
	unsigned long newsp;

	/* syscall2 puts clone_flags in r0 and usp in r1 */
	clone_flags = regs->r0;
	newsp = regs->r1;
	if (!newsp)
		newsp = rdusp();
	return do_fork(clone_flags, newsp, regs, 0, NULL, NULL);
}

int
copy_thread(int nr, unsigned long clone_flags,
	    unsigned long usp, unsigned long topstk,
	    struct task_struct *p, struct pt_regs *regs)
{
	struct pt_regs *childregs;

	childregs = (struct pt_regs *) (task_stack_page(p) + THREAD_SIZE) - 1;
	*childregs = *regs;
	childregs->r0 = 0;

	p->thread.usp = usp;
	p->thread.ksp = (unsigned long)childregs;
	p->thread.pc = (unsigned long)ret_from_fork;

	return 0;
}

/*
 * fill in the user structure for a core dump..
 */
void dump_thread(struct pt_regs *regs, struct user *dump)
{
	dump->magic = CMAGIC;
	dump->start_code = 0;
	dump->start_stack = rdusp() & ~(PAGE_SIZE - 1);
	dump->u_tsize = ((unsigned long)current->mm->end_code) >> PAGE_SHIFT;
	dump->u_dsize = ((unsigned long)(current->mm->brk +
					 (PAGE_SIZE - 1))) >> PAGE_SHIFT;
	dump->u_dsize -= dump->u_tsize;
	dump->u_ssize = 0;

	if (dump->start_stack < TASK_SIZE)
		dump->u_ssize =
		    ((unsigned long)(TASK_SIZE -
				     dump->start_stack)) >> PAGE_SHIFT;

	dump->u_ar0 = (struct user_regs_struct *)((int)&dump->regs - (int)dump);

	dump->regs.r0 = regs->r0;
	dump->regs.r1 = regs->r1;
	dump->regs.r2 = regs->r2;
	dump->regs.r3 = regs->r3;
	dump->regs.r4 = regs->r4;
	dump->regs.r5 = regs->r5;
	dump->regs.r6 = regs->r6;
	dump->regs.r7 = regs->r7;
	dump->regs.p0 = regs->p0;
	dump->regs.p1 = regs->p1;
	dump->regs.p2 = regs->p2;
	dump->regs.p3 = regs->p3;
	dump->regs.p4 = regs->p4;
	dump->regs.p5 = regs->p5;
	dump->regs.orig_p0 = regs->orig_p0;
	dump->regs.a0w = regs->a0w;
	dump->regs.a1w = regs->a1w;
	dump->regs.a0x = regs->a0x;
	dump->regs.a1x = regs->a1x;
	dump->regs.rets = regs->rets;
	dump->regs.astat = regs->astat;
	dump->regs.pc = regs->pc;
}

/*
 * sys_execve() executes a new program.
 */

asmlinkage int sys_execve(char *name, char **argv, char **envp)
{
	int error;
	char *filename;
	struct pt_regs *regs = (struct pt_regs *)((&name) + 5);

	lock_kernel();
	filename = getname(name);
	error = PTR_ERR(filename);
	if (IS_ERR(filename))
		goto out;
	error = do_execve(filename, argv, envp, regs);
	putname(filename);
      out:
	unlock_kernel();
	return error;
}

unsigned long get_wchan(struct task_struct *p)
{
	unsigned long fp, pc;
	unsigned long stack_page;
	int count = 0;
	if (!p || p == current || p->state == TASK_RUNNING)
		return 0;

	stack_page = (unsigned long)p;
	fp = p->thread.usp;
	do {
		if (fp < stack_page + sizeof(struct thread_info) ||
		    fp >= 8184 + stack_page)
			return 0;
		pc = ((unsigned long *)fp)[1];
		if (!in_sched_functions(pc))
			return pc;
		fp = *(unsigned long *)fp;
	}
	while (count++ < 16);
	return 0;
}

/*
 * We are using a different LED from the one used to indicate timer interrupt.
 */
#if defined(CONFIG_BFIN_IDLE_LED)
inline void static leds_switch(int flag)
{
	unsigned short tmp = 0;

	tmp = *(volatile unsigned short *)CONFIG_BFIN_IDLE_LED_PORT;
	__builtin_bfin_ssync();

	if (flag == LED_ON)
		tmp &= ~CONFIG_BFIN_IDLE_LED_PIN;	/* light on */
	else
		tmp |= CONFIG_BFIN_IDLE_LED_PIN;	/* light off */

	*(volatile unsigned short *)CONFIG_BFIN_IDLE_LED_PORT = tmp;
	__builtin_bfin_ssync();

}
#else
inline void static leds_switch(int flag)
{
}
#endif
