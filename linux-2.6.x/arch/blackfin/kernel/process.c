/*
 *  linux/arch/bfinnommu/kernel/process.c
 *
 *  Copyright (C) 2004 LG Soft India. 
 *
 *  uClinux changes Copyright (C) 2000, Lineo, davidm@lineo.com
 */

/*
 * This file handles the architecture-dependent parts of process handling..
 */

#include <linux/smp_lock.h>
#include <linux/unistd.h>
#include <linux/user.h>
#include <linux/a.out.h>
#include <linux/reboot.h>

#include <asm/blackfin.h>
#include <asm/uaccess.h>

#define	LED_ON	0
#define	LED_OFF	1

void leds_switch(int flag);
asmlinkage void ret_from_fork(void);

/*
 * The idle loop on BFIN 
 */
static void default_idle(void)
{
	while(1) {
		leds_switch(LED_OFF);
		while (!need_resched())
			__asm__("idle;\n\t" : : : "cc"); 
		leds_switch(LED_ON);
		schedule();
	}
}

void (*bfin_idle)(void) = default_idle;

/*
 * The idle thread. There's no useful work to be
 * done, so just try to conserve power and have a
 * low exit latency (ie sit in a loop waiting for
 * somebody to say that they'd like to reschedule)
 */
void cpu_idle(void)
{
	bfin_idle();
}

void machine_restart(char * __unused)
{
	printk("Restarting\n");
#if defined(CONFIG_BLKFIN_CACHE)
	asm("csync;");
	*pIMEM_CONTROL = 0x01;
	asm("ssync;");
#endif	
	asm("csync;");
	*pWDOG_CNT = 0x10;
	asm("ssync;");
	*pWDOG_CTL = 0xAF0;
	asm("ssync;");
}

void machine_halt(void)
{
	for (;;);
}

void machine_power_off(void)
{
	for (;;);
}

void show_regs(struct pt_regs * regs)
{
	printk(KERN_NOTICE "\n");
	printk(KERN_NOTICE "PC: %08lu  Status: %04lu  SysStatus: %04lu  RETS: %08lu\n",
	       regs->pc, regs->astat, regs->seqstat, regs->rets);
	printk(KERN_NOTICE "A0.x: %08lx  A0.w: %08lx  A1.x: %08lx  A1.w: %08lx\n",
	       regs->a0x, regs->a0w, regs->a1x, regs->a1w);
	printk(KERN_NOTICE "P0: %08lx  P1: %08lx  P2: %08lx  P3: %08lx\n",
	       regs->p0, regs->p1, regs->p2, regs->p3);
	printk(KERN_NOTICE "P4: %08lx  P5: %08lx\n",
	       regs->p4, regs->p5);
	printk(KERN_NOTICE "R0: %08lx  R1: %08lx  R2: %08lx  R3: %08lx\n",
	       regs->r0, regs->r1, regs->r2, regs->r3);
	printk(KERN_NOTICE "R4: %08lx  R5: %08lx  R6: %08lx  R7: %08lx\n",
	       regs->r4, regs->r5, regs->r6, regs->r7);

	if (!(regs->ipend))
		printk("USP: %08lx\n", rdusp());
}

/*
 * Create a kernel thread
 */
int kernel_thread(int (*fn)(void *), void * arg, unsigned long flags)
{
	long retval;
	long clone_arg = flags | CLONE_VM;
	unsigned long t_hold_sp;

	mm_segment_t fs; 
	fs = get_fs();
	set_fs(KERNEL_DS);

	__asm__ __volatile__ (
			"r1 = sp; \n\t"
			"r0 = %6; \n\t"
			"p0 = %2; \n\t"
			"excpt 0; \n\t"
			"%1 = sp; \n\t"
			"cc = %1 == r1; \n\t"
			"if cc jump 1f; \n\t"
			"r0 = %4; \n\t"	
			"SP += -12; \n\t"
			"call (%5); \n\t"
			"SP += 12; \n\t"
			"p0 = %3; \n\t"
			"excpt 0; \n"
			"1:\n\t"
			"%0 = R0;\n"
		: "=d" (retval), "=d" (t_hold_sp)
		: "i" (__NR_clone),
		  "i" (__NR_exit),
		  "a" (arg),
		  "a" (fn),
		  "a" (clone_arg)
		: "CC", "R0", "R1", "R2", "P0");

	set_fs(fs);	
	return retval;
}

void flush_thread(void)
{
	set_fs(USER_DS);
}

asmlinkage int bfin_vfork(struct pt_regs *regs)
{
	return do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, rdusp(), regs, 0, NULL, NULL );
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
	return do_fork(clone_flags & ~CLONE_IDLETASK, newsp, regs, 0, NULL, NULL); 
}

int copy_thread(int nr, unsigned long clone_flags,
		unsigned long usp, unsigned long topstk,
		struct task_struct * p, struct pt_regs * regs)
{
	struct pt_regs * childregs;
	unsigned long stack_offset;

	stack_offset = THREAD_SIZE - sizeof(struct pt_regs);
	childregs = (struct pt_regs *) ((unsigned long) p->thread_info + stack_offset);

	*childregs = *regs;
	childregs->r0 = 0;

	p->thread.usp = usp;

	/* we should be this from copy_thread and not try to construct
	 * ourselves. We'll get in trouble if we get a sys_clone from user
	 * space */

	p->thread.ksp = (unsigned long)childregs; 
	p->thread.pc = (unsigned long)ret_from_fork;

	return 0;
}

/*
 * fill in the user structure for a core dump..
 */
void dump_thread(struct pt_regs * regs, struct user * dump)
{
	dump->magic = CMAGIC;
	dump->start_code = 0;
	dump->start_stack = rdusp() & ~(PAGE_SIZE - 1);
	dump->u_tsize = ((unsigned long) current->mm->end_code) >> PAGE_SHIFT;
	dump->u_dsize = ((unsigned long) (current->mm->brk +
					  (PAGE_SIZE-1))) >> PAGE_SHIFT;
	dump->u_dsize -= dump->u_tsize;
	dump->u_ssize = 0;

	if (dump->start_stack < TASK_SIZE)
		dump->u_ssize = ((unsigned long) (TASK_SIZE - dump->start_stack)) >> PAGE_SHIFT;

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
	dump->regs.orig_r0 = regs->orig_r0;
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
	char * filename;
	struct pt_regs *regs = (struct pt_regs *) ((&name)+3);

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
		if (fp < stack_page+sizeof(struct thread_info) ||
		    fp >= 8184+stack_page)
			return 0;
		pc = ((unsigned long *)fp)[1];
		if (!in_sched_functions(pc))
			return pc;
		fp = *(unsigned long *) fp;
	} while (count++ < 16);
	return 0;
}
