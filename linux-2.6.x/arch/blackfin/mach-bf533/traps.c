/*
 * arch/bfinnommu/mach-bf533/traps.c 
 *
 * Copyright 1999-2000 D. Jeff Dionne, <jeff@uclinux.org>
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 */
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/errno.h>
#include <linux/irq.h>
#include <asm/system.h>
#include <asm/traps.h>
#include <asm/page.h>

/*
 * void init_IRQ(void)
 *
 * Parameters:	None
 *
 * Returns:	Nothing
 *
 * This function should be called during kernel startup to initialize
 * the IRQ handling routines.
 */

unsigned long probe_irq_on (void)
{
	return 0;
}

int probe_irq_off (unsigned long irqs)
{
	return 0;
}

/*
 *	Generic dumping code. Used for panic and debug.
 */

void dump(struct pt_regs *fp)		
{
	
	printk("\nCURRENT PROCESS:\n\n");
	printk("COMM=%s PID=%d\n", current->comm, current->pid);
	if (current->mm) {
		printk("TEXT=%08x-%08x DATA=%08x-%08x BSS=%08x-%08x\n",
			(int) current->mm->start_code,
			(int) current->mm->end_code,
			(int) current->mm->start_data,
			(int) current->mm->end_data,
			(int) current->mm->end_data,
			(int) current->mm->brk);
		printk("USER-STACK=%08x\n\n",
			(int) current->mm->start_stack);
	}

	printk("PC: %08lx\n", fp->pc);
	printk("RETE:  %08lx  RETN: %08lx  RETX: %08lx  RETS: %08lx\n",
                fp->rete, fp->retn, fp->retx, fp->rets);
	printk("IPEND: %04lx  SYSCFG: %04lx\n", fp->ipend, fp->syscfg);
	printk("SEQSTAT: %08lx    SP: %08lx\n", (long) fp->seqstat, (long) fp);
	printk("R0: %08lx    R1: %08lx    R2: %08lx    R3: %08lx\n",
		fp->r0, fp->r1, fp->r2, fp->r3);
	printk("R4: %08lx    R5: %08lx    R6: %08lx    R7: %08lx\n",
		fp->r4, fp->r5, fp->r6, fp->r7);
	printk("P0: %08lx    P1: %08lx    P2: %08lx    P3: %08lx\n",
		fp->p0, fp->p1, fp->p2, fp->p3);
	printk("P4: %08lx    P5: %08lx    FP: %08lx\n",
		fp->p4, fp->p5, fp->fp);
	printk("A0.w: %08lx    A0.x: %08lx    A1.w: %08lx    A1.x: %08lx\n",
		fp->a0w, fp->a0x, fp->a1w, fp->a1x);

	printk("LB0: %08lx  LT0: %08lx  LC0: %08lx\n",
                fp->lb0, fp->lt0, fp->lc0);
        printk("LB1: %08lx  LT1: %08lx  LC1: %08lx\n",
                fp->lb1, fp->lt1, fp->lc1);
        printk("B0: %08lx  L0: %08lx  M0: %08lx  I0: %08lx\n",
                fp->b0, fp->l0, fp->m0, fp->i0);
        printk("B1: %08lx  L1: %08lx  M1: %08lx  I1: %08lx\n",
                fp->b1, fp->l1, fp->m1, fp->i1);
        printk("B2: %08lx  L2: %08lx  M2: %08lx  I2: %08lx\n",
                fp->b2, fp->l2, fp->m2, fp->i2);
        printk("B3: %08lx  L3: %08lx  M3: %08lx  I3: %08lx\n",
                fp->b3, fp->l3, fp->m3, fp->i3);


	printk("\nUSP: %08lx   ASTAT: %08lx\n",
		rdusp(), fp->astat);

	printk("\n\n");
}
