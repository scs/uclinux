/*
 * linux/arch/$(ARCH)/platform/$(PLATFORM)/traps.c -- general exception handling code
 *
 * Cloned from Linux/m68k.
 *
 * No original Copyright holder listed,
 * Probabily original (C) Roman Zippel (assigned DJD, 1999)
 *
 * Copyright 2003 Metrowerks - for Blackfin
 * Copyright 2000-2001 Lineo, Inc. D. Jeff Dionne <jeff@lineo.ca>
 * Copyright 1999-2000 D. Jeff Dionne, <jeff@uclinux.org>
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 */

/* This #define is to cause the variables interruptFlags and interruptEnable
   to be defined ...MaTed--- */
#define DEF_INTERRUPT_FLAGS 1

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/kernel_stat.h>
#include <linux/errno.h>
#include <linux/irq.h>

#include <asm/system.h>
#include <asm/traps.h>
#include <asm/page.h>
#include <asm/machdep.h>

/* table for system interrupt handlers */
static irq_handler_t irq_list[SYS_IRQS];

static const char *default_names[SYS_IRQS] = {
	"spurious int", "int1 handler", "int2 handler", "int3 handler",
	"int4 handler", "int5 handler", "int6 handler", "int7 handler"
};

/* The number of spurious interrupts */
volatile unsigned int num_spurious;

#define NUM_IRQ_NODES 16
static irq_node_t nodes[NUM_IRQ_NODES];

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

void init_IRQ(void)
{
	mach_init_IRQ ();
}

irq_node_t *new_irq_node(void)
{
	irq_node_t *node;
	short i;

	for (node = nodes, i = NUM_IRQ_NODES-1; i >= 0; node++, i--)
		if (!node->handler)
			return node;

	printk ("new_irq_node: out of nodes\n");
	return NULL;
}


int request_irq(unsigned int irq, int (*handler)(int, void *, struct pt_regs *),unsigned long flags,const char *devname,void *dev_id)
{
	if (irq)
		return mach_request_irq(irq, handler, flags, devname, dev_id);

	if (irq < IRQ_EMU || irq > IRQ_SW_INT2) {
		printk("%s: Incorrect IRQ %d from %s\n", __FUNCTION__, irq, devname);
		return -ENXIO;
	}

	if (!(irq_list[irq].flags & IRQ_FLG_STD)) {
		if (irq_list[irq].flags & IRQ_FLG_LOCK) {
			printk("%s: IRQ %d from %s is not replaceable\n",
			       __FUNCTION__, irq, irq_list[irq].devname);
			return -EBUSY;
		}
		if (flags & IRQ_FLG_REPLACE) {
			printk("%s: %s can't replace IRQ %d from %s\n",
			       __FUNCTION__, devname, irq, irq_list[irq].devname);
			return -EBUSY;
		}
	}
	irq_list[irq].handler = handler;
	irq_list[irq].flags   = flags;
	irq_list[irq].dev_id  = dev_id;
	irq_list[irq].devname = devname;
	return 0;
}

void free_irq(unsigned int irq, void *dev_id)
{
	if (irq) {
		mach_free_irq(irq, dev_id);
		return;
	}

	if (irq < IRQ_EMU || irq > IRQ_SW_INT2) {
		printk("%s: Incorrect IRQ %d\n", __FUNCTION__, irq);
		return;
	}

	if (irq_list[irq].dev_id != dev_id)
		printk("%s: Removing probably wrong IRQ %d from %s\n",
		       __FUNCTION__, irq, irq_list[irq].devname);

	if (mach_default_handler)
		irq_list[irq].handler = (*mach_default_handler)[irq];
	else
		irq_list[irq].handler = NULL;
	irq_list[irq].flags   = IRQ_FLG_STD;
	irq_list[irq].dev_id  = NULL;
	irq_list[irq].devname = default_names[irq];
}

unsigned long probe_irq_on (void)
{
	return 0;
}

int probe_irq_off (unsigned long irqs)
{
	return 0;
}

asmlinkage void process_int(unsigned long vec, struct pt_regs *fp)
{
                if (mach_process_int)
                        mach_process_int(vec, fp);
                else
                        panic("Can't process interrupt vector %ld\n", vec);
                return;
}

/*
 *	Generic dumping code. Used for panic and debug.
 */

void dump(struct pt_regs *fp)		/*BFin*/
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
