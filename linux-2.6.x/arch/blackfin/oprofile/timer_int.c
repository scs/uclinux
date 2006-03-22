/**
 * @file timer_int.c
 *
 * @remark Copyright 2003 OProfile authors
 * @remark Read the file COPYING
 *
 * @author Michael.Kang <blackfin.kang@gmail.com>
 */

#include <linux/init.h>
#include <linux/smp.h>
#include <linux/irq.h>
#include <linux/oprofile.h>

#include <asm/ptrace.h>


static void enable_sys_timer0(){
}
static void disable_sys_timer0(){
}

static irqreturn_t sys_timer0_int_handler(int irq, void *dev_id, struct pt_regs *regs){
	oprofile_add_sample(regs, 0);
	return IRQ_HANDLED;
}
static int sys_timer0_start(void)
{
	enable_sys_timer0();
	int retval = request_irq(IVG11, sys_timer0_int_handler, 0,
                             "sys_timer0", NULL);
	if (retval)
        	return retval;
	return 0;
}


static void sys_timer0_stop(void)
{
	disable_sys_timer();
}


int __init sys_timer0_init(struct oprofile_operations * ops)
{
	extern int nmi_active;

	if (nmi_active <= 0)
		return -ENODEV;

	ops->start = timer_start;
	ops->stop = timer_stop;
	ops->cpu_type = "timer";
	printk(KERN_INFO "oprofile: using NMI timer interrupt.\n");
	return 0;
}
