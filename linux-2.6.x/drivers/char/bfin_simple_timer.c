/***************************************************************************
	Simple timer driver

	Author: (C) 2006 by Axel Weiss (awe@aglaia-gmbh.de)

	This is a simple char-device interface driver for the bf5xx_timers driver.
	It primarily serves as an example for how to use the hardware drivers
	on blackfin, but may also be used as a starting point of development
	for more sophisticated driver frontends.

	Behaviour
	With this driver, a device node /dev/bf5xx_timer[0...] with major number
	238 and minor number 0... can be used to access one of blackfin's internal
	hardware timer. After open(), the timer may be accessed via ioctl:
		BFIN_SIMPLE_TIMER_SET_PERIOD: set timer period (in microseconds)
		BFIN_SIMPLE_TIMER_START: start timer
		BFIN_SIMPLE_TIMER_STOP: stop timer
		BFIN_SIMPLE_TIMER_READ: read the numbers of periods (irq-count)
	This driver enables
		sysclk input
		no physical timer output (OUT_DIS is set)
		free running from start
		timer interrupt, counting
	The driver opens a (ro) file at /proc/bfin_simple_timer that shows the
	irq count values for all timers.

 ***************************************************************************/

/***************************************************************************
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 ***************************************************************************/

#include <linux/config.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/interrupt.h>
#include <asm/bf5xx_timers.h>
#include <asm/irq.h>
#include <asm/bfin_simple_timer.h>
#include <asm/bfin-global.h>

#define AUTHOR "Axel Weiss (awe@aglaia-gmbh.de)"
#define DESCRIPTION "simple timer char-device interface for the bf5xx_timers driver"
#define LICENSE "GPL"
#define TIMER_MAJOR 238

#define DPRINTK(fmt, args...) printk(KERN_NOTICE "%s: " fmt, __FUNCTION__ , ## args)
#define DRV_NAME            "bfin_simple_timer"

MODULE_AUTHOR     (AUTHOR);
MODULE_DESCRIPTION(DESCRIPTION);
MODULE_LICENSE    (LICENSE);

#if defined(BF533_FAMILY) || defined(BF537_FAMILY) 
#define IRQ_TIMER0    IRQ_TMR0 	/*Timer 0 */
#define IRQ_TIMER1    IRQ_TMR1 	/*Timer 1 */
#define IRQ_TIMER2    IRQ_TMR2 	/*Timer 2 */
#if (MAX_BLACKFIN_GPTIMERS > 3)
#define IRQ_TIMER3    IRQ_TMR3 	/*Timer 3 */
#define IRQ_TIMER4    IRQ_TMR4 	/*Timer 4 */
#define IRQ_TIMER5    IRQ_TMR5 	/*Timer 5 */
#define IRQ_TIMER6    IRQ_TMR6 	/*Timer 6 */
#define IRQ_TIMER7    IRQ_TMR7 	/*Timer 7 */
#endif
#endif

static unsigned long sysclk = 0;
module_param(sysclk, long, 0);
MODULE_PARM_DESC(sysclk, "actual SYSCLK frequency in Hz. Default: 120000000 = 120 MHz.");

static volatile unsigned long isr_count[MAX_BLACKFIN_GPTIMERS];
static const struct {
	unsigned short id, bit;
	unsigned long irqbit;
	int irq;
} timer_code[MAX_BLACKFIN_GPTIMERS] = {
	{TIMER0_id,  TIMER0bit,  TIMER_STATUS_TIMIL0,  IRQ_TIMER0},
	{TIMER1_id,  TIMER1bit,  TIMER_STATUS_TIMIL1,  IRQ_TIMER1},
	{TIMER2_id,  TIMER2bit,  TIMER_STATUS_TIMIL2,  IRQ_TIMER2},
#if (MAX_BLACKFIN_GPTIMERS > 3)
	{TIMER3_id,  TIMER3bit,  TIMER_STATUS_TIMIL3,  IRQ_TIMER3},
	{TIMER4_id,  TIMER4bit,  TIMER_STATUS_TIMIL4,  IRQ_TIMER4},
	{TIMER5_id,  TIMER5bit,  TIMER_STATUS_TIMIL5,  IRQ_TIMER5},
	{TIMER6_id,  TIMER6bit,  TIMER_STATUS_TIMIL6,  IRQ_TIMER6},
	{TIMER7_id,  TIMER7bit,  TIMER_STATUS_TIMIL7,  IRQ_TIMER7},
#endif
#if (MAX_BLACKFIN_GPTIMERS > 8)
	{TIMER8_id,  TIMER8bit,  TIMER_STATUS_TIMIL8,  IRQ_TIMER8},
	{TIMER9_id,  TIMER9bit,  TIMER_STATUS_TIMIL9,  IRQ_TIMER9},
	{TIMER10_id, TIMER10bit, TIMER_STATUS_TIMIL10, IRQ_TIMER10},
	{TIMER11_id, TIMER11bit, TIMER_STATUS_TIMIL11, IRQ_TIMER11},
#endif
};

static int timer_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg){
	int minor = MINOR(inode->i_rdev);
	unsigned long n;
	switch (cmd){
	case BFIN_SIMPLE_TIMER_SET_PERIOD:
		if (arg < 2) return -EFAULT;
		n = ((sysclk / 1000) * arg) / 1000;
		if (n > 0xFFFF) n = 0xFFFF;
		set_gptimer_period(timer_code[minor].id, n);
		set_gptimer_pwidth(timer_code[minor].id, n >> 1);
		printk("timer_ioctl TIMER_SET_PERIOD: arg=%lu, period=%lu, width=%lu\n",
			arg, n, n>>1);
		break;
	case BFIN_SIMPLE_TIMER_START:
		enable_gptimers(timer_code[minor].bit);
		break;
	case BFIN_SIMPLE_TIMER_STOP:
		disable_gptimers(timer_code[minor].bit);
		break;
	case BFIN_SIMPLE_TIMER_READ:
		*((unsigned long*)arg) = isr_count[minor];
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

static irqreturn_t timer_isr(int irq, void *dev_id, struct pt_regs *regs){
	int minor = (int)dev_id;
#if (MAX_BLACKFIN_GPTIMERS > 8)
	int octet = BFIN_TIMER_OCTET(minor);
	unsigned long state = get_gptimer_status(octet);
	if (state & timer_code[minor].irqbit){
		set_gptimer_status(octet, timer_code[minor].irqbit);
		++isr_count[minor];
	}
#else
	unsigned long state = get_gptimer_status(0);
	if (state & timer_code[minor].irqbit){
		set_gptimer_status(0,timer_code[minor].irqbit);
		++isr_count[minor];
	}
#endif
	return IRQ_HANDLED;
}

static int timer_open(struct inode *inode, struct file *filp){
	int minor = MINOR(inode->i_rdev);
	int err = 0;
	if(!sysclk)
	  sysclk = get_sclk();
	if (minor >= MAX_BLACKFIN_GPTIMERS) return -ENODEV;
	err = request_irq(timer_code[minor].irq, (void*)timer_isr, SA_INTERRUPT, DRV_NAME, (void*)minor);
	if (err < 0){
		printk(KERN_ERR "request_irq(%d) failed\n", timer_code[minor].irq);
		return err;
	}
	set_gptimer_config(timer_code[minor].id, OUT_DIS | PWM_OUT | PERIOD_CNT | IRQ_ENA);
	DPRINTK("device(%d) opened\n", minor);
	return 0;
}

static int timer_close(struct inode *inode, struct file *filp){
	int minor = MINOR(inode->i_rdev);
	disable_gptimers(timer_code[minor].bit);
	free_irq(timer_code[minor].irq, (void*)minor);
	DPRINTK("device(%d) closed\n", minor);
	return 0;
}

int timer_read_proc(char *buf, char **start, off_t offset, int cnt, int *eof, void *data){
	int ret = 0, i;
	for (i=0; i<MAX_BLACKFIN_GPTIMERS; ++i){
		ret += sprintf(buf + ret, "timer %2d isr count: %lu\n", i, isr_count[i]);
	}
	return ret;
}

static struct proc_dir_entry *timer_dir_entry;
static struct file_operations fops = {
   .owner   = THIS_MODULE,
   .ioctl   = timer_ioctl,
   .open    = timer_open,
   .release = timer_close,
};

int __init timer_initialize(void){
	int err;
	err = register_chrdev(TIMER_MAJOR, DRV_NAME, &fops);
	if (err < 0){
		DPRINTK("could not register device %s\n", DRV_NAME);
		return err;
	}
	timer_dir_entry = create_proc_entry(DRV_NAME, 0444, &proc_root);
	if (timer_dir_entry) timer_dir_entry->read_proc = &timer_read_proc;
	DPRINTK("module loaded\n");
	return 0;
}

void __exit timer_cleanup(void){
	remove_proc_entry(DRV_NAME, &proc_root);
	unregister_chrdev(TIMER_MAJOR, DRV_NAME);
	DPRINTK("module unloaded\n");
}

module_init(timer_initialize);
module_exit(timer_cleanup);
