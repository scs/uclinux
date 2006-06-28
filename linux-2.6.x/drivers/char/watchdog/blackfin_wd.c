/*
 *	BFWD	0.01:	A Blackfin Watchdog Device Driver
 *
 *      Based on softdog.c. Original copyright messages:
 *
 *	(c) Copyright 1996 Alan Cox <alan@redhat.com>, All Rights Reserved.
 *				http://www.redhat.com
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 *	Neither Alan Cox nor CymruNet Ltd. admit liability nor provide
 *	warranty for any of this software. This material is provided
 *	"AS-IS" and at no charge.
 *
 *	(c) Copyright 1995    Alan Cox <alan@lxorguk.ukuu.org.uk>
 *
 *	Software only watchdog driver. Unlike its big brother the WDT501P
 *	driver this won't always recover a failed machine.
 *
 *  03/96: Angelo Haritsis <ah@doc.ic.ac.uk> :
 *	Modularised.
 *	Added soft_margin; use upon insmod to change the timer delay.
 *	NB: uses same minor as wdt (WATCHDOG_MINOR); we could use separate
 *	    minors.
 *
 *  19980911 Alan Cox
 *	Made SMP safe for 2.3.x
 *
 *  20011127 Joel Becker (jlbec@evilplan.org>
 *	Added soft_noboot; Allows testing the softdog trigger without
 *	requiring a recompile.
 *	Added WDIOC_GETTIMEOUT and WDIOC_SETTIMOUT.
 *
 *  20020530 Joel Becker <joel.becker@oracle.com>
 *  	Added Matt Domsch's nowayout module option.
 */

#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/config.h>
#include <linux/types.h>
#include <linux/timer.h>
#include <linux/miscdevice.h>
#include <linux/watchdog.h>
#include <linux/fs.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/init.h>
#include <asm/blackfin.h>
#include <asm/dpmc.h>
#include <asm/uaccess.h>

//#define DEBUG

#define PRINTK(l,x...)	printk(l "%s [%s] : ",__FILE__,__FUNCTION__);\
						printk(x)

#ifdef DEBUG
#define DPRINTK(l,x...)	PRINTK(l,x)
#else
#define DPRINTK(l,x...)	do { } while (0)
#endif

#define PFX "Blackfin_WD: "

#define MIN_TIME 0
#define MAX_TIME 30
#define TO_STR(_S) #_S
#define TIMER_MARGIN	20		/* Default is 60 seconds */
static int cnt_sec = TIMER_MARGIN;	/* in seconds */
module_param(cnt_sec, int, 0);
MODULE_PARM_DESC(cnt_sec, "Watchdog cnt_sec in seconds. (" TO_STR(MIN_TIME) "<cnt_sec<" TO_STR(MAX_TIME) ", default=" __MODULE_STRING(TIMER_MARGIN) ")");

#ifdef CONFIG_WATCHDOG_NOWAYOUT
static int nowayout = 1;
#else
static int nowayout = 0;
#endif

static unsigned long open_check;
static char expect_close;

module_param(nowayout, int, 0);
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started (default=CONFIG_WATCHDOG_NOWAYOUT)");

#define ICTL_RESET 0x0
#define ICTL_NMI 0x2
#define ICTL_GPIO 0x4
#define ICTL_NONE 0x6

#define ICTL_MASK 0x6

static short code2action(int code){
	switch(code){
		case 1:
			return ICTL_NMI;	
		case 2:
			return ICTL_GPIO;	
		case 3:
			return ICTL_NONE;	
		case 0:
		default:
			return ICTL_RESET;	
	}	
}

#define DEFAULT_ACTION_CODE 0
static int wd_action_code = DEFAULT_ACTION_CODE;

module_param(wd_action_code, int, 0);
MODULE_PARM_DESC(wd_action_code, "Watchdog wd_action_code, set to 0 to reboot (default) , 1 to NMI signal, 2 to GPIO signal, 3 to none");

#define WD_TMR_EN_MASK 0x0FF0
#define WD_TMR_EN_ENABLE 0x0000
#define WD_TMR_EN_DISABLE 0x0AD0


/*
 *	Watchdog operations
 */

static int wd_keepalive(void)
{
	DPRINTK(KERN_INFO," call\n");
	/*Reset watchdog counter*/
	bfin_write_WDOG_STAT(0);
	__builtin_bfin_ssync();
	return 0;
}

static int wd_stop(void)
{
	DPRINTK(KERN_INFO," call\n");
	bfin_write_WDOG_CTL((bfin_read_WDOG_CTL() & ~WD_TMR_EN_MASK) | WD_TMR_EN_DISABLE);
	__builtin_bfin_ssync();
	return 0;
}

static int wd_start(void)
{
	DPRINTK(KERN_INFO," call\n");
	bfin_write_WDOG_CTL((bfin_read_WDOG_CTL() & ~WD_TMR_EN_MASK) | WD_TMR_EN_ENABLE);
	__builtin_bfin_ssync();
	return 0;
}

static int wd_running(void){
	DPRINTK(KERN_INFO," WDOG_CTL = 0X%04X, (pWDOG_CTL & WD_TMR_EN_MASK) = 0X%04X, WD_TMR_EN_DISABLE = 0X%04X\n",
		(unsigned short)bfin_read_WDOG_CTL(), (unsigned short)(bfin_read_WDOG_CTL() & WD_TMR_EN_MASK),
		(unsigned short) WD_TMR_EN_DISABLE);
	return ((bfin_read_WDOG_CTL() & WD_TMR_EN_MASK) != WD_TMR_EN_DISABLE);
}

static spinlock_t conf_spinlock = SPIN_LOCK_UNLOCKED;

static int wd_set_heartbeat(int t)
{
	unsigned long flags;
	unsigned long cnt = 0;
	if ((t < MIN_TIME) || (t > MAX_TIME)){
		printk (KERN_WARNING PFX "cnt_sec value must be " TO_STR(MIN_TIME) "<cnt_sec<" TO_STR(MAX_TIME) ", using %d\n",
			TIMER_MARGIN);
		return -EINVAL;
	}

	cnt_sec = t;
	cnt = cnt_sec * get_sclk();
	spin_lock_irqsave(&conf_spinlock,flags);
	{
		int run = wd_running();
		wd_stop();
		bfin_write_WDOG_CNT(cnt);
		if (run) wd_start();
	}
	spin_unlock_irqrestore(&conf_spinlock,flags);
	return 0;
}

static int wd_set_action(int code){
	unsigned long flags;
	short wd_action = code2action(code);
	if (code < 0 || code > 3){
		return -EINVAL;
	}
	if (code == 1 || code == 2){
		printk (KERN_WARNING PFX " Sorry, wd_action_code %d not implemented yet.\n",code);
		return -EINVAL;
	}
	wd_action_code = code;
	spin_lock_irqsave(&conf_spinlock,flags);
	{
		int run = wd_running();
		wd_stop();
		bfin_write_WDOG_CTL((bfin_read_WDOG_CTL() & ~ICTL_MASK) | wd_action);
		if (run) wd_start();
	}
	spin_unlock_irqrestore(&conf_spinlock,flags);
	return 0;
} 

/*
 *	/dev/watchdog handling
 */

static int wd_open(struct inode *inode, struct file *file)
{
	DPRINTK(KERN_INFO," call\n");
	if(test_and_set_bit(0, &open_check))
		return -EBUSY;
	if (nowayout)
		__module_get(THIS_MODULE);
	/*
	 *	Activate timer
	 */
	wd_start();
	wd_keepalive();
	return nonseekable_open(inode, file);
}

static int wd_release(struct inode *inode, struct file *file)
{
	DPRINTK(KERN_INFO," call\n");
	/*
	 *	Shut off the timer.
	 * 	Lock it in if it's a module and we set nowayout
	 */
	if (expect_close == 42) {
		wd_stop();
	} else {
		printk(KERN_CRIT PFX "Unexpected close, not stopping watchdog!\n");
		wd_keepalive();
	}
	expect_close = 0;
	clear_bit(0, &open_check);
	return 0;
}

static ssize_t wd_write(struct file *file, const char __user *data, size_t len, loff_t *ppos)
{
	DPRINTK(KERN_INFO," call\n");
	/*
	 *	Refresh the timer.
	 */
	if(len) {
		if (!nowayout) {
			size_t i;

			/* In case it was set long ago */
			expect_close = 0;

			for (i = 0; i != len; i++) {
				char c;

				if (get_user(c, data + i))
					return -EFAULT;
				if (c == 'V')
					expect_close = 42;
			}
		}
		wd_keepalive();
	}
	return len;
}

static int wd_ioctl(struct inode *inode, struct file *file,
	unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int __user *p = argp;
	int new_margin;
	static struct watchdog_info ident = {
		.options =	WDIOF_SETTIMEOUT |
					WDIOF_KEEPALIVEPING |
					WDIOF_MAGICCLOSE,
		.firmware_version =	0,
		.identity =		"Blackfin 53X Watchdog",
	};
	DPRINTK(KERN_INFO," call\n");
	switch (cmd) {
		default:
			return -ENOIOCTLCMD;
		case WDIOC_GETSUPPORT:
			return copy_to_user(argp, &ident,
				sizeof(ident)) ? -EFAULT : 0;
		case WDIOC_GETSTATUS:
		case WDIOC_GETBOOTSTATUS:
			return put_user(0, p);
		case WDIOC_KEEPALIVE:
			wd_keepalive();
			return 0;
		case WDIOC_SETTIMEOUT:
			if (get_user(new_margin, p))
				return -EFAULT;
			if (wd_set_heartbeat(new_margin))
				return -EINVAL;
			/* Fall */
		case WDIOC_GETTIMEOUT:
			return put_user(cnt_sec, p);
	}
}

/*
 *	Notifier for system down
 */

static int wd_notify_sys(struct notifier_block *this, unsigned long code,
	void *unused)
{
	DPRINTK(KERN_INFO," call\n");
	if(code==SYS_DOWN || code==SYS_HALT) {
		/* Turn the WDT off */
		wd_stop();
	}
	return NOTIFY_DONE;
}

/*
 *	Kernel Interfaces
 */

static struct file_operations wd_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.write		= wd_write,
	.ioctl		= wd_ioctl,
	.open		= wd_open,
	.release	= wd_release,
};

static struct miscdevice wd_miscdev = {
	.minor		= WATCHDOG_MINOR,
	.name		= "watchdog",
	.fops		= &wd_fops,
};

static struct notifier_block wd_notifier = {
	.notifier_call	= wd_notify_sys,
};

static char banner[] __initdata = KERN_INFO "Blackfin Watchdog Timer: 0.01 initialized. wd_action_code=%d cnt_sec=%d sec (nowayout= %d)\n";

static int __init watchdog_init(void)
{
	int ret;

	/* Check that the cnt_sec value is within it's range ; if not reset to the default */
	if (wd_set_heartbeat(cnt_sec)) {
		wd_set_heartbeat(TIMER_MARGIN);
		printk(KERN_INFO PFX "cnt_sec value must be " TO_STR(MIN_TIME) "<cnt_sec<" TO_STR(MAX_TIME) ", using %d\n",
			TIMER_MARGIN);
	}

	/* Check that the wd_action_code value is within it's range ; if not reset to the default */
	if (wd_set_action(wd_action_code)) {
		wd_set_action(DEFAULT_ACTION_CODE);
		printk(KERN_INFO PFX "Watchdog wd_action_code must be set to 0 to reboot (default) , 1 to NMI signal, 2 to GPIO signal, 3 to none. Using %d\n",
			DEFAULT_ACTION_CODE);
	}

	ret = register_reboot_notifier(&wd_notifier);
	if (ret) {
		printk (KERN_ERR PFX "cannot register reboot notifier (err=%d)\n",
			ret);
		return ret;
	}

	ret = misc_register(&wd_miscdev);
	if (ret) {
		printk (KERN_ERR PFX "cannot register miscdev on minor=%d (err=%d)\n",
			WATCHDOG_MINOR, ret);
		unregister_reboot_notifier(&wd_notifier);
		return ret;
	}

	printk(banner, wd_action_code, cnt_sec, nowayout);

	return 0;
}

static void __exit watchdog_exit(void)
{
	misc_deregister(&wd_miscdev);
	unregister_reboot_notifier(&wd_notifier);
}

module_init(watchdog_init);
module_exit(watchdog_exit);

MODULE_AUTHOR("Michele d'Amico");
MODULE_DESCRIPTION("Blackfin Watchdog Device Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS_MISCDEV(WATCHDOG_MINOR);
