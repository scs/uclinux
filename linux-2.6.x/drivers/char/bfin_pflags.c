/*
 * File:         drivers/char/bfin_pflags.c
 * Based on:
 * Author:       Bas Vermeulen, Luuk van Dijk <lvd@mndmttr.nl>
 *
 * Created:      Tue Apr 20 10:53:12 CEST 2004
 * Description:  pfbits driver for bf53x
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright (C) 2004 Luuk van Dijk/BuyWays B.V.
 * Jan 10, 2005  Changed Michael Hennerich
 * Apr 20, 2005  Changed added PROC entry Michael Hennerich
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

/*
   BF533 STAMP Board Connections are made as follows:
   PF2 -> GUI_LED1
   PF3 -> GUI_LED2
   PF4 -> GUI_LED3
   GUI_BUT1 -> PF5
   GUI_BUT2 -> PF6
   LAN_IRQ -> PF7
   GUI_BUT3 -> PF8

   BF537 STAMP Board Connections are made as follows:
   PF6 -> GUI_LED1
   PF7 -> GUI_LED2
   PF8 -> GUI_LED3
   PF9 -> GUI_LED4
   PF10-> GUI_LED5
   PF11-> GUI_LED6
   GUI_BUT1 -> PF2
   GUI_BUT2 -> PF3
   GUI_BUT3 -> PF4
   GUI_BUT4 -> PF5
 */

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/poll.h>
#include <asm/uaccess.h>
#include <asm/blackfin.h>
#include <asm/irq.h>
#include <linux/proc_fs.h>
#include "bfin_pflags.h"

#undef	DEBUG
//#define DEBUG

#undef ENABLE_POLL
//#define ENABLE_POLL

#ifdef DEBUG
# define DPRINTK(x...)	printk(KERN_DEBUG x)
#else
# define DPRINTK(x...)	do { } while (0)
#endif

#define PFLAG_MAJOR 253		//experimental

/* 0 / 1 meaning 0=input, 1=output *
 *                111111           *
 *                5432109876543210 */
#define PINCONF 0b0000000000011100

#ifdef ENABLE_POLL
static wait_queue_head_t pflags_in_waitq;
static short pflags_laststate = 0;
static short pflags_statechanged = 0;
static unsigned int pflags_poll(struct file *filp,
				struct poll_table_struct *wait);
static irqreturn_t pflags_irq_handler(int irq, void *dev_id,
				      struct pt_regs *regs);
#endif

static int pflags_ioctl(struct inode *inode, struct file *filp, uint cmd,
			unsigned long arg);
static int pflags_proc_output(char *buf);
static int pflags_read_proc(char *page, char **start, off_t off, int count,
			    int *eof, void *data);
static int check_minor(struct inode *inode);
static int pflags_open(struct inode *inode, struct file *filp);
static ssize_t pflags_read(struct file *filp, char *buf, size_t size,
			   loff_t * offp);
static int pflags_release(struct inode *inode, struct file *filp);
static ssize_t pflags_write(struct file *filp, const char *buf, size_t size,
			    loff_t * offp);

/* return the minor number or -ENODEV */

static int check_minor(struct inode *inode)
{
	int minor = MINOR(inode->i_rdev);

	if (minor > 15)
		return -ENODEV;

	return minor;

}

/***********************************************************
*
* FUNCTION NAME :pflags_open
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
* in_filp - Description of openned file.
* 
* RETURN
* 0: Open ok.
* -ENXIO  No such device
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED:
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'open' system call
*              to open spi device.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int pflags_open(struct inode *inode, struct file *filp)
{
	if (check_minor(inode) < 0)
		return -ENODEV;

#if defined(CONFIG_BF534) || defined(CONFIG_BF536) || defined(CONFIG_BF537)
	bfin_write_PORT_FER(bfin_read_PORT_FER() & ~(1 << MINOR(inode->i_rdev)));
#endif

	return 0;
}

static int pflags_release(struct inode *inode, struct file *filp)
{
	if (check_minor(inode) < 0)
		return -ENODEV;
	return 0;
}

/***********************************************************
*
* FUNCTION NAME :pflags_read
*
* INPUTS/OUTPUTS:
* in_filp - Description of openned file.
* in_count - how many bytes user wants to get.
* out_buf - data would be write to this address.
* 
* RETURN
* positive number: bytes read back 
* -ENODEV When minor not available.
* -EMSGSIZE When size more than a single ASCII digit followed by /n.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: 
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'read' system call
*              to read from system.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static ssize_t
pflags_read(struct file *filp, char *buf, size_t size, loff_t * offp)
{
	const char *bit;
	int minor = check_minor(filp->f_dentry->d_inode);

	DPRINTK("pfbits driver for bf53x minor = %d\n", minor);

	if (minor < 0)
		return -ENODEV;

	if (size < 2)
		return -EMSGSIZE;

	bit = (bfin_read_FIO_FLAG_D() & (1 << minor)) ? "1" : "0";

	return (copy_to_user(buf, bit, 2)) ? -EFAULT : 2;

}

/***********************************************************
*
* FUNCTION NAME :pflags_write
*
* INPUTS/OUTPUTS:
* in_filp - Description of openned file.
* in_count - how many bytes user wants to send.
* out_buf - where we get those sending data.
* 
* RETURN
* positive number: bytes sending out.
* 0: There is no data send out or parameter error.
* RETURN
* positive number: bytes read back 
* -ENODEV When minor not available.
* -EMSGSIZE When size more than a single ASCII digit followed by /n.
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED:
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: It is invoked when user call 'Write' system call
*              to write from system.
*              
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static ssize_t
pflags_write(struct file *filp, const char *buf, size_t size, loff_t * offp)
{

	int minor = check_minor(filp->f_dentry->d_inode);

	volatile unsigned short *set_or_clear;

	DPRINTK("pfbits driver for bf53x minor = %d\n", minor);

	if (minor < 0)
		return -ENODEV;

	if (size < 2)
		return -EMSGSIZE;

	if (!buf)
		return -EFAULT;

	set_or_clear = (buf[0] == '0') ?
		((volatile unsigned short *)FIO_FLAG_C) :
		((volatile unsigned short *)FIO_FLAG_S);

	*set_or_clear = (1 << minor);

	return size;

}

#ifdef ENABLE_POLL
static unsigned int pflags_poll(struct file *filp,
				struct poll_table_struct *wait)
{

	int minor = check_minor(filp->f_dentry->d_inode);

	int changed = 0;

	unsigned int mask = 0;

	if (minor < 0)
		return -ENODEV;

//	bfin_write_FIO_MASKA_C(bfin_read_FIO_MASKA_C() | (1 << minor));
	bfin_write_FIO_MASKA_S(bfin_read_FIO_MASKA_S() | (1 << minor));
	bfin_write_FIO_INEN(bfin_read_FIO_INEN() | (1 << minor));

	if (filp->f_mode & FMODE_READ) {

		do {

			/* attention! this wakes up when /any/ of the flags changes */
			poll_wait(filp, &pflags_in_waitq, wait);

			changed = pflags_statechanged & (1 << minor);

		} while (!changed);

		mask |= POLLIN | POLLRDNORM;

	}

	/* we can always write */
	if (filp->f_mode & FMODE_WRITE)
		mask |= POLLOUT | POLLWRNORM;

	return mask;
}

static irqreturn_t pflags_irq_handler(int irq, void *dev_id,
				      struct pt_regs *regs)
{

	short pflags_nextstate;

	pflags_nextstate = bfin_read_FIO_FLAG_D();
	/* FIXME: Clear only status of flag pin that caused the interrupt */
	bfin_write_FIO_FLAG_C(0xFFFF);	/* clear irq status on interrupt lines */

	DPRINTK("pflags_irq_handler\n");

	pflags_statechanged = pflags_laststate ^ pflags_nextstate;
	pflags_laststate = pflags_nextstate;

	wake_up(&pflags_in_waitq);

	return IRQ_HANDLED;

}
#endif

static struct file_operations pflags_fops = {
      .read    = pflags_read,
      .write   = pflags_write,
      .ioctl   = pflags_ioctl,
      .open    = pflags_open,
      .release = pflags_release,
#ifdef ENABLE_POLL
      .poll    = pflags_poll
#endif
};

static int __init blackfin_pflags_init(void)
{
	register_chrdev(PFLAG_MAJOR, "pflag", &pflags_fops);

	create_proc_read_entry("driver/pflags", 0, 0, pflags_read_proc, NULL);

	/* FIXME: Remove following two lines as soon the default config has changed in u-boot */
	bfin_write_FIO_MASKA_C((PF8 | PF6 | PF5));
	bfin_write_FIO_EDGE(bfin_read_FIO_EDGE() & ~(PF8 | PF6 | PF5));

#ifdef ENABLE_POLL
	if (request_irq(IRQ_PROG_INTA, pflags_irq_handler, SA_INTERRUPT, "pflags", NULL)) {
		printk(KERN_WARNING "pflags: IRQ %d is not free.\n", IRQ_PROG_INTA);
		return -EIO;
	}
	init_waitqueue_head(&pflags_in_waitq);
	pflags_laststate = bfin_read_FIO_FLAG_D();
	pflags_statechanged = 0xffff;
	printk(KERN_INFO "pfx: pfbits driver for bf53x IRQ %d\n", IRQ_PROG_INTA);
#else
	printk(KERN_INFO "pfx: pfbits driver for bf53x\n");
#endif
//	enable_irq(IRQ_PROG_INTA);

	return 0;
}

void __exit blackfin_plags_exit(void)
{
	remove_proc_entry("driver/pflags", NULL);
}

module_init(blackfin_pflags_init);
module_exit(blackfin_plags_exit);

/*
 *  Info exported via "/proc/driver/pflags".
 */

static int pflags_proc_output(char *buf)
{
	char *p;
	unsigned short i, data, dir, maska, maskb, polar, edge, inen, both;
	p = buf;

	data = bfin_read_FIO_FLAG_D();
	dir = bfin_read_FIO_DIR();
	maska = bfin_read_FIO_MASKA_D();
	maskb = bfin_read_FIO_MASKB_D();
	polar = bfin_read_FIO_POLAR();
	both = bfin_read_FIO_BOTH();
	edge = bfin_read_FIO_EDGE();
	inen = bfin_read_FIO_INEN();

	p += sprintf(p, "FIO_DIR \t: = 0x%X\n", dir);
	p += sprintf(p, "FIO_MASKA\t: = 0x%X\n", maska);
	p += sprintf(p, "FIO_MASKB\t: = 0x%X\n", maskb);
	p += sprintf(p, "FIO_POLAR\t: = 0x%X\n", polar);
	p += sprintf(p, "FIO_EDGE \t: = 0x%X\n", edge);
	p += sprintf(p, "FIO_INEN \t: = 0x%X\n", inen);
	p += sprintf(p, "FIO_BOTH \t: = 0x%X\n", both);
	p += sprintf(p, "FIO_FLAG_D\t: = 0x%X\n", data);
	p += sprintf(p, "PIN\t:DATA DIR INEN EDGE BOTH POLAR MASKA MASKB\n");
	p += sprintf(p, "   \t:H/L  O/I D/E  E/L  B/S   L/H   S/C   S/C\n");

	for (i = 0; i < 16; i++)
		p += sprintf(p,
			     "PF%d\t: %d....%d....%d....%d....%d....%d.....%d.....%d \n",
			     i, ((data >> i) & 1), ((dir >> i) & 1),
			     ((inen >> i) & 1), ((edge >> i) & 1),
			     ((both >> i) & 1), ((polar >> i) & 1),
			     ((maska >> i) & 1), ((maskb >> i) & 1));

	return p - buf;
}

static int
pflags_read_proc(char *page, char **start, off_t off,
		 int count, int *eof, void *data)
{
	int len = pflags_proc_output(page);
	if (len <= off + count)
		*eof = 1;
	*start = page + off;
	len -= off;
	if (len > count)
		len = count;
	if (len < 0)
		len = 0;
	return len;
}

/***********************************************************
*
* FUNCTION NAME :pflags_ioctl
*
* INPUTS/OUTPUTS:
* in_inode - Description of openned file.
* in_filp - Description of openned file.
* in_cmd - Command passed into ioctl system call.
* in/out_arg - It is parameters which is specified by last command
*
* RETURN:
* 0 OK
* -EINVAL
*
* FUNCTION(S) CALLED:
*
* GLOBAL VARIABLES REFERENCED: 
*
* GLOBAL VARIABLES MODIFIED: NIL
*
* DESCRIPTION: 
* 
* CAUTION:
*************************************************************
* MODIFICATION HISTORY :
**************************************************************/
static int
pflags_ioctl(struct inode *inode, struct file *filp, uint cmd,
	     unsigned long arg)
{

	int minor = check_minor(filp->f_dentry->d_inode);

	if (minor < 0)
		return -ENODEV;

	DPRINTK("pfbits driver for bf53x minor = %d\n", minor);

	switch (cmd) {
	case SET_FIO_DIR:
		{
			DPRINTK("pflags_ioctl: SET_FIO_DIR\n");

			if (arg)	// OUTPUT
				bfin_write_FIO_DIR(bfin_read_FIO_DIR() | (1 << minor));
			else	// INPUT
				bfin_write_FIO_DIR(bfin_read_FIO_DIR() & ~(1 << minor));

			break;
		}
	case SET_FIO_POLAR:
		{
			DPRINTK("pflags_ioctl: SET_FIO_POLAR \n", arg);

			if (arg)	// ACTIVELOW_FALLINGEDGE
				bfin_write_FIO_POLAR(bfin_read_FIO_POLAR() | (1 << minor));
			else	// ACTIVEHIGH_RISINGEDGE
				bfin_write_FIO_POLAR(bfin_read_FIO_POLAR() & ~(1 << minor));

			break;
		}
	case SET_FIO_EDGE:
		{
			DPRINTK("pflags_ioctl: SET_FIO_EDGE\n");

			if (arg)	// EDGE
				bfin_write_FIO_EDGE(bfin_read_FIO_EDGE() | (1 << minor));
			else	// LEVEL
				bfin_write_FIO_EDGE(bfin_read_FIO_EDGE() & ~(1 << minor));

			break;
		}
	case SET_FIO_BOTH:
		{
			DPRINTK("pflags_ioctl: SET_FIO_BOTH\n");

			if (arg)	// BOTHEDGES
				bfin_write_FIO_BOTH(bfin_read_FIO_BOTH() | (1 << minor));
			else	// SINGLEEDGE
				bfin_write_FIO_BOTH(bfin_read_FIO_BOTH() & ~(1 << minor));

			break;
		}
	case SET_FIO_INEN:
		{
			DPRINTK("pflags_ioctl: SET_FIO_INEN\n");

			if (arg)	// OUTPUT_ENABLE
				bfin_write_FIO_INEN(bfin_read_FIO_INEN() | (1 << minor));
			else	// INPUT_DISABLE
				bfin_write_FIO_INEN(bfin_read_FIO_INEN() & ~(1 << minor));

			break;
		}
	default:
		return -EINVAL;
	}

	return 0;
}
