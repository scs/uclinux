/*
 * File:
 * Based on:
 * Author:       Michael Hennerich
 *
 * Created:
 * Description:
 *
 *
 * Modified:
 *               Copyright 2008 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/miscdevice.h>
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/dma.h>
#include <asm/cacheflush.h>
#include <asm/portmux.h>
#include <asm/gpio.h>
#include <asm/delay.h>

/************************************************************/

/* definitions */

#define DEFAULT_PPICONFIG (DLEN_8 | PACK_EN | XFR_TYPE)

#define PPI0_MINOR         248

#define PPI_DEVNAME       "PPI hs_conv"
#define PPI_INTNAME       "IRQ PPI hs_conv"	/* Should be less than 19 chars. */

#define WRDACRAM GPIO_PG9

#define ppi_debug pr_debug

/************************************************************/

typedef struct PPI_Device_t {
	int opened;
	int nonblock;
	unsigned short irqnum;
	unsigned short done;
	unsigned short dma_config;
	unsigned short ppi_control;
	unsigned short ppi_status;
	unsigned short ppi_delay;
	short ppi_trigger_gpio;
	struct fasync_struct *fasyc;
	wait_queue_head_t *rx_avail;
} ppi_device_t;

u16 hs_conv_ppi_req[] = {P_PPI0_CLK, P_PPI0_FS1, P_PPI0_FS2, P_PPI0_D0,\
	 P_PPI0_D1, P_PPI0_D2, P_PPI0_D3, P_PPI0_D4, P_PPI0_D5, P_PPI0_D6,\
	 P_PPI0_D7, 0};

/************************************************************/

/* Globals */

static DECLARE_WAIT_QUEUE_HEAD(ppirxq0);
static ppi_device_t ppiinfo;
static DEFINE_SPINLOCK(hs_conv_lock);

/*
 * FUNCTION NAME: hs_conv_reg_reset
 *
 * INPUTS/OUTPUTS:
 * in_idev - device number , other unavailable.
 * VALUE RETURNED:
 * void
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES REFERENCED:
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: Reset PPI to initialization state.
 *
 * CAUTION:
 */
void hs_conv_reg_reset(ppi_device_t *pdev)
{
/* Do some initializaion stuff here based on the defined Camera Module
   so we don't have to use ioctls                     */

	bfin_clear_PPI_STATUS();

	bfin_write_PPI_DELAY(pdev->ppi_delay);
	bfin_write_PPI_FRAME(1);

	return;

}

/*
 * FUNCTION NAME: hs_conv_irq
 *
 * INPUTS/OUTPUTS:
 * in_irq - Interrupt vector number.
 * in_dev_id  - point to device information structure base address.
 * in_regs - unuse here.
 *
 * VALUE RETURNED:
 * void
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES REFERENCED: ppiinfo
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: ISR of PPI
 *
 * CAUTION:
 */
static irqreturn_t hs_conv_irq(int irq, void *dev_id, struct pt_regs *regs)
{
	ppi_device_t *pdev = (ppi_device_t *) dev_id;


	udelay(10);
	ppi_debug("hs_conv_irq:\n");
	ppi_debug(":hs_conv_irq: X_COUNT = %d PPI Status = 0x%X\n",bfin_read_DMA0_CURR_X_COUNT(), bfin_read_PPI_STATUS());
	/* Acknowledge DMA Interrupt */
	clear_dma_irqstat(CH_PPI);

	/* disable ppi */

	bfin_write_PPI_CONTROL(pdev->ppi_control & ~PORT_EN);

	pdev->done = 1;

	/* Give a signal to user program. */
	if (pdev->fasyc)
		kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);

	ppi_debug("hs_conv_irq: wake_up_interruptible pdev->done=%d\n",
		pdev->done);

	/* wake up read */

	wake_up_interruptible(pdev->rx_avail);

	ppi_debug("hs_conv_irq: return\n");

	return IRQ_HANDLED;
}

#ifdef USE_PPI_ERROR_IRQ
static irqreturn_t hs_conv_irq_error(int irq, void *dev_id, struct pt_regs *regs)
{
	ppi_device_t *pdev = (ppi_device_t *) dev_id;

	udelay(10);

	ppi_debug(":hs_conv_irq_error: X_COUNT = %d PPI Status = 0x%X\n",bfin_read_DMA0_CURR_X_COUNT(), bfin_read_PPI_STATUS());

	bfin_clear_PPI_STATUS();

	/* Acknowledge DMA Interrupt */
	clear_dma_irqstat(CH_PPI);

	/* disable ppi */

	bfin_write_PPI_CONTROL(pdev->ppi_control & ~PORT_EN);

	pdev->done = 1;

	/* Give a signal to user program. */
	if (pdev->fasyc)
		kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);

	ppi_debug("hs_conv_error_irq: wake_up_interruptible pdev->done=%d\n",
		pdev->done);
	/* wake up read */

	wake_up_interruptible(pdev->rx_avail);

	ppi_debug("hs_conv_error_irq: return\n");

	return IRQ_HANDLED;
}
#endif

/*
 * FUNCTION NAME: hs_conv_ppi_ioctl
 *
 * INPUTS/OUTPUTS:
 * in_inode - Description of openned file.
 * in_filp - Description of openned file.
 * in_cmd - Command passed into ioctl system call.
 * in/out_arg - It is parameters which is specified by last command
 *
 * RETURN:
 * 0 OK
 * -EINVAL  Invalid
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES REFERENCED: ppiinfo
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION:
 *
 * CAUTION:
 */
static int hs_conv_ppi_ioctl(struct inode *inode, struct file *filp, uint cmd,
		     unsigned long arg)
{
	/*ppi_device_t *pdev = filp->private_data;*/

	switch (cmd) {

	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * FUNCTION NAME: hs_conv_fasync
 *
 * INPUTS/OUTPUTS:
 * in_fd - File descriptor of openned file.
 * in_filp - Description of openned file.
 *
 * RETURN:
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES REFERENCED: ppiinfo
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: It is invoked when user changes status of sync
 *              it resister a hook in system. When there is
 *              data coming, user program would get a signal.
 *
 * CAUTION:
 */
static int hs_conv_fasync(int fd, struct file *filp, int on)
{
	ppi_device_t *pdev = filp->private_data;
	return fasync_helper(fd, filp, on, &(pdev->fasyc));
}

/*
 * FUNCTION NAME: hs_conv_ppi_read
 *
 * INPUTS/OUTPUTS:
 * in_filp - Description of openned file.
 * in_count - how many bytes user wants to get.
 * out_buf - data would be write to this address.
 *
 * RETURN
 * positive number: bytes read back
 * -EINVIL When word size is set to 16, reading odd bytes.
 * -EAGAIN When reading mode is set to non block and there is no rx data.
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES REFERENCED: ppiinfo
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: It is invoked when user call 'read' system call
 *              to read from system.
 *
 * CAUTION:
 */
static ssize_t hs_conv_ppi_read(struct file *filp, char *buf, size_t count,
			loff_t * pos)
{
	int ierr;
	ppi_device_t *pdev = filp->private_data;

	ppi_debug("hs_conv_ppi_read:\n");

	if (count <= 0)
		return 0;

	pdev->done = 0;

	/* Invalidate allocated memory in Data Cache */

	blackfin_dcache_invalidate_range((u_long) buf, (u_long) (buf + count));

	ppi_debug("hs_conv_ppi_read: blackfin_dcache_invalidate_range : DONE\n");

	/* configure ppi port for DMA RX */

	bfin_write_PPI_COUNT(count - 1);

	set_dma_config(CH_PPI, pdev->dma_config | WNR);
	set_dma_start_addr(CH_PPI, (u_long) buf);

	if (pdev->dma_config & WDSIZE_16) {
		set_dma_x_modify(CH_PPI, 2);
		set_dma_x_count(CH_PPI, count / 2);	// Div 2 because of 16-bit packing

	} else {
		set_dma_x_modify(CH_PPI, 1);
		set_dma_x_count(CH_PPI, count);
	}
	ppi_debug("hs_conv_ppi_read: SETUP DMA : DONE\n");

	enable_dma(CH_PPI);

	/* Enable PPI */

	bfin_write_PPI_CONTROL(DEFAULT_PPICONFIG | PORT_EN);
	SSYNC();

	ppi_debug("hs_conv_ppi_read: PPI ENABLED : DONE\n");

	/* Wait for data available */
	if (1) {
		if (pdev->nonblock)
			return -EAGAIN;
		else {
			ppi_debug("PPI wait_event_interruptible\n");
			ierr =
			    wait_event_interruptible(*(pdev->rx_avail),
						     pdev->done);
			if (ierr) {
				/* waiting is broken by a signal */
				ppi_debug("PPI wait_event_interruptible ierr\n");
				return ierr;
			}
		}
	}

	ppi_debug("PPI wait_event_interruptible done\n");

	disable_dma(CH_PPI);

	ppi_debug("hs_conv_ppi_read: return\n");

	return count;
}

static ssize_t hs_conv_ppi_write (struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	int ierr;
	ppi_device_t *pdev = filp->private_data;

	ppi_debug("hs_conv_ppi_write:\n");

	if (count <= 0)
		return 0;

	pdev->done = 0;

	blackfin_dcache_flush_range((u_long) buf, (u_long) (buf + count));

	ppi_debug("hs_conv_ppi_write: blackfin_dcache_invalidate_range : DONE\n");


	/* configure ppi port for DMA RX */

	bfin_write_PPI_COUNT(count - 1);

	set_dma_config(CH_PPI, pdev->dma_config);
	set_dma_start_addr(CH_PPI, (u_long) buf);

	if (pdev->dma_config & WDSIZE_16) {
		set_dma_x_modify(CH_PPI, 2);
		set_dma_x_count(CH_PPI, count / 2);	// Div 2 because of 16-bit packing
	} else {
		set_dma_x_modify(CH_PPI, 1);
		set_dma_x_count(CH_PPI, count);
	}

	ppi_debug("hs_conv_ppi_write: SETUP DMA : DONE\n");

	enable_dma(CH_PPI);

	/* Enable PPI */

	bfin_write_PPI_CONTROL(DEFAULT_PPICONFIG | PORT_EN | PORT_DIR);
	SSYNC();

	ppi_debug("hs_conv_ppi_write: PPI ENABLED : DONE\n");

	gpio_set_value(pdev->ppi_trigger_gpio, 1);
	ppi_debug("hs_conv_ppi_write: WRDACRAM HIGH\n");
	/* Wait for data available */
	if (1) {
		if (pdev->nonblock)
			return -EAGAIN;
		else {
			ppi_debug("PPI wait_event_interruptible\n");
			ierr =
			    wait_event_interruptible(*(pdev->rx_avail),
						     pdev->done);
			if (ierr) {
				/* waiting is broken by a signal */
				ppi_debug("PPI wait_event_interruptible ierr\n");
				return ierr;
			}
		}
	}

	ppi_debug("PPI wait_event_interruptible done\n");

	disable_dma(CH_PPI);
	gpio_set_value(pdev->ppi_trigger_gpio, 0);
	ppi_debug("hs_conv_ppi_write: return\n");

	return count;
}

/*
 * FUNCTION NAME: hs_conv_ppi_open
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
 * GLOBAL VARIABLES REFERENCED: ppiinfo
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: It is invoked when user call 'open' system call
 *              to open ppi device.
 *
 * CAUTION:
 */
static int hs_conv_ppi_open(struct inode *inode, struct file *filp)
{
	char intname[20];
	unsigned long flags;
	int minor = MINOR(inode->i_rdev);

	ppi_debug("hs_conv_ppi_open:\n");

	/* PPI ? */
	if (minor != PPI0_MINOR)
		return -ENXIO;

	spin_lock_irqsave(&hs_conv_lock, flags);

	if (ppiinfo.opened) {
		spin_unlock_irqrestore(&hs_conv_lock, flags);
		return -EMFILE;
	}

	/* Clear configuration information */
	memset(&ppiinfo, 0, sizeof(ppi_device_t));

	if (filp->f_flags & O_NONBLOCK)
		ppiinfo.nonblock = 1;

	ppiinfo.opened = 1;
	ppiinfo.done = 0;
	ppiinfo.dma_config =
	    (DMAFLOW_STOP | RESTART | WDSIZE_16 | DI_EN);


	ppiinfo.ppi_control = DEFAULT_PPICONFIG;
	ppiinfo.ppi_status = 0;
	ppiinfo.ppi_delay = 0;
	ppiinfo.ppi_trigger_gpio = WRDACRAM;

	ppiinfo.rx_avail = &ppirxq0;

	strcpy(intname, PPI_INTNAME);
	ppiinfo.irqnum = IRQ_PPI;

	filp->private_data = &ppiinfo;

	hs_conv_reg_reset(filp->private_data);

	spin_unlock_irqrestore(&hs_conv_lock, flags);

	ppi_debug("hs_conv_ppi_open: return\n");

	return 0;
}

/*
 * FUNCTION NAME: hs_conv_ppi_release
 *
 * INPUTS/OUTPUTS:
 * in_inode - Description of openned file.
 * in_filp - Description of openned file.
 *
 * RETURN
 * Always 0
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES REFERENCED: ppiinfo
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: It is invoked when user call 'close' system call
 *              to close device.
 *
 * CAUTION:
 */
static int hs_conv_ppi_release(struct inode *inode, struct file *filp)
{

	unsigned long flags;
	ppi_device_t *pdev = filp->private_data;

	ppi_debug("hs_conv_ppi_release: close()\n");

	spin_lock_irqsave(&hs_conv_lock, flags);

	hs_conv_reg_reset(pdev);
	pdev->opened = 0;
	spin_unlock_irqrestore(&hs_conv_lock, flags);

	hs_conv_fasync(-1, filp, 0);

	ppi_debug("hs_conv_ppi_release: close() return\n");
	return 0;
}

static struct file_operations ppi_fops = {
	owner:   THIS_MODULE,
	read:    hs_conv_ppi_read,
	write:   hs_conv_ppi_write,
	ioctl:   hs_conv_ppi_ioctl,
	open:    hs_conv_ppi_open,
	release: hs_conv_ppi_release,
	fasync:  hs_conv_fasync,
};

static struct miscdevice bfin_ppi_dev = {
	PPI0_MINOR,
	"ppi",
	&ppi_fops
};

/*
 * FUNCTION NAME: hs_conv_init / init_module
 *
 * INPUTS/OUTPUTS:
 *
 * RETURN:
 * 0 if module init ok.
 * -1 init fail.
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES REFERENCED: ppiinfo
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: It will be invoked when using 'insmod' command.
 *              or invoke it directly if ppi module is needed.
 *
 * CAUTION:
 */
int __init hs_conv_init(void)
{
	int result;

	if (peripheral_request_list(hs_conv_ppi_req, PPI_DEVNAME)) {
		printk(KERN_ERR "Requesting Peripherals PPI faild\n");
		return -EFAULT;
	}

	if (gpio_request(WRDACRAM, PPI_DEVNAME)) {
		printk(KERN_ERR"Requesting GPIO %d faild\n",
				WRDACRAM);
		peripheral_free_list(hs_conv_ppi_req);
		return -EFAULT;
	}

	gpio_direction_output(WRDACRAM, 0);

	/* Request DMA channel, and pass the interrupt handler */

	if (request_dma(CH_PPI, "BF533_PPI_DMA") < 0) {
		panic("Unable to attach BlackFin PPI DMA channel\n");
		peripheral_free_list(hs_conv_ppi_req);
		gpio_free(WRDACRAM);
		return -EFAULT;

	} else
		set_dma_callback(CH_PPI, (void *)hs_conv_irq,
				 &ppiinfo);

#ifdef USE_PPI_ERROR_IRQ
	request_irq(IRQ_PPI_ERROR, (void *)hs_conv_irq_error, IRQF_DISABLED,
		    "PPI ERROR", &ppiinfo);
#endif

	result = misc_register(&bfin_ppi_dev);

	if (result < 0) {
		printk(KERN_WARNING "PPI: can't get minor %d\n", PPI0_MINOR);
		return result;
	}
	printk(KERN_INFO "High Speed Converter Driver IRQ:%d\n",
	       IRQ_PPI);
	return 0;
}

/*
 * FUNCTION NAME: hs_conv_uninit / cleanup_module
 *
 * INPUTS/OUTPUTS:
 *
 * RETURN:
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES REFERENCED: ppiinfo
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: It will be invoked when using 'rmmod' command.
 *              or, you invoke it directly when it needs remove
 *              ppi module.
 *
 * CAUTION:
 */
void __exit hs_conv_uninit(void)
{
	gpio_free(ppiinfo.ppi_trigger_gpio);

	free_dma(CH_PPI);

#ifdef USE_PPI_ERROR_IRQ
	free_irq(IRQ_PPI_ERROR, filp->private_data);
#endif
	peripheral_free_list(hs_conv_ppi_req);

	misc_deregister(&bfin_ppi_dev);
	printk(KERN_ALERT "Goodbye PPI\n");
}

module_init(hs_conv_init);
module_exit(hs_conv_uninit);

MODULE_AUTHOR("Michael Hennerich");
MODULE_LICENSE("GPL");
