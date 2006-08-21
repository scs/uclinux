/*
 * File:         drivers/char/bfin_ppifcd.c
 * Based on:
 * Author:       Michael Hennerich
 *
 * Created:      Sept. 10th 2004
 * Description:  Simple PPI Frame Capture driver for ADSP-BF5xx
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
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
#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/dma.h>
#include <asm/cacheflush.h>

#include "bfin_ppifcd.h"

/************************************************************/

/* definitions */

#undef  DEBUG
//#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)   printk(KERN_DEBUG x)
#else
#define DPRINTK(x...)   do { } while (0)
#endif

#define PPI_MAJOR          241	/* experiential */
#define PPI0_MINOR         0
#define PPI1_MINOR         1

#define PPI_DEVNAME       "PPIFCP"
#define PPI_INTNAME       "PPI-FCP-INT"	/* Should be less than 19 chars. */

/************************************************************/

typedef struct PPI_Device_t {
	int opened;
	int nonblock;
	unsigned short irqnum;
	unsigned short done;
	unsigned short dma_config;
	unsigned short pixel_per_line;
	unsigned short lines_per_frame;
	unsigned short bpp;
	unsigned short ppi_control;
	unsigned short ppi_status;
	unsigned short ppi_delay;
	unsigned short ppi_trigger_gpio;
	struct fasync_struct *fasyc;
	wait_queue_head_t *rx_avail;
} ppi_device_t;

/************************************************************/

/* Globals */

static DECLARE_WAIT_QUEUE_HEAD(ppirxq0);
static ppi_device_t ppiinfo;

/*
 * FUNCTION NAME: ppifcd_reg_reset
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
void ppifcd_reg_reset(ppi_device_t *pdev)
{
/* Do some initializaion stuff here based on the defined Camera Module
   so we don't have to use ioctls                     */

/*BF537/6/4 PPI_STATUS is Write to Clear*/
#if defined(CONFIG_BF537) || defined(CONFIG_BF536) || defined(CONFIG_BF534)
	bfin_write_PPI_STATUS(0xFFFF);
#else
	u16 status = bfin_read_PPI_STATUS();
#endif

	bfin_write_PPI_CONTROL(pdev->ppi_control & ~PORT_EN);
	bfin_write_PPI_DELAY(pdev->ppi_delay);
	bfin_write_PPI_COUNT(pdev->pixel_per_line - 1);
	bfin_write_PPI_FRAME(pdev->lines_per_frame);

	return;

}

/*
 * FUNCTION NAME: ppifcd_irq
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
static irqreturn_t ppifcd_irq(int irq, void *dev_id, struct pt_regs *regs)
{
	ppi_device_t *pdev = (ppi_device_t *) dev_id;

	DPRINTK("ppifcd_irq:\n");

	/* Acknowledge DMA Interrupt */
	clear_dma_irqstat(CH_PPI);

	/* disable ppi */

	bfin_write_PPI_CONTROL(pdev->ppi_control & ~PORT_EN);

	pdev->done = 1;

	/* Give a signal to user program. */
	if (pdev->fasyc)
		kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);

	DPRINTK("ppifcd_irq: wake_up_interruptible pdev->done=%d\n",
		pdev->done);

	/* wake up read */

	wake_up_interruptible(pdev->rx_avail);

	DPRINTK("ppifcd_irq: return\n");

	return IRQ_HANDLED;
}

static irqreturn_t ppifcd_irq_error(int irq, void *dev_id, struct pt_regs *regs)
{
	ppi_device_t *pdev = (ppi_device_t *) dev_id;

	DPRINTK("ppifcd_error_irq:\n");
	DPRINTK("PPI Status = 0x%X\n", bfin_read_PPI_STATUS());

/*BF537/6/4 PPI_STATUS is Write to Clear*/
#if defined(CONFIG_BF537) || defined(CONFIG_BF536) || defined(CONFIG_BF534)
	bfin_write_PPI_STATUS(0xFFFF);
#endif

	/* Acknowledge DMA Interrupt */
	clear_dma_irqstat(CH_PPI);

	/* disable ppi */

	bfin_write_PPI_CONTROL(pdev->ppi_control & ~PORT_EN);

	pdev->done = 1;

	/* Give a signal to user program. */
	if (pdev->fasyc)
		kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);

	DPRINTK("ppifcd_error_irq: wake_up_interruptible pdev->done=%d\n",
		pdev->done);
	/* wake up read */

	wake_up_interruptible(pdev->rx_avail);

	DPRINTK("ppifcd_error_irq: return\n");

	return IRQ_HANDLED;
}

/*
 * FUNCTION NAME: ppi_ioctl
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
static int ppi_ioctl(struct inode *inode, struct file *filp, uint cmd,
		     unsigned long arg)
{
	u_long value;
	ppi_device_t *pdev = filp->private_data;

	switch (cmd) {
	case CMD_PPI_SET_PIXELS_PER_LINE:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SET_PIXELS_PER_LINE\n");

			pdev->pixel_per_line = (unsigned short)arg;
			bfin_write_PPI_COUNT(pdev->pixel_per_line - 1);
			break;
		}
	case CMD_PPI_SET_LINES_PER_FRAME:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SET_LINES_PER_FRAME\n");

			pdev->lines_per_frame = (unsigned short)arg;
			bfin_write_PPI_FRAME(pdev->lines_per_frame);
			break;
		}
	case CMD_PPI_SET_PPICONTROL_REG:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SET_PPICONTROL_REG\n");

			pdev->ppi_control = ((unsigned short)arg) & ~PORT_EN;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_SET_PPIDEALY_REG:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SET_PPIDEALY_REG\n");

			pdev->ppi_delay = (unsigned short)arg;
			bfin_write_PPI_DELAY(pdev->ppi_delay);
			break;
		}
	case CMD_SET_TRIGGER_GPIO:
		{
			DPRINTK("ppi_ioctl: CMD_SET_TRIGGER_GPIO\n");

			pdev->ppi_trigger_gpio = (unsigned short)arg;
			break;
		}
	case CMD_PPI_GET_ALLCONFIG:
		{

			break;
		}
	case CMD_PPI_GET_SYSTEMCLOCK:
		{
			value = get_sclk();
			DPRINTK
			    ("ppi_ioctl: CMD_PPI_GET_SYSTEMCLOCK SCLK: %d \n",
			     (int)value);
			copy_to_user((unsigned long *)arg, &value,
				     sizeof(unsigned long));
			break;
		}

	default:
		return -EINVAL;
	}
	return 0;
}

/*
 * FUNCTION NAME: ppi_fasync
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
static int ppi_fasync(int fd, struct file *filp, int on)
{
	ppi_device_t *pdev = filp->private_data;
	return fasync_helper(fd, filp, on, &(pdev->fasyc));
}

/*
 * FUNCTION NAME: ppi_read
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
static ssize_t ppi_read(struct file *filp, char *buf, size_t count,
			loff_t * pos)
{
	int ierr;
	ppi_device_t *pdev = filp->private_data;

	DPRINTK("ppi_read:\n");

	if (count <= 0)
		return 0;

	pdev->done = 0;

	/* Invalidate allocated memory in Data Cache */

	blackfin_dcache_invalidate_range((u_long) buf, (u_long) (buf + count));

	DPRINTK("ppi_read: blackfin_dcache_invalidate_range : DONE\n");

	/* configure ppi port for DMA RX */

	set_dma_config(CH_PPI, pdev->dma_config);
	set_dma_start_addr(CH_PPI, (u_long) buf);
	set_dma_x_count(CH_PPI, pdev->pixel_per_line / 2);	// Div 2 because of 16-bit packing
	set_dma_y_count(CH_PPI, pdev->lines_per_frame);
	set_dma_y_modify(CH_PPI, 2);

	if (pdev->bpp > 8 || pdev->dma_config & WDSIZE_16)
		set_dma_x_modify(CH_PPI, 2);
	else
		set_dma_x_modify(CH_PPI, 1);

	DPRINTK("ppi_read: SETUP DMA : DONE\n");

	enable_dma(CH_PPI);

	/* Enable PPI */

	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | PORT_EN);
	__builtin_bfin_ssync();

	if (pdev->ppi_trigger_gpio < NO_TRIGGER) {
		bfin_write_FIO_FLAG_S(1 << pdev->ppi_trigger_gpio);
		__builtin_bfin_ssync();
		bfin_write_FIO_FLAG_C(1 << pdev->ppi_trigger_gpio);
		__builtin_bfin_ssync();
	}

	DPRINTK("ppi_read: PPI ENABLED : DONE\n");

	/* Wait for data available */
	if (1) {
		if (pdev->nonblock)
			return -EAGAIN;
		else {
			DPRINTK("PPI wait_event_interruptible\n");
			ierr =
			    wait_event_interruptible(*(pdev->rx_avail),
						     pdev->done);
			if (ierr) {
				/* waiting is broken by a signal */
				DPRINTK("PPI wait_event_interruptible ierr\n");
				return ierr;
			}
		}
	}

	DPRINTK("PPI wait_event_interruptible done\n");

	disable_dma(CH_PPI);

	DPRINTK("ppi_read: return\n");

	return count;
}

/*
 * FUNCTION NAME: ppi_open
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
static int ppi_open(struct inode *inode, struct file *filp)
{
	char intname[20];
	int minor = MINOR(inode->i_rdev);

	DPRINTK("ppi_open:\n");

	/* PPI ? */
	if (minor != PPI0_MINOR)
		return -ENXIO;

	if (ppiinfo.opened)
		return -EMFILE;

	/* Clear configuration information */
	memset(&ppiinfo, 0, sizeof(ppi_device_t));

	if (filp->f_flags & O_NONBLOCK)
		ppiinfo.nonblock = 1;

	ppiinfo.opened = 1;
	ppiinfo.done = 0;
	ppiinfo.dma_config =
	    (DMA_FLOW_MODE | WNR | RESTART | DMA_WDSIZE_16 | DMA2D | DI_EN);

	ppiinfo.pixel_per_line = PIXEL_PER_LINE;
	ppiinfo.lines_per_frame = LINES_PER_FRAME;
	ppiinfo.bpp = 8;
	ppiinfo.ppi_control =
	    POL_S | POL_C | PPI_DATA_LEN | PPI_PACKING | CFG_GP_Input_3Syncs |
	    GP_Input_Mode;
	ppiinfo.ppi_status = 0;
	ppiinfo.ppi_delay = 0;
	ppiinfo.ppi_trigger_gpio = NO_TRIGGER;

	ppiinfo.rx_avail = &ppirxq0;

	strcpy(intname, PPI_INTNAME);
	ppiinfo.irqnum = IRQ_PPI;

	filp->private_data = &ppiinfo;

	ppifcd_reg_reset(filp->private_data);

	/* Request DMA channel, and pass the interrupt handler */

	if (request_dma(CH_PPI, "BF533_PPI_DMA") < 0) {
		panic("Unable to attach BlackFin PPI DMA channel\n");
		return -EFAULT;
	} else
		set_dma_callback(CH_PPI, (void *)ppifcd_irq,
				 filp->private_data);

	request_irq(IRQ_PPI_ERROR, (void *)ppifcd_irq_error, SA_INTERRUPT,
		    "PPI ERROR", filp->private_data);

#if (defined(CONFIG_BF537) || defined(CONFIG_BF534) || defined(CONFIG_BF536))
	bfin_write_PORTG_FER(0x00FF);	/* PPI[7:0]    */
	bfin_write_PORTF_FER(bfin_read_PORTF_FER() | 0x8300);	/* PF.15 PPI_CLK FS1 FS2 */
	bfin_write_PORT_MUX(bfin_read_PORT_MUX() & ~0x0E00);
#endif

	DPRINTK("ppi_open: return\n");

	return 0;
}

/*
 * FUNCTION NAME: ppi_release
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
static int ppi_release(struct inode *inode, struct file *filp)
{
	ppi_device_t *pdev = filp->private_data;

	DPRINTK("ppi_release: close()\n");

	/* After finish DMA, release it. */
	free_dma(CH_PPI);

	ppifcd_reg_reset(pdev);
	pdev->opened = 0;

	ppi_fasync(-1, filp, 0);

	DPRINTK("ppi_release: close() return\n");
	return 0;
}

static struct file_operations ppi_fops = {
	owner:   THIS_MODULE,
	read:    ppi_read,
	ioctl:   ppi_ioctl,
	open:    ppi_open,
	release: ppi_release,
	fasync:  ppi_fasync,
};

/*
 * FUNCTION NAME: ppifcd_init / init_module
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
int __init ppifcd_init(void)
{
	int result;

	result = register_chrdev(PPI_MAJOR, PPI_DEVNAME, &ppi_fops);
	if (result < 0) {
		printk(KERN_WARNING "PPI: can't get minor %d\n", PPI_MAJOR);
		return result;
	}
	printk(KERN_INFO "PPI: ADSP PPI Frame Capture Driver IRQ:%d \n",
	       IRQ_PPI);
	return 0;
}

/*
 * FUNCTION NAME: ppifcd_uninit / cleanup_module
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
void __exit ppifcd_uninit(void)
{
	unregister_chrdev(PPI_MAJOR, PPI_DEVNAME);
	printk(KERN_ALERT "Goodbye PPI\n");
}

module_init(ppifcd_init);
module_exit(ppifcd_uninit);

MODULE_AUTHOR("Michael Hennerich");
MODULE_LICENSE("GPL");
