/*
 * File:         drivers/char/bfin_ppi.c
 * Based on:
 * Author:       John DeHority <john.dehority@NOSPAM@kodak.com>
 *
 * Created:      May 5, 2005
 * Description:  PPI Input Driver for ADSP-BF533
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright (C) 2005, Eastman Kodak Company
 *               Copyright 2005-2006 Analog Devices Inc.
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
#include <linux/delay.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/dma.h>
#include <asm/cacheflush.h>

#include <asm/bf5xx_timers.h>

#include "bfin_ppi.h"

/* definitions */

//#define MODULE

#undef	DEBUG

#ifdef DEBUG
#define DPRINTK(x...)	printk(KERN_DEBUG x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif

#define PPI_MAJOR          241	/* experiential */
#define PPI0_MINOR         0

#define PPI_DEVNAME       "ppi"
#define PPI_INTNAME       "ppiint"	/* Should be less than 19 chars. */

typedef struct Ppi_Device_t {
	unsigned char opened;
	unsigned char nonblock;
	unsigned char portenable;
	unsigned char datalen;
	unsigned char triggeredge;

	unsigned char cont;
	unsigned char dimensions;	//1D or 2D
	unsigned short delay;
	unsigned short access_mode;
	unsigned short *buffer;
	unsigned short done;
	unsigned short dma_config;
	unsigned short linelen;
	unsigned short numlines;
	unsigned short ppi_control;
	int irqnum;
	struct fasync_struct *fasyc;
	wait_queue_head_t *rx_avail;
} ppi_device_t;

/* Globals */
/* We must declare queue structure by the following macro.
 * firstly declare 'wait_queue_head_t' and then 'init_waitqueue_head'
 * doesn't work in 2.4.7 kernel / redhat 7.2 */
static DECLARE_WAIT_QUEUE_HEAD(ppi_wq0);

static ppi_device_t ppiinfo;
static int get_ppi_reg(unsigned int addr, unsigned short *pdata);

/*
 * FUNCTION NAME: get_ppi_reg
 *
 * INPUTS/OUTPUTS:
 * in_addr  - register address.
 * out_pdata - data which would be read from relative register.
 *
 * VALUE RETURNED:
 * NONE
 *
 * FUNCTION(S) CALLED:
 *
 * GLOBAL VARIABLES MODIFIED: NIL
 *
 * DESCRIPTION: Using it set PPI's register.
 *
 * CAUTION:  PPI registers' address are in word aliened.
 */
static int get_ppi_reg(unsigned int addr, unsigned short *pdata)
{
	*pdata = inw(addr);
	return 0;
}

#ifdef CONFIG_BF537
static void setup_gpio_for_PPI(unsigned char datalen)
{
	unsigned short regdata;
	unsigned short syncBits;
	unsigned short portG;
	unsigned short portmux;
	unsigned short ppiCTRL;
	unsigned short portCFG;

	// initialization
	portG = syncBits = 0;
	ppiCTRL = bfin_read_PPI_CONTROL();
	portCFG = (ppiCTRL & PORT_CFG) >> 4;
	portmux = bfin_read_PORT_MUX();

	if (ppiCTRL & PORT_DIR) {	// we're doing output
		switch (portCFG) {
		case CFG_PPI_PORT_CFG_SYNC1:
			syncBits |= PF9;	// enable FS1
			break;
		case CFG_PPI_PORT_CFG_SYNC23:
			syncBits |= (PF9 | PF8);	//enable FS1, FS2
			//syncBits |= ( PF9 | PF8 | PF7); //enable FS1, FS2, FS3
			//portmux |= PFFE_PPI; //enable FS3 in PORT_MUX
			break;
		default:
			break;
		}
	} else {		// we're doing input
		switch (portCFG) {
		case CFG_PPI_PORT_CFG_XSYNC1:
			syncBits |= PF9;	// enable FS1 only
			break;
		case CFG_PPI_PORT_CFG_XSYNC23:
			syncBits |= (PF9 | PF8);	//enable FS1, FS2
			//syncBits |= ( PF9 | PF8 | PF7); //enable FS1, FS2, FS3
			//portmux |= PFFE_PPI; //enable FS3 in PORT_MUX
			break;
		default:
			break;
		}
	}

	regdata = bfin_read_PORTF_FER();
	regdata |= syncBits;
	regdata |= PF15;	//enable PPI_CLK
	bfin_write_PORTF_FER(regdata);
	__builtin_bfin_ssync();
	DPRINTK("PORTF_FER = 0x%04X\n", regdata);

	// enable GPIO pins for PPI data
	// note:  the switch falls through to pick up lower pins

	switch (datalen) {
	case CFG_PPI_DATALEN_16:
		portG |= PG15;
	case CFG_PPI_DATALEN_15:
		portG |= PG14;
	case CFG_PPI_DATALEN_14:
		portG |= PG13;
		portmux &= ~PGTE;	// enable bits 13 14 15
	case CFG_PPI_DATALEN_13:
		portG |= PG12;
	case CFG_PPI_DATALEN_12:
		portG |= PG11;
	case CFG_PPI_DATALEN_11:
		portG |= PG10;
		portmux &= ~PGRE;	// enable bits 10 11 12
	case CFG_PPI_DATALEN_10:
		portG |= (PG9 | PG8);
		portmux &= ~PGSE;	// enable bits 8 & 9
	case CFG_PPI_DATALEN_8:
		portG |= 0xFF;
		break;
	default:
		portG = 0xFFFF;	//enable all 16 data bits
		break;
	}

	regdata = bfin_read_PORTG_FER();
	regdata |= portG;
	bfin_write_PORTG_FER(regdata);
	__builtin_bfin_ssync();
	//DPRINTK("PORTG_FER = 0x%04X\n", regdata);

	if (ppiCTRL & PORT_DIR) {	// we're doing output
		// clear corresponding pins in PORTGIO_INEN register
		regdata = bfin_read_PORTGIO_INEN();
		regdata &= ~portG;
		bfin_write_PORTGIO_INEN(regdata);
		__builtin_bfin_ssync();

		regdata = bfin_read_PORTGIO_DIR();
		regdata |= portG;
		bfin_write_PORTGIO_DIR(regdata);
		__builtin_bfin_ssync();

		regdata = bfin_read_PORTFIO_DIR();
		regdata |= syncBits;	//sync bits are output
		regdata &= ~PF15;	//ppi_clock is input
		bfin_write_PORTFIO_DIR(regdata);
		__builtin_bfin_ssync();
		DPRINTK("PORTFIO_DIR = 0x%04X\n", regdata);

		regdata = bfin_read_PORTFIO_INEN();
		regdata &= ~syncBits;
		regdata |= PF15;	// enable PPI_CLK for input
		bfin_write_PORTFIO_INEN(regdata);
		__builtin_bfin_ssync();
		DPRINTK("PORTFIO_INEN = 0x%04X\n", regdata);
	} else {		// were doing input
		// set corresponding bits in PORTGIO_INEN register
		regdata = bfin_read_PORTGIO_INEN();
		regdata |= portG;
		bfin_write_PORTGIO_INEN(regdata);
		__builtin_bfin_ssync();

		regdata = bfin_read_PORTGIO_DIR();
		regdata &= ~portG;
		bfin_write_PORTGIO_DIR(regdata);
		__builtin_bfin_ssync();

		regdata = bfin_read_PORTFIO_INEN();
		regdata |= syncBits;
		regdata |= PF15;	//enable ppi_clock
		bfin_write_PORTFIO_INEN(regdata);
		__builtin_bfin_ssync();
		DPRINTK("PORTFIO_INEN = 0x%04X\n", regdata);

		regdata = bfin_read_PORTFIO_DIR();
		regdata &= ~syncBits;
		regdata &= ~PF15;	//enable PPI_CLOCK for input
		bfin_write_PORTFIO_DIR(regdata);
		__builtin_bfin_ssync();
		DPRINTK("PORTFIO_DIR = 0x%04X\n", regdata);
	}

	bfin_write_PORT_MUX(portmux);
	__builtin_bfin_ssync();
	DPRINTK("PORT_MUX = 0x%04X (after)\n", portmux);
}
#endif

/*
 * FUNCTION NAME: ppi_reg_reset
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
void ppi_reg_reset(ppi_device_t * pdev)
{
	bfin_write_PPI_CONTROL(0x0000);
	bfin_clear_PPI_STATUS();
	bfin_write_PPI_COUNT(0x0000);
	bfin_write_PPI_FRAME(0x0000);
	bfin_write_PPI_DELAY(0x0000);
}

/*
 * FUNCTION NAME: ppi_irq
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
static irqreturn_t ppi_irq(int irq, void *dev_id, struct pt_regs *regs)
{
	unsigned short regdata;
	ppi_device_t *pdev = (ppi_device_t *) dev_id;

	DPRINTK("ppi_irq:\n");
	get_ppi_reg(DMA0_IRQ_STATUS, &regdata);

	if (!(regdata & DMA_DONE)) {
		DPRINTK("DMA0_IRQ_STATUS = %X\n", regdata);
	}

	clear_dma_irqstat(CH_PPI);

	pdev->done = 1;

	if (pdev->access_mode == PPI_WRITE)
		disable_gptimers((FS1_TIMER_BIT | FS2_TIMER_BIT));

	// disable ppi
	regdata = bfin_read_PPI_CONTROL();
	pdev->ppi_control = regdata & ~PORT_EN;
	bfin_write_PPI_CONTROL(pdev->ppi_control);
	__builtin_bfin_ssync();

	// disable DMA
	disable_dma(CH_PPI);

	/* Give a signal to user program. */
	if (pdev->fasyc)
		kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);

	/* wake up read/write block. */
	wake_up_interruptible(pdev->rx_avail);

	DPRINTK("ppi_irq: return\n");

	return IRQ_HANDLED;
}

/*
 * FUNCTION NAME: ppi_irq_error
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
 * DESCRIPTION: Error ISR of PPI
 *
 * CAUTION:
 */
static irqreturn_t ppi_irq_error(int irq, void *dev_id, struct pt_regs *regs)
{
	printk(KERN_ERR "PPI Error: PPI Status = 0x%X \n",
	       bfin_read_PPI_STATUS());

	/* Add some more Error Handling Code Here */
	bfin_clear_PPI_STATUS();

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
 * -EINVAL  Invalid baudrate
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
static int
ppi_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{
	unsigned short regdata;
	ppi_device_t *pdev = filp->private_data;

	switch (cmd) {
	case CMD_PPI_PORT_ENABLE:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_PORT_ENABLE\n");
			regdata = bfin_read_PPI_CONTROL();
			pdev->portenable = (unsigned short)arg;
			if (arg)
				regdata |= PORT_EN;
			else
				regdata &= ~PORT_EN;
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_PORT_DIRECTION:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_PORT_DIRECTION\n");
			regdata = bfin_read_PPI_CONTROL();
			if (arg)
				regdata |= PORT_DIR;
			else
				regdata &= ~PORT_DIR;
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_XFR_TYPE:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_XFR_TYPE\n");
			if (arg < 0 || arg > 3)
				return -EINVAL;
			regdata = bfin_read_PPI_CONTROL();
			regdata &= ~XFR_TYPE;
			regdata |= ((unsigned short)arg << 2);
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_PORT_CFG:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_PORT_CFG\n");
			if (arg < 0 || arg > 3)
				return -EINVAL;
			regdata = bfin_read_PPI_CONTROL();
			regdata &= ~PORT_CFG;
			regdata |= ((unsigned short)arg << 4);
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_FIELD_SELECT:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_FIELD_SELECT\n");
			regdata = bfin_read_PPI_CONTROL();
			if (arg)
				regdata |= FLD_SEL;
			else
				regdata &= ~FLD_SEL;
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_PACKING:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_PACKING\n");
			regdata = bfin_read_PPI_CONTROL();
			if (arg)
				regdata |= PACK_EN;
			else
				regdata &= ~PACK_EN;
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_SKIPPING:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SKIPPING\n");
			regdata = bfin_read_PPI_CONTROL();
			if (arg)
				regdata |= SKIP_EN;
			else
				regdata &= ~SKIP_EN;
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_SKIP_ODDEVEN:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SKIP_ODDEVEN\n");
			regdata = bfin_read_PPI_CONTROL();
			if (arg)
				regdata |= SKIP_EO;
			else
				regdata &= ~SKIP_EO;
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_DATALEN:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_DATALEN\n");
			if (arg < 0 || arg > 7)
				return -EINVAL;
			pdev->datalen = (unsigned short)arg;
			regdata = bfin_read_PPI_CONTROL();
			regdata &= ~DLENGTH;
			regdata |= (arg << 11);
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_CLK_EDGE:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_CLK_EDGE\n");
			regdata = bfin_read_PPI_CONTROL();
			if (arg)
				regdata |= POLC;
			else
				regdata &= ~POLC;
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_TRIG_EDGE:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_TRIG_EDGE\n");
			pdev->triggeredge = (unsigned short)arg;
			regdata = bfin_read_PPI_CONTROL();
			if (arg)
				regdata |= POLFS;
			else
				regdata &= ~POLFS;
			pdev->ppi_control = regdata;
			bfin_write_PPI_CONTROL(pdev->ppi_control);
			break;
		}
	case CMD_PPI_LINELEN:
		{
			DPRINTK("ppi_ioctl:  CMD_PPI_LINELEN\n");
			if (arg < 0 || arg > PPI_DMA_MAXSIZE)
				return -EINVAL;
			pdev->linelen = (unsigned short)arg;
			break;
		}
	case CMD_PPI_NUMLINES:
		{
			DPRINTK("ppi_ioctl:  CMD_PPI_NUMLINES\n");
			if (arg < 0 || arg > PPI_DMA_MAXSIZE)
				return -EINVAL;
			pdev->numlines = (unsigned short)arg;
			break;

		}
	case CMD_PPI_SET_WRITECONTINUOUS:
		{
			DPRINTK("ppi_ioctl:  CMD_PPI_SET_WRITECONTINUOUS\n");
			pdev->cont = (unsigned char)arg;
			break;

		}
	case CMD_PPI_SET_DIMS:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SET_DIMS\n");
			pdev->dimensions = (unsigned char)arg;
			break;
		}

	case CMD_PPI_DELAY:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_DELAY\n");
			pdev->delay = (unsigned short)arg;
			bfin_write_PPI_DELAY((unsigned short)pdev->delay);
			__builtin_bfin_ssync();
			break;
		}

#ifdef DEBUG
	case CMD_PPI_GET_ALLCONFIG:
		{
			unsigned short usreg;
			DPRINTK("ppi_ioctl: CMD_PPI_GET_ALLCONFIG\n");

			printk(KERN_INFO "opened: %d.\n", ppiinfo.opened);
			printk(KERN_INFO "portenable: %d.\n",
			       ppiinfo.portenable);
			printk(KERN_INFO "nonblock: %d.\n", ppiinfo.nonblock);
			printk(KERN_INFO "irqnum: %d.\n", ppiinfo.irqnum);
			printk(KERN_INFO "pixel size: %d.\n", ppiinfo.datalen);
			printk(KERN_INFO "line length: %hd.\n",
			       ppiinfo.linelen);
			printk(KERN_INFO "num lines: %hd.\n", ppiinfo.numlines);

			get_ppi_reg(PPI_CONTROL, &usreg);
			printk(KERN_INFO "Ctrl reg:     0x%04hx.\n", usreg);
			get_ppi_reg(PPI_STATUS, &usreg);
			printk(KERN_INFO "Status reg:   0x%04hx.\n", usreg);
			get_ppi_reg(PPI_COUNT, &usreg);
			printk(KERN_INFO "Status count: 0x%04hx.\n", usreg);
			get_ppi_reg(PPI_FRAME, &usreg);
			printk(KERN_INFO "Status frame: 0x%04hx.\n", usreg);
			get_ppi_reg(PPI_DELAY, &usreg);
			printk(KERN_INFO "Status delay: 0x%04hx.\n", usreg);
			get_ppi_reg(0xFFC00640, &usreg);	//TIMER_ENABLE
			printk(KERN_INFO "Timer Enable: 0x%04hx.\n", usreg);
			break;
		}
#endif
	case CMD_PPI_SETGPIO:
		{
			DPRINTK("ppi_ioctl: CMD_PPI_SETGPIO\n");
#ifdef CONFIG_BF537
			setup_gpio_for_PPI(ppiinfo.datalen);
#endif
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
 * filp - Description of openned file.
 * buf -- Pointer to buffer allocated to hold data.
 * count - how many bytes user wants to get.
 * pos -- unused
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
static ssize_t ppi_read(struct file *filp, char *buf, size_t count, loff_t *pos)
{
	unsigned short regdata;
	unsigned short stepSize;
	unsigned short port_cfg;
	int ierr;
	ppi_device_t *pdev = filp->private_data;

	DPRINTK("ppi_read(0x%08X, %d)\n", (int)buf, count);

	if (count <= 0)
		return 0;

	pdev->done = 0;
	pdev->access_mode = PPI_READ;

	blackfin_dcache_invalidate_range((unsigned long)buf,
					 ((unsigned long)buf) + count);

	/*
	 ** configure ppi port for DMA TIMOD RX (receive)
	 ** Note:  the rest of PPI control register bits should already be set
	 ** with ioctls before read operation
	 */

	stepSize = (pdev->datalen > CFG_PPI_DATALEN_8) ?	// adjust transfer size
	    2 : 1;

	regdata = bfin_read_PPI_CONTROL();
	pdev->ppi_control = regdata & ~PORT_DIR;
	bfin_write_PPI_CONTROL(pdev->ppi_control);

	regdata = bfin_read_PPI_STATUS();	// read status register to clear it

	/*
	 ** Configure DMA Controller
	 ** WNR:  memory write
	 ** RESTART: flush DMA FIFO before beginning work unit
	 ** DI_EN: generate interrupt on completion of work unit
	 ** DMA2D: 2 dimensional buffer
	 */
	pdev->dma_config |= (WNR | RESTART);
	if (!pdev->cont)
		pdev->dma_config |= DI_EN;
	if (pdev->datalen > CFG_PPI_DATALEN_8)	/* adjust transfer size */
		pdev->dma_config |= WDSIZE_16;
	else
		pdev->dma_config &= ~WDSIZE_16;
	if (pdev->dimensions == CFG_PPI_DIMS_2D) {
		pdev->dma_config |= DMA2D;
	} else
		pdev->dma_config &= ~DMA2D;

	set_dma_config(CH_PPI, pdev->dma_config);
	set_dma_start_addr(CH_PPI, (unsigned long)buf);
	set_dma_x_modify(CH_PPI, stepSize);

	/*
	 ** 1D or 2D DMA
	 */
	if (pdev->dimensions == CFG_PPI_DIMS_2D) {	/* configure for 2D transfers */
		DPRINTK
		    ("PPI read -- 2D data xcount = linelen = %hd, ycount = numlines = %hd stepsize = %hd \n",
		     pdev->linelen, pdev->numlines, stepSize);

		set_dma_x_count(CH_PPI, pdev->linelen);
		set_dma_y_count(CH_PPI, pdev->numlines);
		set_dma_y_modify(CH_PPI, stepSize);

		/* configure PPI registers to match DMA registers */
		bfin_write_PPI_COUNT(pdev->linelen - 1);
		__builtin_bfin_ssync();
		bfin_write_PPI_FRAME(pdev->numlines);
		__builtin_bfin_ssync();
	} else {
		if (pdev->datalen > CFG_PPI_DATALEN_8)	/* adjust transfer size */
			set_dma_x_count(CH_PPI, count / 2);
		else
			set_dma_x_count(CH_PPI, count);
		DPRINTK("PPI read -- 1D data count = %d\n",
			pdev->datalen ? count / 2 : count);
	}

	//DPRINTK("dma_config = 0x%04hX\n", pdev->dma_config);

	bfin_write_PPI_DELAY((unsigned short)pdev->delay);
	__builtin_bfin_ssync();

#ifdef CONFIG_BF537
	port_cfg = (pdev->ppi_control & CFG_PPI_PORT_CFG_NOSYNC) >> 2;

	switch (port_cfg) {
	case CFG_PPI_PORT_CFG_XSYNC23:
		// disable timer1 for FS2
		regdata = get_gptimer_config(FS2_TIMER_ID),
		    regdata &= ~TIMER_OUT_DIS;
		set_gptimer_config(FS2_TIMER_ID, regdata);
		// fall through to get FS1 timers

	case CFG_PPI_PORT_CFG_SYNC1:
		// disable timer0 outputs for FS1
		regdata = get_gptimer_config(TIMER0_id),
		    regdata &= ~TIMER_OUT_DIS;
		set_gptimer_config(TIMER0_id, regdata);
		break;
	default:
		break;
	}
#endif

	__builtin_bfin_ssync();
	enable_dma(CH_PPI);

	/* clear ppi status before enabling */
	bfin_clear_PPI_STATUS();

	// enable ppi
	regdata = bfin_read_PPI_CONTROL();
	pdev->ppi_control = regdata | PORT_EN;
	bfin_write_PPI_CONTROL(pdev->ppi_control);
	__builtin_bfin_ssync();

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

	/*
	 ** disable ppi and dma  -- order matters! see 9-16
	 */
	regdata = bfin_read_PPI_CONTROL();
	pdev->ppi_control = regdata & ~PORT_EN;
	bfin_write_PPI_CONTROL(pdev->ppi_control);
	__builtin_bfin_ssync();

	disable_dma(CH_PPI);

	DPRINTK("ppi_read: return\n");

	return count;
}

/*
 * FUNCTION NAME: ppi_write
 *
 * INPUTS/OUTPUTS:
 * in_filp - Description of openned file.
 * in_count - how many bytes user wants to send.
 * out_buf - where we get those sending data.
 *
 * RETURN
 * positive number: bytes sending out.
 * 0: There is no data send out or parameter error.
 * RETURN:
 * >0 The actual count sending out.
 * -EINVIL When word size is set to 16, writing odd bytes.
 * -EAGAIN When sending mode is set to non block and there is no tx buffer.
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
static ssize_t ppi_write(struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	unsigned short regdata;
	int ierr;
	short fs1_timer_cfg = 0;
	short fs2_timer_cfg = 0;
	unsigned short t_mask;
	unsigned int linePeriod;
	unsigned int frameSize;
	unsigned short stepSize;
	ppi_device_t *pdev = filp->private_data;

	DPRINTK("ppi_write:\n");

	if (count <= 0)
		return 0;

	pdev->done = 0;
	pdev->access_mode = PPI_WRITE;

	blackfin_dcache_invalidate_range((unsigned long)buf,
					 ((unsigned long)buf + (count * 2)));

	pdev->dma_config = set_bfin_dma_config(DIR_READ,	// read from memory to write to PPI
					       DMAFLOW_STOP,	// no chained DMA operation
					       INTR_ON_BUF,	// interrupt when whole transfer complete
					       (pdev->numlines) ? DIMENSION_2D : DIMENSION_LINEAR,	// 2D or 1D
					       DATA_SIZE_16);
	DPRINTK("dma_config = 0x%04X\n", pdev->dma_config);
	set_dma_config(CH_PPI, pdev->dma_config);
	set_dma_start_addr(CH_PPI, (unsigned long)buf);

	if (pdev->datalen > CFG_PPI_DATALEN_8) {	/* adjust transfer size */
		frameSize = count / 2;
		stepSize = 2;
	} else {
		frameSize = count;
		stepSize = 1;
	}

	/*
	 ** set timer configuration register template
	 **
	 ** see note on page 11-29 of BF533 HW Reference Manual
	 ** for setting PULSE_HI according to PPI trigger edge configuration
	 ** of PPI_FS1 and PPI_FS2
	 **
	 ** set TOGGLE_HI so line and frame are not asserted simultaneously
	 */
	fs1_timer_cfg = (TIMER_CLK_SEL | TIMER_TIN_SEL |
			 TIMER_MODE_PWM | TIMER_TOGGLE_HI);

	if (pdev->triggeredge)
		fs1_timer_cfg &= ~TIMER_PULSE_HI;
	else
		fs1_timer_cfg |= TIMER_PULSE_HI;

	fs2_timer_cfg = fs1_timer_cfg;
	fs1_timer_cfg |= TIMER_PERIOD_CNT;	// set up line sync to be recurring

	if (pdev->dimensions == CFG_PPI_DIMS_2D) {	/* configure for 2D transfers */
		DPRINTK("PPI write -- 2D data linelen = %hd, numlines = %hd\n",
			pdev->linelen, pdev->numlines);

		linePeriod = pdev->linelen + pdev->delay;
		frameSize = linePeriod * pdev->numlines * 2;	// TOGGLE_HI effects

		set_dma_x_count(CH_PPI, pdev->linelen);
		set_dma_x_modify(CH_PPI, stepSize);
		set_dma_y_count(CH_PPI, pdev->numlines);
		set_dma_y_modify(CH_PPI, stepSize);

		/* configure PPI registers to match DMA registers */
		bfin_write_PPI_COUNT(pdev->linelen - 1);
		bfin_write_PPI_FRAME(pdev->numlines);
		bfin_write_PPI_DELAY(pdev->delay);

		/*
		 ** configure 2 timers for 2D
		 ** Timer1 - hsync - line time  PPI_FS1 (Timer0 on BF537)
		 ** Timer2 - vsync - frame time PPI_FS2 (Timer1 on BF537)
		 */
		t_mask = (FS1_TIMER_BIT | FS2_TIMER_BIT);	//use both timers

		set_gptimer_config(FS2_TIMER_ID, fs2_timer_cfg);
		set_gptimer_period(FS2_TIMER_ID, frameSize);
		set_gptimer_pwidth(FS2_TIMER_ID, frameSize);
		DPRINTK
		    ("Timer %d: (frame/vsync) config = %04hX, period = %d, width = %d\n",
		     FS2_TIMER_ID, get_gptimer_config(FS2_TIMER_ID),
		     get_gptimer_period(FS2_TIMER_ID),
		     get_gptimer_pwidth(FS2_TIMER_ID));

		set_gptimer_config(FS1_TIMER_ID, fs1_timer_cfg);
		set_gptimer_period(FS1_TIMER_ID, linePeriod);
		//divide linelen by 4 due to TOGGLE_HI behavior
		set_gptimer_pwidth(FS1_TIMER_ID, (pdev->linelen >> 2));
		DPRINTK
		    ("Timer %d: (line/hsync) config = %04hX, period = %d, width = %d\n",
		     FS1_TIMER_ID, get_gptimer_config(FS1_TIMER_ID),
		     get_gptimer_period(FS1_TIMER_ID),
		     get_gptimer_pwidth(FS1_TIMER_ID));
	} else {
		DPRINTK("PPI write -- 1D data count = %d\n", count);

		t_mask = FS1_TIMER_BIT;

		set_dma_x_count(CH_PPI, frameSize);
		set_dma_x_modify(CH_PPI, stepSize);

		/*
		 ** set timer for frame vsync
		 **             use fs2_timer_cfg,  'cuz it is the non-recurring config
		 */
		set_gptimer_config(FS1_TIMER_ID, fs2_timer_cfg);
		set_gptimer_period(FS1_TIMER_ID, frameSize + 1);
		set_gptimer_pwidth(FS1_TIMER_ID, frameSize);

		DPRINTK("Timer %d: config = %04hX, period = %d, width = %d\n",
			FS1_TIMER_ID, fs2_timer_cfg,
			get_gptimer_period(FS1_TIMER_ID),
			get_gptimer_pwidth(FS1_TIMER_ID));

	}
	__builtin_bfin_ssync();
	enable_dma(CH_PPI);

#if 0
	regdata = bfin_read_PPI_COUNT();
	DPRINTK("PPI_COUNT = %d\n", regdata);
	regdata = bfin_read_PPI_FRAME();
	DPRINTK("PPI_FRAME = %d\n", regdata);
	regdata = bfin_read_PPI_DELAY();
	DPRINTK("PPI_DELAY = %d\n", regdata);
#endif

	// enable ppi
	regdata = bfin_read_PPI_CONTROL();
	regdata |= PORT_EN;
	pdev->ppi_control = regdata;
	bfin_write_PPI_CONTROL(pdev->ppi_control);
	__builtin_bfin_ssync();

	DPRINTK("PPI_CONTROL(enabled) = %04hX\n", regdata);

#ifdef CONFIG_BF533
	// rewrite timer configuration registers per BF533 anomaly #25
	set_gptimer_config(FS1_TIMER_ID, fs1_timer_cfg);
	set_gptimer_config(FS2_TIMER_ID, fs2_timer_cfg);
#endif

	DPRINTK("enable_gptimers(mask=%d)\n", t_mask);

	enable_gptimers(t_mask);

#ifdef DEBUG
	regdata = get_dma_curr_irqstat(CH_PPI);
	DPRINTK("DMA IRQ stat = 0x%04X\n", regdata);
	regdata = bfin_read_PPI_STATUS();
	DPRINTK("PPI status = 0x%04X\n", regdata);
#endif

	/* Wait for DMA to finish */

	if (!pdev->cont) {
		if (pdev->nonblock) {
			return -EAGAIN;
		} else {
			DPRINTK("PPI wait_event_interruptible\n");
			ierr =
			    wait_event_interruptible(*(pdev->rx_avail),
						     pdev->done);
			if (ierr) {
				/* waiting is broken by a signal */
				DPRINTK
				    ("PPI wait_event_interruptible ierr = %d\n",
				     ierr);
				return ierr;
			}
		}
	}

	get_ppi_reg(PPI_STATUS, &regdata);
	DPRINTK("PPI Status reg: %x\n", regdata);

	DPRINTK("ppi_write: return\n");

	/*
	 ** disable ppi and dma  -- order matters! see 9-16
	 */
	regdata = bfin_read_PPI_CONTROL();
	pdev->ppi_control = regdata & ~PORT_EN;
	bfin_write_PPI_CONTROL(pdev->ppi_control);
	__builtin_bfin_ssync();

	disable_dma(CH_PPI);

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

	ppiinfo.rx_avail = &ppi_wq0;

	ppiinfo.opened = 1;
	ppiinfo.cont = 0;

	strcpy(intname, PPI_INTNAME);
	ppiinfo.irqnum = PPI_IRQ_NUM;

	filp->private_data = &ppiinfo;

	ppi_reg_reset(filp->private_data);

	/* Request DMA0 channel, and pass the interrupt handler */

	if (request_dma(CH_PPI, "BF533_PPI_DMA") < 0) {
		panic("Unable to attach BlackFin PPI DMA channel\n");
		return -EFAULT;
	} else
		set_dma_callback(CH_PPI, (void *)ppi_irq, filp->private_data);

	if (request_irq(IRQ_PPI_ERROR, (void *)ppi_irq_error, SA_INTERRUPT,
			"PPI ERROR", NULL) < 0) {
		panic("Unable to attach BlackFin PPI Error Interrupt\n");
		return -EFAULT;
	}

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

	ppi_reg_reset(pdev);
	pdev->opened = 0;

	ppi_fasync(-1, filp, 0);

	DPRINTK("ppi_release: close() return\n");
	return 0;
}

static struct file_operations ppi_fops = {
      owner:THIS_MODULE,
      read:ppi_read,
      write:ppi_write,
      ioctl:ppi_ioctl,
      open:ppi_open,
      release:ppi_release,
      fasync:ppi_fasync,
};

/*
 * FUNCTION NAME: ppi_init / init_module
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
int __init ppi_init(void)
{
	int result;

	result = register_chrdev(PPI_MAJOR, PPI_DEVNAME, &ppi_fops);
	if (result < 0) {
		printk(KERN_WARNING "PPI: can't get major %d\n", PPI_MAJOR);
		return result;
	}
	printk(KERN_INFO "PPI: PPI-EKC Driver INIT IRQ:%d \n", PPI_IRQ_NUM);
	return 0;
}

/*
 * FUNCTION NAME: ppi_uninit / cleanup_module
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
void __exit ppi_uninit(void)
{
	unregister_chrdev(PPI_MAJOR, PPI_DEVNAME);
	printk(KERN_ALERT "Goodbye PPI\n");
}

module_init(ppi_init);
module_exit(ppi_uninit);

MODULE_AUTHOR("John DeHority");
MODULE_LICENSE("GPL");
