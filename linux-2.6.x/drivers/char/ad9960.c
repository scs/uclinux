/*
 * File:         drivers/char/ad9960.c
 * Based on:
 * Author:       Aubrey.Li <aubrey.Li@analog.com>
 *
 * Created:
 * Description:
 *
 * Prototype:
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2005 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
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
#include <linux/device.h>
#include <linux/spi/spi.h>
#include <linux/delay.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/dma.h>
#include <asm/cacheflush.h>
#include <asm/bfin5xx_spi.h>

/************************************************************/

/* definitions */

#define AD9960_MAJOR          240   /* experiential */
#define AD9960_MINOR         0

#define AD9960_DEVNAME       "AD9960"
#define AD9960_INTNAME       "AD9960-INT"  /* Should be less than 19 chars. */

#define CMD_SPI_WRITE		0x1
#define CMD_GET_SCLK		0x2
#define CMD_GET_PPI_BUF		0x4

extern unsigned long physical_mem_end;

struct spi_command
{
	unsigned char address;
	unsigned char toWrite;
	unsigned char readBack;
};

struct dmasgsmall_t {
	unsigned short next_desc_addr_lo;
	unsigned short start_addr_lo;
	unsigned short start_addr_hi;
	unsigned short cfg;
	unsigned short x_count;
	unsigned short x_modify;
	unsigned short y_count;
	unsigned short y_modify;
};

/************************************************************/
struct ad9960_spi{
	struct spi_device *spi;
};

struct ad9960_ppi{
	unsigned short irqnum;
	unsigned short dma_config;
	unsigned short ppi_control;
	unsigned short ppi_status;
	unsigned short ppi_delay;
};

struct ad9960_device_t{
	int opened;
	int nonblock;
	unsigned short done;
	struct ad9960_spi *spi_dev;
	struct ad9960_ppi ppi_dev;
	struct fasync_struct *fasyc;
	unsigned short *gpio;
	wait_queue_head_t *rx_avail;
	unsigned short* buffer;
};

/************************************************************/

/* Globals */

static DECLARE_WAIT_QUEUE_HEAD(ad9960_rxq);
struct ad9960_device_t ad9960_info;
int ad9960_spi_read(struct ad9960_spi *spi, unsigned short data,
		unsigned short *buf);
int ad9960_spi_write(struct ad9960_spi *spi, unsigned short data);

/* extern unsigned long l1_data_A_sram_alloc(unsigned long size); */
/* extern int l1_data_A_sram_free(unsigned long addr); */

static irqreturn_t ad9960_ppi_irq(int irq, void *dev_id, struct pt_regs *regs)
{

	struct ad9960_device_t *pdev = (struct ad9960_device_t*)dev_id;

	pr_debug("ad9960_ppi_irq: begin\n");

	/* Acknowledge DMA Interrupt*/
	clear_dma_irqstat(CH_PPI);

	/* disable ppi */
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() &  ~PORT_EN);

	pdev->done = 1;

	/* Give a signal to user program. */
	if(pdev->fasyc)
		kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);

	pr_debug("ad9960_ppi_irq: wake_up_interruptible pdev->done=%d\n",pdev->done);

	/* wake up read*/
	wake_up_interruptible(pdev->rx_avail);

	pr_debug("ad9960_ppi_irq: return \n");

	return IRQ_HANDLED;

}

static int ad9960_fasync(int fd, struct file *filp, int on)
{
	struct ad9960_device_t *pdev = filp->private_data;

	return fasync_helper(fd, filp, on, &(pdev->fasyc));
}

static ssize_t ad9960_read (struct file *filp, char *buf, size_t count, loff_t *pos)
{
	int ierr;
	struct ad9960_device_t *pdev;
	int i,j;
	unsigned int desc_count=0;
	int count_remain=0;
	struct dmasgsmall_t *descriptors = 0;

	pr_debug("ad9960_read: beginning read\n");

	pdev = filp->private_data;

	pr_debug("ad9960_read: count = %d\n", (unsigned int)count);

	if((unsigned int)count <= 0)
		return 0;

	pdev->done=0;

	/* Disable PPI */
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() & ~ PORT_EN);
	/* Disable dma */
	disable_dma(CH_PPI);
	bfin_write_PORTFIO_SET(bfin_read_PORTFIO_SET() | 0x0100);
	bfin_write_PORTG_FER(0xFFFF);
	__builtin_bfin_ssync();

	/* setup PPI */
	if(buf[0] == 1)			/* Show only Channel I (skip Channel Q) */
		bfin_write_PPI_CONTROL(0x3E3C);
	else if(buf[0] == 2)		/* Show only Channel Q (skip Channel I) */
		bfin_write_PPI_CONTROL(0x3A3C);
	else if(buf[0] == 0) 	/* Show both channels */
		bfin_write_PPI_CONTROL(0x783C);

	bfin_write_PPI_DELAY(7);

	desc_count = 1; /* One descriptor is enough for 4GB of DMA buffer */
	descriptors = (struct dmasgsmall_t *)l1_data_A_sram_alloc(
			desc_count * sizeof(struct dmasgsmall_t));
	pr_debug("ad9960_read: allocated %i descriptors starting at 0x%08X\n",
			desc_count, (unsigned int)descriptors);

	pr_debug("ad9960_read: configuring descriptor\n");
	descriptors[desc_count-1].next_desc_addr_lo = (unsigned short)(((int)(&descriptors[0]))&0xFFFF);
	descriptors[desc_count-1].start_addr_lo = _ramend + ((desc_count-1)*65535*65535);
	descriptors[desc_count-1].start_addr_hi = (_ramend + ((desc_count-1)*65535*65535))>>16;
	descriptors[desc_count-1].cfg = 0x0097;

	count_remain = count - ((desc_count-1)*0xFFFF);
	pr_debug("ad9960_read: last descriptor needs to get %i samples\n",count_remain);
	for(i=2;i<0xFFFF;i++)
	{
		for(j=1;j<0xFFFF;j++)
		{
			if(i*j==count_remain)
				break;
		}
		if(i * j == count_remain)
			break;
	}

	pr_debug("ad9960_read: using 2D array configuration of %ix%i\n",i,j);

	descriptors[desc_count-1].x_count = i;
	descriptors[desc_count-1].x_modify = 2;
	descriptors[desc_count-1].y_count = j;
	descriptors[desc_count-1].y_modify = 2;

	set_dma_config(CH_PPI, 0x6816);
	set_dma_next_desc_addr(CH_PPI,((unsigned long)&descriptors[0]));

	pr_debug("ad9960_read: SETUP DMA : DONE \n");

	enable_dma(CH_PPI);
	/* Enable PPI */
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | PORT_EN);
	__builtin_bfin_ssync();

	bfin_write_PORTFIO_CLEAR(0x0100);
	__builtin_bfin_ssync();

	pr_debug("ad9960_read: PPI ENABLED : DONE \n");
	/* Wait for data available */
	if(pdev->nonblock)
		return -EAGAIN;
	else
	{
		pr_debug("PPI wait_event_interruptible\n");
		ierr = wait_event_interruptible(*(pdev->rx_avail),pdev->done);
		if(ierr)
		{
			/* waiting is broken by a signal */
			printk("PPI wait_event_interruptible ierr\n");
			return ierr;
		}
	}

	pr_debug("PPI wait_event_interruptible done\n");

	l1_data_A_sram_free(descriptors);
	disable_dma(CH_PPI);
	bfin_write_PORTFIO_SET(0x0100);
	__builtin_bfin_ssync();

	pr_debug("ppi_read: return \n");

	return count;
}

static ssize_t ad9960_write (struct file *filp, const char *buf, size_t count, loff_t *pos)
{
	struct ad9960_device_t *pdev = filp->private_data;
	char *dma_buf;
	int i;
	struct dmasgsmall_t *descriptors = 0;
	unsigned int desc_count=0;
	unsigned int count_remain=0;
	unsigned int data_pointer;

	dma_buf = (void*)pdev->buffer;

	pr_debug("ad9960_write: \n");

	if(count <= 0)
		return 0;

	pdev->done=0;

	/* Disable PPI */
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() & ~PORT_EN);
	/* Disable dma */
	disable_dma(CH_PPI);
	bfin_write_PORTFIO_CLEAR(0x0100);

	__builtin_bfin_ssync();

	/* setup PPI */
	bfin_write_PPI_CONTROL(0x7802);
	bfin_write_PPI_DELAY(0);

	/* configure ppi port for DMA read*/
	if (count <= 0xFFFF) {
		if (buf[0] == 1) {
			/* 
			 * One-shot mode: Does not autobuffer, 
			 * but does wait for FS 
			 */
			pr_debug("Processing one-shot TX\n");
			bfin_write_PPI_CONTROL(0x780E);
			bfin_write_PPI_COUNT(count-1);
			/* No interrupt */
			set_dma_config(CH_PPI, 0x0004);
		} else {
			pr_debug("Processing looped TX\n");
			/* Autobuffer no interrupt */
			set_dma_config(CH_PPI, 0x1004);
		}

		set_dma_start_addr(CH_PPI, (u_long)dma_buf);
		set_dma_x_count(CH_PPI, count);
		set_dma_x_modify(CH_PPI, 2);
	} else {
		desc_count = (count / 65536);

		if (count % 65536 != 0)
			desc_count++;

		pr_debug("%i = (%i/65536)+1\n", desc_count, (int)count);
		descriptors = (struct dmasgsmall_t*)l1_data_A_sram_alloc(
				desc_count * sizeof(struct dmasgsmall_t));
		pr_debug("ad9960_write: allocated %i descriptors starting at 0x%08X\n",
					desc_count,(unsigned int)descriptors);

		for (i=0;i < (desc_count-1);i++) {
			data_pointer = ((unsigned int)_ramend)+((unsigned int)(2*i*65536));
			pr_debug("ad9960_write: configuring descriptor %i at %08X",
					"Buffer at 0x%08X\n",i,(unsigned int)&descriptors[i],data_pointer);
			descriptors[i].next_desc_addr_lo = (unsigned short)(((int)(&descriptors[i+1]))&0xFFFF);
			descriptors[i].start_addr_lo = data_pointer&0xFFFF;
			descriptors[i].start_addr_hi = data_pointer>>16;
			descriptors[i].cfg = 0x6805;
			descriptors[i].x_count = 0; /* 65536 */
			descriptors[i].x_modify = 2;
		}
		data_pointer = _ramend + (2 * (desc_count-1) * 65536);
		count_remain = 0;
		count_remain = (unsigned int)count;
		count_remain = count_remain - (((unsigned int)(desc_count-1)) * 65536);
		pr_debug("ad9960_write: configuring last descriptor %i Buffer at 0x%08X-0x%08X\n",
					desc_count-1,data_pointer,data_pointer+count_remain);
		descriptors[desc_count-1].next_desc_addr_lo = (unsigned short)(((int)(&descriptors[0])) & 0xFFFF);
		descriptors[desc_count-1].start_addr_lo = data_pointer & 0xFFFF;
		descriptors[desc_count-1].start_addr_hi = data_pointer >> 16;
		descriptors[desc_count-1].cfg = 0x6805;

		descriptors[desc_count-1].x_count = count_remain;
		descriptors[desc_count-1].x_modify = 2;

		set_dma_config(CH_PPI, 0x6804);
		set_dma_next_desc_addr(CH_PPI,((unsigned long)&descriptors[0]));	
	}

	pr_debug("ad9960_write: SETUP DMA : DONE \n");

	enable_dma(CH_PPI);

	/* Enable PPI */
	bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | PORT_EN);
	__builtin_bfin_ssync();

	bfin_write_PORTFIO_SET(0x0100);
	__builtin_bfin_ssync();

	pr_debug("ad9960_write: PPI ENABLED : DONE \n");
	/* Wait for data available */
#if 0
	if (1) {
		if(pdev->nonblock)
	  		return -EAGAIN;
	  	else {
			pr_debug("PPI wait_event_interruptible\n");
	  		ierr = wait_event_interruptible(*(pdev->rx_avail),pdev->done);
	  		if (ierr) {
				/* waiting is broken by a signal */
				printk(KERN_ERR "PPI wait_event_interruptible ierr\n");
				return ierr;
			}
		}
	}
#endif

	/* DPRINTK("PPI wait_event_interruptible done\n"); */

#if 0	
	l1_data_A_sram_free((u_long)dma_buf);
	disable_dma(CH_PPI);
	bfin_write_PORTFIO_CLEAR(0x0100);
	__builtin_bfin_ssync();
#endif

	pr_debug("ppi_write: return \n");

	return count;
}


static int ad9960_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{
	struct spi_command * spi_cmd = ((struct spi_command *)((void *)arg));
	unsigned short value = (spi_cmd->address)<<8|(spi_cmd->toWrite);
	unsigned long  sclk;
	unsigned short readin;    

	switch (cmd) {
	case CMD_SPI_WRITE:
		pr_debug("ad9960_ioctl: CMD_SPI_WRITE addr: %x, data: %x\n", (value&0xff00)>>8, (value&0x00ff));
		ad9960_spi_read(ad9960_info.spi_dev, value,&readin);   
		pr_debug("ad9960_ioctl: CMD_SPI_WRITE read: %04x\n",readin);
		spi_cmd->readBack = readin&0x00FF;
		break;
	case CMD_GET_SCLK:
		pr_debug("ad9960_ioctl: CMD_GET_SCLK\n");
		sclk = get_sclk();
		copy_to_user((unsigned long *)arg, &sclk, sizeof(unsigned long));
		break;
	case CMD_GET_PPI_BUF:
		pr_debug("ad9960_ioctl: CMD_GET_PPI_BUF\n");
		copy_to_user((unsigned long *)arg, &ad9960_info.buffer, sizeof(unsigned long));
	default:
		return -EINVAL;
	}
	return 0;
}

static int ad9960_open (struct inode *inode, struct file *filp)
{
	char intname[20];
	int minor = MINOR (inode->i_rdev);
	int i;

	pr_debug("ad9960_open: \n");

	/* PPI ? */
	if(minor != AD9960_MINOR) return -ENXIO;

	if(ad9960_info.opened)
		return -EMFILE;

	if(filp->f_flags & O_NONBLOCK)
		ad9960_info.nonblock = 1;

	ad9960_info.opened = 1;
	ad9960_info.done = 0;

	ad9960_info.rx_avail = &ad9960_rxq;

	strcpy(intname, AD9960_INTNAME);
	ad9960_info.ppi_dev.irqnum = IRQ_PPI;

	filp->private_data = &ad9960_info;

	/* Request DMA channel, and pass the interrupt handler */

	if(request_dma(CH_PPI, "AD9960_PPI_DMA") < 0)
	{
		panic("Unable to attach BlackFin PPI DMA channel\n");
		return -EFAULT;
	}
	else
		set_dma_callback(CH_PPI, (void*) ad9960_ppi_irq,filp->private_data);

	/* AD9960 Initialization */
	ad9960_spi_write(ad9960_info.spi_dev, 0x0001);  /* SW Reset */
	ad9960_spi_write(ad9960_info.spi_dev, 0x0100);  /* Blackfin mode */
	ad9960_spi_write(ad9960_info.spi_dev, 0x05FF);  /* Detailed programming mode */
	ad9960_spi_write(ad9960_info.spi_dev, 0x068E);  /* Bypass TXFIR, 32MHz clock */
	ad9960_spi_write(ad9960_info.spi_dev, 0x078E);  /* Bypass TXCCI, 32MHz clock */
	ad9960_spi_write(ad9960_info.spi_dev, 0x088E);  /* Bypass RXCIC, output clock of 32MHz */
	ad9960_spi_write(ad9960_info.spi_dev, 0x098E);  /* Bypass RXFIR, output clock of 32MHz */
	ad9960_spi_write(ad9960_info.spi_dev, 0x0AFF);  /* PPI Config, both PPI clock to 64MHz */
	ad9960_spi_write(ad9960_info.spi_dev, 0x0000);  /* Pull everything out of reset */
	ad9960_spi_write(ad9960_info.spi_dev, 0x1000);  /* GIO08:GPIO1 as output*/
	ad9960_spi_write(ad9960_info.spi_dev, 0x1100);  /* GPIO0 as output */
	ad9960_spi_write(ad9960_info.spi_dev, 0x1450);  /* GPIO4 as overrange, GPIO8 as CLK out */
	/* Disable clock multiplier to set DCLK as 32MHz, otherwise, DCLK is set as 64MHz */
	/*ad9960_spi_write(ad9960_info.spi_dev, 0x3150);*/  /* Turn off clock multiplier */

	/* AD9960 Filter clear out */
	ad9960_spi_write(ad9960_info.spi_dev, 0x1E00);

	for(i=0;i<256;i++){
		ad9960_spi_write(ad9960_info.spi_dev, 0x1F00);
	}
	
	pr_debug("ppi_open: return \n");

	return 0;
}

static int ad9960_release (struct inode *inode, struct file *filp)
{
	struct ad9960_device_t *pdev = filp->private_data;

	pr_debug("ad9960_release: close() \n");

	/* After finish DMA, release it. */
	free_dma(CH_PPI);

	pdev->opened = 0;

	ad9960_fasync(-1, filp, 0);

	pr_debug("ad9960_release: close() return \n");
	return 0;
}

static struct file_operations ad9960_fops = {
	.owner = THIS_MODULE,
	.read = ad9960_read,
	.write = ad9960_write,
	.ioctl = ad9960_ioctl,
	.open = ad9960_open,
	.release = ad9960_release,
	.fasync = ad9960_fasync,
};

int ad9960_spi_read(struct ad9960_spi *spi, unsigned short data,
		unsigned short *buf)
{
	struct spi_transfer t = {
		.tx_buf = &data,
		.len = 2,
	};
	struct spi_transfer r = {
		.rx_buf = buf,
		.len =2,
	};
	struct spi_message m;

	spi_message_init(&m);
	spi_message_add_tail(&t, &m);
	spi_message_add_tail(&r, &m);

	return spi_sync(spi->spi, &m);
}

int ad9960_spi_write(struct ad9960_spi *spi, unsigned short data)
{
	struct spi_transfer t = {
		.tx_buf = &data,
		.len = 2,
	};
	struct spi_message m;

	spi_message_init(&m);
	spi_message_add_tail(&t, &m);

	return spi_sync(spi->spi, &m);
}

static int __devinit ad9960_spi_probe(struct spi_device *spi)
{
	struct ad9960_spi       *chip;

	pr_info("ad9960_spi_probe\n");
	chip = kmalloc(sizeof(struct ad9960_spi), GFP_KERNEL);
	if(!chip) {
		return -ENOMEM;
	}
	dev_set_drvdata(&spi->dev, chip);
	spi->dev.power.power_state = PMSG_ON;

	chip->spi = spi;
	ad9960_info.spi_dev = chip;

	return 0;
}

static int __devexit ad9960_spi_remove(struct spi_device *spi)
{
	struct ad9960_spi *chip = dev_get_drvdata(&spi->dev);
	kfree(chip);
	pr_debug("ad9960_spi_remove: ok\n");

	return 0;
}

static struct spi_driver ad9960_spi_driver = {
	.driver = {
		.name   = "ad9960-spi",
		.bus    = &spi_bus_type,
		.owner  = THIS_MODULE,
	},
	.probe          = ad9960_spi_probe,
	.remove         = __devexit_p(ad9960_spi_remove),
};

static int __init ad9960_init(void)
{
	int result;

	/* Enable PPI_CLK(PF15) and PPI_FS1(PF9) */
	bfin_write_PORTF_FER(bfin_read_PORTF_FER() | 0x8200);    
	/* PF8 select AD9960 TX/RX */
	bfin_write_PORTFIO_DIR(bfin_read_PORTFIO_DIR() | 0x0100); 
	bfin_write_PORTFIO_SET(0x0100);
	bfin_write_PORTG_FER(0xFFFF);

	bfin_write_TIMER0_CONFIG(bfin_read_TIMER0_CONFIG() | OUT_DIS);
	__builtin_bfin_ssync();

	/* Clear configuration information */
	memset(&ad9960_info, 0, sizeof(struct ad9960_device_t));

	spi_register_driver(&ad9960_spi_driver);
	result = register_chrdev(AD9960_MAJOR, AD9960_DEVNAME, &ad9960_fops);
	if (result < 0) {
		printk(KERN_WARNING "ad9960: can't get minor %d\n", AD9960_MAJOR);
		return result;
	}
	printk("ad9960: AD9960 driver, irq:%d \n",IRQ_PPI);

	ad9960_info.buffer = (unsigned short *)_ramend;

	if((unsigned int)ad9960_info.buffer >= physical_mem_end) {
		printk(KERN_ERR "ad9960: ERROR: _ramend = physical_mem_end"
				"- The driver assumes 32MB SDRAM reserved for AD9960 DMA\n");
	}

	pr_info("ad9960: Buffer allocated at 0x%08X",(unsigned int)ad9960_info.buffer);
	/* SDRAM < 0x20000000 in BF537 memory map */
	if((unsigned int)ad9960_info.buffer > 0x20000000)
		pr_info(" (L1 SRAM)\n");
	else
		pr_info(" (SDRAM)\n");

	return 0;
}
static void __exit ad9960_exit(void)
{
	unregister_chrdev(AD9960_MAJOR, AD9960_DEVNAME);
	spi_unregister_driver(&ad9960_spi_driver);
}
module_init(ad9960_init);
module_exit(ad9960_exit);

MODULE_AUTHOR("Aubrey Li");
MODULE_LICENSE("GPL");
