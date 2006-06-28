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

#undef  DEBUG
//#define DEBUG

#ifdef DEBUG
#define DPRINTK(x...)   printk(x)
#else
#define DPRINTK(x...)   do { } while (0)
#endif

#define AD9960_MAJOR          240   /* experiential */
#define AD9960_MINOR         0

#define AD9960_DEVNAME       "AD9960"
#define AD9960_INTNAME       "AD9960-INT"  /* Should be less than 19 chars. */

#define CMD_SPI_WRITE		0x1
#define CMD_GET_SCLK		0x2

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
};
	
/************************************************************/

/* Globals */

static DECLARE_WAIT_QUEUE_HEAD(ad9960_rxq);
struct ad9960_device_t ad9960_info;
int ad9960_spi_read(struct ad9960_spi *spi, unsigned short data,
                                        unsigned short *buf);
int ad9960_spi_write(struct ad9960_spi *spi, unsigned short data);

extern unsigned long l1_data_A_sram_alloc(unsigned long size);
extern int l1_data_A_sram_free(unsigned long addr);

static irqreturn_t ad9960_ppi_irq(int irq, void *dev_id, struct pt_regs *regs)
{

    struct ad9960_device_t *pdev = (struct ad9960_device_t*)dev_id;

    DPRINTK("ad9960_ppi_irq: begin\n");

    /* Acknowledge DMA Interrupt*/
    clear_dma_irqstat(CH_PPI);

    /* disable ppi */
    bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() &  ~PORT_EN);

    pdev->done = 1;

    /* Give a signal to user program. */
    if(pdev->fasyc)
        kill_fasync(&(pdev->fasyc), SIGIO, POLLIN);

    DPRINTK("ad9960_ppi_irq: wake_up_interruptible pdev->done=%d\n",pdev->done);

    /* wake up read*/
    wake_up_interruptible(pdev->rx_avail);

    DPRINTK("ad9960_ppi_irq: return \n");

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
    struct ad9960_device_t *pdev = filp->private_data;
    char *dma_buf;
	
    dma_buf = (char *)l1_data_A_sram_alloc((u_long)(count*2));

    DPRINTK("ad9960_read: count = %d\n", count);

    if(count <= 0)
        return 0;

    pdev->done=0;

    /* Disable PPI */
    bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() & ~ PORT_EN);
    /* Disable dma */
    disable_dma(CH_PPI);
    bfin_write_PORTFIO_SET(bfin_read_PORTFIO_SET() | 0x0100);
    __builtin_bfin_ssync();
    /* setup PPI */
    bfin_write_PPI_CONTROL(0x783C);
    bfin_write_PPI_DELAY(1);
    /* configure ppi port for DMA write */
    set_dma_config(CH_PPI, 0x0086);
    set_dma_start_addr(CH_PPI, (u_long)dma_buf);
    set_dma_x_count(CH_PPI, count);
    set_dma_x_modify(CH_PPI, 2);

    DPRINTK("ad9960_read: SETUP DMA : DONE \n");

    enable_dma(CH_PPI);
    /* Enable PPI */
    bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | PORT_EN);
    __builtin_bfin_ssync();

    bfin_write_PORTFIO_CLEAR(bfin_read_PORTFIO_CLEAR() | 0x0100);
    __builtin_bfin_ssync();

    DPRINTK("ad9960_read: PPI ENABLED : DONE \n");

    /* Wait for data available */
    if(1)
    {
        if(pdev->nonblock)
            return -EAGAIN;
        else
        {
            DPRINTK("PPI wait_event_interruptible\n");
            ierr = wait_event_interruptible(*(pdev->rx_avail),pdev->done);
            if(ierr)
            {
                /* waiting is broken by a signal */
                printk("PPI wait_event_interruptible ierr\n");
                return ierr;
            }
        }
    }

    memcpy(buf,dma_buf,count*2);
    DPRINTK("PPI wait_event_interruptible done\n");

    l1_data_A_sram_free((u_long)dma_buf);
    disable_dma(CH_PPI);
    bfin_write_PORTFIO_SET(bfin_read_PORTFIO_SET() | 0x0100);
    __builtin_bfin_ssync();

    DPRINTK("ppi_read: return \n");

  return count;
}

static ssize_t ad9960_write (struct file *filp, const char *buf, size_t count, loff_t *pos)
{
    int ierr;
    struct ad9960_device_t *pdev = filp->private_data;
    char *dma_buf;

    dma_buf = (char *)l1_data_A_sram_alloc(count*2);
    memcpy(dma_buf,buf,count*2);

    DPRINTK("ad9960_write: \n");

    if(count <= 0)
        return 0;

    pdev->done=0;

    /* Disable PPI */
    bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() & ~PORT_EN);
    /* Disable dma */
    disable_dma(CH_PPI);
    bfin_write_PORTFIO_CLEAR(bfin_read_PORTFIO_CLEAR() | 0x0100);
    __builtin_bfin_ssync();

    /* setup PPI */
    bfin_write_PPI_CONTROL(0x780E);
    bfin_write_PPI_COUNT(2*count -1);
    bfin_write_PPI_DELAY(0);
    /* configure ppi port for DMA read*/
    set_dma_config(CH_PPI, 0x0084);
    set_dma_start_addr(CH_PPI, (u_long)dma_buf);
    set_dma_x_count(CH_PPI, 2*count);
    set_dma_x_modify(CH_PPI, 2);

    DPRINTK("ad9960_write: SETUP DMA : DONE \n");

    enable_dma(CH_PPI);

    /* Enable PPI */
    bfin_write_PPI_CONTROL(bfin_read_PPI_CONTROL() | PORT_EN);
    __builtin_bfin_ssync();
    
    bfin_write_PORTFIO_SET(bfin_read_PORTFIO_SET() | 0x0100);
    __builtin_bfin_ssync();

    DPRINTK("ad9960_write: PPI ENABLED : DONE \n");
    /* Wait for data available */
    if(1)
    {
        if(pdev->nonblock)
            return -EAGAIN;
        else
        {
            DPRINTK("PPI wait_event_interruptible\n");
            ierr = wait_event_interruptible(*(pdev->rx_avail),pdev->done);
            if(ierr)
            {
                /* waiting is broken by a signal */
                printk("PPI wait_event_interruptible ierr\n");
                return ierr;
            }
        }
    }

    DPRINTK("PPI wait_event_interruptible done\n");

    l1_data_A_sram_free((u_long)dma_buf);
    disable_dma(CH_PPI);
    bfin_write_PORTFIO_CLEAR(bfin_read_PORTFIO_CLEAR() | 0x0100);
    __builtin_bfin_ssync();

    DPRINTK("ppi_write: return \n");

    return count;
}

static int ad9960_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{
    unsigned short value = (unsigned short)arg;
    unsigned long  sclk;
    switch (cmd)
    {
	case CMD_SPI_WRITE:
	{
		DPRINTK("ad9960_ioctl: CMD_SPI_WRITE addr: %x, data: %x\n", (value&0xff00)>>8, (value&0x00ff));
		ad9960_spi_write(ad9960_info.spi_dev, value);    
		break;
	}
	case CMD_GET_SCLK:
	{
		DPRINTK("ad9960_ioctl: CMD_GET_SCLK\n");
		sclk = get_sclk();
		copy_to_user((unsigned long *)arg, &sclk, sizeof(unsigned long));
		break;
	}
	default:
            return -EINVAL;
    }
    return 0;
}

static int ad9960_open (struct inode *inode, struct file *filp)
{
    char intname[20];
    int minor = MINOR (inode->i_rdev);

    DPRINTK("ad9960_open: \n");

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

    DPRINTK("ppi_open: return \n");

    return 0;
}

static int ad9960_release (struct inode *inode, struct file *filp)
{
    struct ad9960_device_t *pdev = filp->private_data;

    DPRINTK("ad9960_release: close() \n");

    /* After finish DMA, release it. */
    free_dma(CH_PPI);

    pdev->opened = 0;

    ad9960_fasync(-1, filp, 0);

    DPRINTK("ad9960_release: close() return \n");
    return 0;
}

static struct file_operations ad9960_fops = {
    owner:      THIS_MODULE,
    read:       ad9960_read,
    write:	ad9960_write,
    ioctl:	ad9960_ioctl,
    open:       ad9960_open,
    release:    ad9960_release,
    fasync:     ad9960_fasync,
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
	int i;

        chip = kmalloc(sizeof(struct ad9960_spi), GFP_KERNEL);
        if(!chip) {
                return -ENOMEM;
        }
        dev_set_drvdata(&spi->dev, chip);
        spi->dev.power.power_state = PMSG_ON;

        chip->spi = spi;
        ad9960_info.spi_dev = chip;
	
	 /* Setup AD9960 SPI register */

        ad9960_spi_write(ad9960_info.spi_dev, 0x0100);
        ad9960_spi_write(ad9960_info.spi_dev, 0x05FF);
        ad9960_spi_write(ad9960_info.spi_dev, 0x068E);
        ad9960_spi_write(ad9960_info.spi_dev, 0x078E);
        ad9960_spi_write(ad9960_info.spi_dev, 0x088E);
        ad9960_spi_write(ad9960_info.spi_dev, 0x098E);
        ad9960_spi_write(ad9960_info.spi_dev, 0x0AFF);
        ad9960_spi_write(ad9960_info.spi_dev, 0x0000);
        ad9960_spi_write(ad9960_info.spi_dev, 0x1000);
        ad9960_spi_write(ad9960_info.spi_dev, 0x1100);
        ad9960_spi_write(ad9960_info.spi_dev, 0x1450);
        /* AD9960 Filter clear out */
        ad9960_spi_write(ad9960_info.spi_dev, 0x1E00);

        for(i=0;i<256;i++){
                ad9960_spi_write(ad9960_info.spi_dev, 0x1F00);
        }
        return 0;
}

static int __devexit ad9960_spi_remove(struct spi_device *spi)
{
        struct ad9960_spi *chip = dev_get_drvdata(&spi->dev);
        kfree(chip);
	DPRINTK("ad9960_spi_remove: ok\n");

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

	bfin_write_PORTF_FER(bfin_read_PORTF_FER() | 0x8200);    /* Enable PPI_CLK(PF15) and PPI_FS1(PF9) */
	bfin_write_PORTFIO_DIR(bfin_read_PORTFIO_DIR() | 0x0100);  /* PF8 select AD9960 TX/RX */
	bfin_write_PORTFIO_SET(bfin_read_PORTFIO_SET() | 0x0100);
	bfin_write_PORTG_FER(0xFFFF);

	bfin_write_TIMER0_CONFIG(bfin_read_TIMER0_CONFIG() | OUT_DIS);
	__builtin_bfin_ssync();

	/* Clear configuration information */
        memset(&ad9960_info, 0, sizeof(struct ad9960_device_t));
	
    	spi_register_driver(&ad9960_spi_driver);
	result = register_chrdev(AD9960_MAJOR, AD9960_DEVNAME, &ad9960_fops);
	if (result < 0)
	    {
        	printk(KERN_WARNING "ad9960: can't get minor %d\n", AD9960_MAJOR);
	        return result;
	    }
	printk("ad9960: AD9960 driver, irq:%d \n",IRQ_PPI);
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
