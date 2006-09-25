/*
 * File:         drivers/char/bfin_sport.c
 * Based on:
 * Author:       Roy Huang (roy.huang@analog.com)
 *
 * Created:      Thu Aug. 24 2006
 * Description:  Common sport driver exporting an device interface to user space
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

/* This driver implements a user space interface for sport interface.
 * But it isn't perfect. Maybe it cannot meet your requirement. If you write
 * some code to improve it, you are welcomed to post your patch on our website.
 */

#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/proc_fs.h>
#include <linux/fcntl.h>
#include <linux/cdev.h>
#include <linux/delay.h>
#include <asm/blackfin.h>
#include <asm/bfin_sport.h>
#include <asm/dma.h>

#include <asm/system.h>
#include <asm/uaccess.h>

int sport_major =   SPORT_MAJOR;
int sport_minor =   0;
int sport_nr_devs = SPORT_NR_DEVS;	/* number of bare sport devices */

struct sport_dev *sport_devices;	/* allocated in sport_init_module */

#define SSYNC __builtin_bfin_ssync()

#undef assert

#ifdef DEBUG
#define assert(expr) \
	if (!(expr)) { \
		printk("Assertion failed! %s, %s, %s, line=%d \n", \
			#expr, __FILE__, __FUNCTION__, __LINE__); \
	}
#else
#define assert(expr)
#endif

static irqreturn_t dma_rx_irq_handler(int irq, void *dev_id, struct pt_regs *regs);
static irqreturn_t dma_tx_irq_handler(int irq, void *dev_id, struct pt_regs *regs);

/* note: multichannel is in units of 8 channels, tdm_count is # channels NOT / 8 ! */
static int sport_set_multichannel(struct sport_register *regs,
					int tdm_count, int packed, int frame_delay)
{

	if (tdm_count) {

		int shift = 32 - tdm_count;
		unsigned int mask = (0xffffffff >> shift);

		regs->mcmc1 = ((tdm_count>>3)-1) << 12;  /* set WSIZE bits */
		regs->mcmc2 = (frame_delay << 12)| MCMEN | \
					(packed ? (MCDTXPE|MCDRXPE) : 0);

		regs->mtcs0 = mask;
		regs->mrcs0 = mask;

	} else {

		regs->mcmc1 = 0;
		regs->mcmc2 = 0;

		regs->mtcs0 = 0;
		regs->mrcs0 = 0;
	}

	regs->mtcs1 = 0; regs->mtcs2 = 0; regs->mtcs3 = 0;
	regs->mrcs1 = 0; regs->mrcs2 = 0; regs->mrcs3 = 0;

	SSYNC;

	return 0;
}

static int sport_configure(struct sport_dev *dev, struct sport_config *config)
{
	unsigned int tcr1,tcr2,rcr1,rcr2;
	unsigned int clkdiv, fsdiv;
	struct sport_config *old_cfg = &dev->config;

	tcr1=tcr2=rcr1=rcr2=0;
	clkdiv = fsdiv =0;

	if ((old_cfg->dma_enabled == 0) && (config->dma_enabled)) {
		free_irq(dev->tx_irq, dev);
		free_irq(dev->rx_irq, dev);

		/* Request rx dma and set irq handler */
		if (request_dma(dev->dma_rx_chan, "sport_rx_dma_chan") < 0) {
			printk(KERN_ERR "Unable to request sport rx dma channel\n");
			goto fail;
		}
		set_dma_callback(dev->dma_rx_chan, dma_rx_irq_handler, dev);

		/* Request tx dma and set irq handler */
		if (request_dma(dev->dma_tx_chan, "sport_tx_dma_chan") < 0) {
			printk(KERN_ERR "Unable to request sport tx dma channel\n");
			goto fail;
		}
		set_dma_callback(dev->dma_tx_chan, dma_tx_irq_handler, dev);
	}
	memcpy(old_cfg, config, sizeof(*config));

	if ((dev->regs->tcr1 & TSPEN) || (dev->regs->rcr1 & RSPEN))
		return -EBUSY;

	if (config->mode == TDM_MODE) {
		if(config->channels & 0x7 || config->channels>32)
			return -EINVAL;

		sport_set_multichannel(dev->regs, config->channels, 1, config->frame_delay);
	} else if (config->mode == I2S_MODE) {
		tcr1 |= (TCKFE | TFSR);
		tcr2 |= TSFSE ;

		rcr1 |= (RCKFE | RFSR);
		rcr2 |= RSFSE;
	} else {
		tcr1 |= (config->lsb_first << 4) | (config->fsync << 10) | \
			(config->data_indep << 11) | (config->act_low << 12) | \
			(config->late_fsync << 13) | (config->tckfe << 14) ;
		tcr2 |= config->sec_en;

		rcr1 |= (config->lsb_first << 4) | (config->fsync << 10) | \
			(config->data_indep << 11) | (config->act_low << 12) | \
			(config->late_fsync << 13) | (config->tckfe << 14) ;
		rcr2 |= config->sec_en;
	}

	/* Using internal clock*/
	if (config->int_clk) {
		u_long sclk=get_sclk();

		if (config->serial_clk < 0 || config->serial_clk > sclk/2)
			return -EINVAL;
		clkdiv = sclk/(2*config->serial_clk) - 1;
		fsdiv = config->serial_clk / config->fsync_clk - 1;

		tcr1 |= (ITCLK | ITFS);
		rcr1 |= (IRCLK | IRFS);
	}

	/* Setting data format */
	tcr1 |= (config->data_format << 2); /* Bit TDTYPE */
	rcr1 |= (config->data_format << 2); /* Bit TDTYPE */
	if (config->word_len >= 3 && config->word_len <= 32) {
		tcr2 |= config->word_len - 1;
		rcr2 |= config->word_len - 1;
	} else
		return -EINVAL;

	dev->regs->rcr1 = rcr1;
	dev->regs->rcr2 = rcr2;
	dev->regs->rclkdiv = clkdiv;
	dev->regs->rfsdiv = fsdiv;
	dev->regs->tcr1 = tcr1;
	dev->regs->tcr2 = tcr2;
	dev->regs->tclkdiv = clkdiv;
	dev->regs->tfsdiv = fsdiv;
	__builtin_bfin_ssync();

#if 1
	pr_debug("tcr1:0x%x, tcr2:0x%x, rcr1:0x%x, rcr2:0x%x\n"
		"mcmc1:0x%x, mcmc2:0x%x\n",
		dev->regs->tcr1, dev->regs->tcr2,
		dev->regs->rcr1, dev->regs->rcr2,
		dev->regs->mcmc1, dev->regs->mcmc2);
#endif

	return 0;

fail:
	return -1;
}

static inline uint16_t sport_wordsize(int word_len)
{
	uint16_t wordsize = 0;

	if(word_len <= 8) {
		wordsize =  WDSIZE_8;
	} else if (word_len <= 16) {
		wordsize = WDSIZE_16;
	} else if (word_len <=32) {
		wordsize = WDSIZE_32;
	} else {
		printk(KERN_ERR "%s: word_len:%d is error\n", __FUNCTION__, word_len);
	}

	return wordsize;
}

static irqreturn_t dma_rx_irq_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	struct sport_dev *dev = dev_id;

	pr_debug("%s enter\n", __FUNCTION__);
	dev->regs->rcr1 &= ~RSPEN;
	__builtin_bfin_ssync();
	disable_dma(dev->dma_rx_chan);

	dev->wait_con = 1;
	wake_up(&dev->waitq);

	clear_dma_irqstat(dev->dma_rx_chan);
	return IRQ_HANDLED;
}

static irqreturn_t dma_tx_irq_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	struct sport_dev *dev = dev_id;
	unsigned short status ;

	pr_debug("%s enter\n", __FUNCTION__);
	status = get_dma_curr_irqstat(dev->dma_tx_chan);
	pr_debug("status:0x%04x\n", status);
	while (status & DMA_RUN) {
		status = get_dma_curr_irqstat(dev->dma_tx_chan);
		pr_debug("status:0x%04x\n", status);
	}
	status = 0;
	while (!(status & TUVF)) {
		status = dev->regs->stat;
	}

	dev->regs->tcr1 &= ~TSPEN;
	__builtin_bfin_ssync();
	disable_dma(dev->dma_tx_chan);

	dev->wait_con = 1;
	wake_up(&dev->waitq);

	/* Clear the interrupt status */
	clear_dma_irqstat(dev->dma_tx_chan);

	return IRQ_HANDLED;
}

static irqreturn_t sport_rx_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	struct sport_dev *dev = dev_id;
	struct sport_config *cfg = &dev->config;

	int word_bytes = (cfg->word_len + 7) / 8;

	if (word_bytes == 3) word_bytes = 4;

	if (word_bytes == 1) {
		while ((dev->rx_received < dev->rx_len) && \
				(dev->regs->stat & RXNE)) {
			 *(dev->rx_buf + dev->rx_received) = \
				*(unsigned char*)(&dev->regs->rx);
			 dev->rx_received++;
		}
	} else if (word_bytes == 2) {
		while ((dev->rx_received < dev->rx_len) && \
				(dev->regs->stat & RXNE)) {
			*(unsigned short*)(dev->rx_buf + dev->rx_received) = \
				*(unsigned short*)(&dev->regs->rx);
			dev->rx_received += 2;
		}
	} else if (word_bytes == 4) {
		while ((dev->rx_received < dev->rx_len) && \
				(dev->regs->stat & RXNE)) {
			*(unsigned long*)(dev->rx_buf + dev->rx_received) = \
				*(unsigned long*)(&dev->regs->rx);
			dev->rx_received += 4;
		}
	}

	if (dev->rx_received >= dev->rx_len) {
		dev->regs->rcr1 &= ~RSPEN;
		dev->wait_con = 1;
		wake_up(&dev->waitq);
	}

	return IRQ_HANDLED;
}

static inline void sport_tx_write(struct sport_dev *dev)
{
	struct sport_config *cfg = &dev->config;
	int word_bytes = (cfg->word_len + 7) / 8;

	if (word_bytes == 3) word_bytes = 4;

	if (word_bytes == 1) {
		while ((dev->tx_sent < dev->tx_len) && \
				!(dev->regs->stat & TXF)) {
			*(unsigned char*)(&dev->regs->tx) = *(dev->tx_buf + \
					dev->tx_sent);
			dev->tx_sent++;
		}
	} else if (word_bytes == 2) {
		while ((dev->tx_sent < dev->tx_len) && \
				!(dev->regs->stat & TXF)) {
			*(unsigned short*)(&dev->regs->tx) = *(unsigned short*) \
					(dev->tx_buf + dev->tx_sent);
			dev->tx_sent += 2;
		}
	} else if (word_bytes == 4) {
		while ((dev->tx_sent < dev->tx_len) && \
				!(dev->regs->stat & TXF)) {
			dev->regs->tx = *(unsigned long*) \
					(dev->tx_buf + dev->tx_sent);
			dev->tx_sent += 4;
		}
	}
}

static irqreturn_t sport_tx_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	struct sport_dev *dev = dev_id;

	sport_tx_write(dev);

	return IRQ_HANDLED;
}

static irqreturn_t sport_err_handler(int irq, void *dev_id, struct pt_regs *regs)
{
	struct sport_dev *dev = dev_id;
	uint16_t status;

	pr_debug("%s enter\n", __FUNCTION__);
	status = dev->regs->stat;

	if (status & (TOVF|TUVF|ROVF|RUVF)) {
		dev->regs->stat = (status & (TOVF|TUVF|ROVF|RUVF));
		if (dev->config.dma_enabled) {
			disable_dma(dev->dma_rx_chan);
			disable_dma(dev->dma_tx_chan);
		}
		dev->regs->tcr1 &= ~TSPEN;
		dev->regs->rcr1 &= ~RSPEN;
		__builtin_bfin_ssync();

		if (!dev->config.dma_enabled) {
			if (status & TUVF) {
				dev->wait_con = 1;
				wake_up(&dev->waitq);
			}
		} else
			printk(KERN_WARNING "sport status error:%s%s%s%s\n",
					status & TOVF ? " TOVF" : "",
					status & TUVF ? " TUVF" : "",
					status & ROVF ? " ROVF" : "",
					status & RUVF ? " RUVF" : "");
	}

	return IRQ_HANDLED;
}

/*
 * Open and close
 */

static int sport_open(struct inode *inode, struct file *filp)
{
	struct sport_dev *dev; /* device information */

	dev = container_of(inode->i_cdev, struct sport_dev, cdev);
	filp->private_data = dev; /* for other methods */

	memset(&dev->config, 0, sizeof(struct sport_config));

	if (request_irq(dev->tx_irq, sport_tx_handler, SA_SHIRQ, "sport_tx", dev) < 0) {
		printk(KERN_ERR "Unable to request sport tx irq\n");
		goto fail;
	}

	if (request_irq(dev->rx_irq, sport_rx_handler, SA_SHIRQ, "sport_rx", dev) < 0) {
		printk(KERN_ERR "Unable to request sport rx irq\n");
		goto fail;
	}

	if (request_irq(dev->sport_err_irq, sport_err_handler, 0, "sport_err_irq", dev) < 0) {
		printk(KERN_ERR "Unable to request sport err irq\n");
		goto fail;
	}

#if defined(CONFIG_BF534) || defined(CONFIG_BF536) || defined(CONFIG_BF537)
	if (dev->sport_num == 0) {
		bfin_write_PORT_MUX(bfin_read_PORT_MUX() & ~(PJSE|PJCE(3)));
		__builtin_bfin_ssync();
	} if (dev->sport_num == 1) {
		bfin_write_PORT_MUX(bfin_read_PORT_MUX() | PGTE|PGRE|PGSE);
		bfin_write_PORTG_FER(bfin_read_PORTG_FER() | 0xFF00);
		__builtin_bfin_ssync();
	}
#endif
	return 0;

fail:
	free_dma(dev->dma_rx_chan);
	free_dma(dev->dma_tx_chan);

	return -EBUSY;
}

static int sport_release(struct inode *inode, struct file *filp)
{
	struct sport_dev *dev;

	dev = container_of(inode->i_cdev, struct sport_dev, cdev);

	if (dev->config.dma_enabled) {
		free_dma(dev->dma_rx_chan);
		free_dma(dev->dma_tx_chan);
	} else {
		free_irq(dev->tx_irq, dev);
		free_irq(dev->rx_irq, dev);
	}
	free_irq(dev->sport_err_irq, dev);

	return 0;
}

static ssize_t sport_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
	DECLARE_COMPLETION(done);
	struct sport_dev *dev = filp->private_data;
	struct sport_config *cfg = &dev->config;

	pr_debug("%s count:%ld\n", __FUNCTION__, count);

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;

	if (cfg->dma_enabled) {
		int word_bytes = (cfg->word_len + 7) / 8;
		uint16_t dma_config = 0;

		if (word_bytes == 3) word_bytes = 4;

		pr_debug("DMA mode read\n");
		/* Configure dma */
		set_dma_start_addr(dev->dma_rx_chan, (unsigned long)buf);
		set_dma_x_count(dev->dma_rx_chan, count / word_bytes);
		set_dma_x_modify(dev->dma_rx_chan, word_bytes);
		dma_config = (WNR | RESTART | sport_wordsize(cfg->word_len) | DI_EN);
		set_dma_config(dev->dma_rx_chan, dma_config);

		enable_dma(dev->dma_rx_chan);
	} else {
		dev->rx_buf = buf;
		dev->rx_len = count;
		dev->rx_received = 0;
	}

	dev->regs->rcr1 |= RSPEN;
	__builtin_bfin_ssync();

	wait_event_interruptible(dev->waitq, dev->wait_con);
	dev->wait_con = 0;

	pr_debug("Complete called in dma rx irq handler\n");
	up(&dev->sem);

	return count;
}

static void dump_dma_regs( void )
{
	dma_register_t *dma = (dma_register_t*)DMA4_NEXT_DESC_PTR;

	pr_debug(KERN_ERR " config:0x%04x, x_count:0x%04x,"
			" x_modify:0x%04x\n", dma->cfg,
			dma->x_count, dma->x_modify);
}

static ssize_t sport_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
	DECLARE_COMPLETION(done);
	struct sport_dev *dev = filp->private_data;
	struct sport_config *cfg = &dev->config;
	pr_debug("%s count:%ld  dma_tx_chan:%d\n",
			__FUNCTION__, count, dev->dma_tx_chan);

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;

	/* Configure dma to start transfer */
	if (cfg->dma_enabled) {
		uint16_t dma_config = 0;
		int word_bytes = (cfg->word_len + 7) / 8;

		if (word_bytes == 3) word_bytes = 4;

		pr_debug("DMA mode\n");
		/* Configure dma */
		set_dma_start_addr(dev->dma_tx_chan, (unsigned long)buf);
		set_dma_x_count(dev->dma_tx_chan, count / word_bytes);
		set_dma_x_modify(dev->dma_tx_chan, word_bytes);
		dma_config = (RESTART | sport_wordsize(cfg->word_len) | DI_EN);
		set_dma_config(dev->dma_tx_chan, dma_config);

		enable_dma(dev->dma_tx_chan);
		dump_dma_regs();
	/* Configure parameters to start PIO transfer */
	} else {
		dev->tx_buf = buf;
		dev->tx_len = count;
		dev->tx_sent = 0;

		sport_tx_write(dev);
	}
	dev->regs->tcr1 |= TSPEN;
	__builtin_bfin_ssync();

	wait_event_interruptible(dev->waitq, dev->wait_con );
	dev->wait_con = 0;
	up(&dev->sem);

	return count;
}

static int sport_ioctl(struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg)
{
	struct sport_dev *dev = filp->private_data;
	struct sport_config config;

	pr_debug("%s: enter, arg:0x%lx\n", __FUNCTION__, arg);
	switch (cmd) {
		case SPORT_IOC_CONFIG:
			copy_from_user(&config, (void*)arg,
					sizeof(struct sport_config));
			if (sport_configure(dev, &config) < 0)
				return -EFAULT;
			break;

		/* Test purpose */
		case ENABLE_AD73311:
#define GPIO_SE 4
			if (arg == 0) { /* Disable ad73311 */
				/* Pull down SE pin on AD73311 */
				*(unsigned short*)FIO_DIR |= (1 << GPIO_SE);
				*(unsigned short*)FIO_FLAG_C = (1 << GPIO_SE);
				__builtin_bfin_ssync();
			} else if (arg == 1) { /* Enable ad73311 */
				*(unsigned short*)FIO_DIR |= (1 << GPIO_SE);
				*(unsigned short*)FIO_FLAG_S = (1 << GPIO_SE);
				__builtin_bfin_ssync();
			}
			break;
		default:
		return -EINVAL;
	}

	return 0;
}

static struct file_operations sport_fops = {
	.owner =    THIS_MODULE,
	.read =     sport_read,
	.write =    sport_write,
	.ioctl =    sport_ioctl,
	.open =     sport_open,
	.release =  sport_release,
};

static void sport_cleanup_module(void)
{
	int i;
	dev_t devno = MKDEV(sport_major, sport_minor);

	if (sport_devices) {
		for (i = 0; i < sport_nr_devs; i++) {
			cdev_del(&sport_devices[i].cdev);
		}
		kfree(sport_devices);
	}

#ifdef SPORT_DEBUG
	sport_remove_proc();
#endif

	unregister_chrdev_region(devno, sport_nr_devs);
}

static void sport_setup_cdev(struct sport_dev *dev, int index)
{
	int err, devno = MKDEV(sport_major, sport_minor + index);

	cdev_init(&dev->cdev, &sport_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &sport_fops;
	err = cdev_add (&dev->cdev, devno, 1);
	if (err)
		printk(KERN_NOTICE "Error %d adding sport%d", err, index);
}

static int sport_init_module(void)
{
	int result, i;
	dev_t dev = 0;

	dev = MKDEV(sport_major, sport_minor);
	result = register_chrdev_region(dev, sport_nr_devs, "sport");

	if (result < 0) {
		printk(KERN_WARNING "sport: can't get major %d\n", sport_major);
		return result;
	}

       	sport_devices = kmalloc(sport_nr_devs * sizeof(struct sport_dev), GFP_KERNEL);
	if (!sport_devices) {
		result = -ENOMEM;
		goto fail;
	}
	memset(sport_devices, 0, sport_nr_devs * sizeof(struct sport_dev));

        /* Initialize each device. */
	for (i = 0; i < sport_nr_devs; i++) {
		sport_setup_cdev(&sport_devices[i], i);
		sport_devices[i].sport_num = i;
		init_MUTEX(&sport_devices[i].sem);
		init_waitqueue_head(&sport_devices[i].waitq);
	}
	sport_devices[0].regs = (struct sport_register*) 0xFFC00800;
	sport_devices[0].dma_rx_chan = CH_SPORT0_RX;
	sport_devices[0].dma_tx_chan = CH_SPORT0_TX;
	sport_devices[0].rx_irq = IRQ_SPORT0_RX;
	sport_devices[0].tx_irq = IRQ_SPORT0_TX;
	sport_devices[0].sport_err_irq = IRQ_SPORT0_ERROR;
	sport_devices[1].regs = (struct sport_register*) 0xFFC00900;
	sport_devices[1].dma_rx_chan = CH_SPORT1_RX;
	sport_devices[1].dma_tx_chan = CH_SPORT1_TX;
	sport_devices[1].rx_irq = IRQ_SPORT1_RX;
	sport_devices[1].tx_irq = IRQ_SPORT1_TX;
	sport_devices[1].sport_err_irq = IRQ_SPORT1_ERROR;

	return 0; /* succeed */

fail:
	sport_cleanup_module();
	return result;
}

module_init(sport_init_module);
module_exit(sport_cleanup_module);

MODULE_AUTHOR("Roy Huang <roy.huang@analog.com>");
MODULE_DESCRIPTION("Common sport driver for blackfin");
MODULE_LICENSE("GPL");
