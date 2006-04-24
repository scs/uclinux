/************************************************************
*
* Copyright (C) 2004, Analog Devices. All Rights Reserved
*
* FILE adsp-spiadc.c
* PROGRAMMER(S): Michael Hennerich (Analog Devices Inc.)
*
*
* DATE OF CREATION: Sept. 10th 2004
*
* SYNOPSIS:
*
* DESCRIPTION: SPI-ADC/DAC Driver for ADSP-BF533/2/1. It can
*              only be used in linux.
**************************************************************
* MODIFICATION HISTORY:
* March 10, 2006  Modify to use new SPI common frame work. (Luke Yang)
********************************************************/


#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/string.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/spi/spi.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/blackfin.h>
#include <asm/cacheflush.h>
#include <asm/bfin5xx_spi.h>
#include <asm/dma.h>

#ifdef DEBUG
#define DPRINTK(x...)	printk(x)
#else
#define DPRINTK(x...)	do { } while (0)
#endif

#define SKFS		       4  /* number of first samples to skip */

#define TOL 		       5

#define TIMEOUT		       50


#define TIMEOUT		   50

#define SPI_ADC_MAJOR          252   /* experiential */
#define SPI0_ADC_MINOR         0

#define SPI_ADC_DEVNAME       "BFIN_SPI_ADC"
#define SPI_ADC_INTNAME       "BFIN_SPIINT"  /* Should be less than 19 chars. */

struct bfin_spi_adc {
	int     opened;
	int     timeout;
	unsigned char 	sense;
	unsigned char 	edge;
	unsigned int     triggerpos;
	unsigned int     actcount;
	unsigned short   *buffer;
	unsigned short 	level;
	unsigned char 	mode;
	unsigned char 	cont;
	int     baud;

	struct spi_device	*spidev;
};

struct bfin_spi_adc spi_adc;

static u_long spi_get_sclk(void)
{
	u_long vco;
	u_long sclk = 0;

	vco = (CONFIG_CLKIN_HZ) * ((*pPLL_CTL >> 9)& 0x3F);

	if (1 & *pPLL_CTL) /* DR bit */
		vco >>= 1;

	if((*pPLL_DIV & 0xf) != 0)
		sclk = vco/(*pPLL_DIV & 0xf);
	else
		printk("Invalid System Clock\n");

	return (sclk);
}

static int adc_spi_ioctl(struct inode *inode, struct file *filp, uint cmd, unsigned long arg)
{
	unsigned long value;
	struct bfin_spi_adc *bfin_spi_adc = filp->private_data;

	switch (cmd) {
	case CMD_SPI_SET_TRIGGER_MODE:
	{
		DPRINTK("spi_ioctl: CMD_SPI_SET_TRIGGER_MODE \n");
		bfin_spi_adc->mode = (unsigned char)arg;
		break;
	}
	case CMD_SPI_SET_TRIGGER_SENSE:
	{
		DPRINTK("spi_ioctl: CMD_SPI_SET_TRIGGER_SENSE \n");
		bfin_spi_adc->sense = (unsigned char)arg;
		break;
	}
	case CMD_SPI_SET_TRIGGER_EDGE:
	{
		DPRINTK("spi_ioctl: CMD_SPI_SET_TRIGGER_EDGE \n");
		bfin_spi_adc->edge = (unsigned char)arg;
		break;
	}
	case CMD_SPI_SET_TRIGGER_LEVEL:
	{
		DPRINTK("spi_ioctl: CMD_SPI_SET_TRIGGER_LEVEL \n");
		bfin_spi_adc->level = (unsigned short)arg;
		break;
	}
	case CMD_SPI_GET_SYSTEMCLOCK:
	{
		value = spi_get_sclk();
		copy_to_user((unsigned long *)arg, &value, sizeof(unsigned long));
		break;
	}
	case CMD_SPI_SET_BAUDRATE:
        {
		DPRINTK("spi_ioctl: CMD_SPI_SET_BAUDRATE \n");
		/* BaudRate 0,1 unavail */
		if((unsigned short)arg <= 1)
			return -EINVAL;
		/* SPI's baud rate is SCLK / ( arg * 2) */
		bfin_spi_adc->baud = (unsigned short)arg;
		break;
        }
	default:
		return -EINVAL;
	}
	return 0;
}

static ssize_t adc_spi_read (struct file *filp, char *buf, size_t count, loff_t *pos)
{
	struct spi_transfer t;
	struct spi_message m;
	int i;
	int repeat_reading;
	struct bfin_spi_adc *bfin_spi_adc = filp->private_data;
	repeat_reading = 0;

	if(count <= 0)
		return 0;

	bfin_spi_adc->actcount = count;
	bfin_spi_adc->timeout = TIMEOUT;

	/* Allocate some memory */
	bfin_spi_adc->buffer = kmalloc((count+SKFS*2)*2,GFP_KERNEL);

	/* Invalidate allocated memory in Data Cache */
	blackfin_dcache_invalidate_range((unsigned long)bfin_spi_adc->buffer,((unsigned long) bfin_spi_adc->buffer)+(count+SKFS*2)*2);

	spi_message_init(&m);
	memset(&t, 0, (sizeof &t));
	t.rx_buf = bfin_spi_adc->buffer;
	t.len = count + SKFS;

	do {
		spi_message_add_tail(&t, &m);
		spi_sync(bfin_spi_adc->spidev, &m);

		bfin_spi_adc->triggerpos=0;

		if(bfin_spi_adc->mode) {
			/* Search for trigger condition */
			if(bfin_spi_adc->sense) {
				/* Edge sensitive */
				if(bfin_spi_adc->edge){
					/* Falling edge */
					bfin_spi_adc->triggerpos=0;
					for(i=1+SKFS;(i < bfin_spi_adc->actcount)&& !bfin_spi_adc->triggerpos;i++) {
						if ((bfin_spi_adc->buffer[i-1] > bfin_spi_adc->level)&&(bfin_spi_adc->buffer[i+1] < bfin_spi_adc->level)) {
							bfin_spi_adc->triggerpos=i;
							i=bfin_spi_adc->actcount;
						}
					}
					if(!bfin_spi_adc->triggerpos && bfin_spi_adc->timeout--) repeat_reading = 1;

				} else {
					/* Rising edge */
					bfin_spi_adc->triggerpos=0;
					for(i=1+SKFS;(i < bfin_spi_adc->actcount)&& !bfin_spi_adc->triggerpos;i++) {

						if ((bfin_spi_adc->buffer[i-1] < bfin_spi_adc->level)&&(bfin_spi_adc->buffer[i+1] > bfin_spi_adc->level)) {
							bfin_spi_adc->triggerpos=i;
							i=bfin_spi_adc->actcount;
						}
					}

					if(!bfin_spi_adc->triggerpos && bfin_spi_adc->timeout--) repeat_reading = 1;
				}
			} else {
				if(bfin_spi_adc->edge){
					/* Falling edge */
					bfin_spi_adc->triggerpos=0;
					for(i=1+SKFS;(i < bfin_spi_adc->actcount)&& !bfin_spi_adc->triggerpos;i++) {
						if ((bfin_spi_adc->buffer[i-1] > bfin_spi_adc->level)&&(bfin_spi_adc->buffer[i+1] < bfin_spi_adc->level)) {
							bfin_spi_adc->triggerpos=i;
							i=bfin_spi_adc->actcount;
						}
					}
					if(!bfin_spi_adc->triggerpos && bfin_spi_adc->timeout--) repeat_reading = 1;
				} else {
					/* Rising edge */
					bfin_spi_adc->triggerpos=0;
					for(i=1+SKFS;(i < bfin_spi_adc->actcount)&& !bfin_spi_adc->triggerpos;i++) {
						if ((bfin_spi_adc->buffer[i-1] < bfin_spi_adc->level)&&(bfin_spi_adc->buffer[i+1] > bfin_spi_adc->level)) {
							bfin_spi_adc->triggerpos=i;
							i=bfin_spi_adc->actcount;
						}
					}

					if(!bfin_spi_adc->triggerpos && bfin_spi_adc->timeout--) repeat_reading = 1;
				}
			}
		}
	} while (repeat_reading);

	if(!(bfin_spi_adc->timeout < 0) && (!bfin_spi_adc->triggerpos))
		copy_to_user(buf, bfin_spi_adc->buffer + SKFS, count);
	else
		copy_to_user(buf, bfin_spi_adc->buffer + bfin_spi_adc->triggerpos, count);

	kfree(bfin_spi_adc->buffer);

	DPRINTK(" timeout = %d \n",bfin_spi_adc->timeout);
	if(bfin_spi_adc->timeout < 0)
		return SPI_ERR_TRIG;

	return count;
}

static ssize_t adc_spi_write (struct file *filp, const char *buf, size_t count, loff_t *f_pos)
{
	struct spi_transfer t;
	struct spi_message m;
	struct bfin_spi_adc *bfin_spi_adc = filp->private_data;

	DPRINTK("spi_write: \n");

	if(count <= 0)
		return 0;

	bfin_spi_adc->actcount = count;
	bfin_spi_adc->timeout = TIMEOUT;

	blackfin_dcache_flush_range((unsigned long)buf,((unsigned long)buf+(count)));

	spi_message_init(&m);
	memset(&t, 0, (sizeof &t));
	t.tx_buf = buf;
	t.len = count;

	spi_message_add_tail(&t, &m);
	spi_sync(bfin_spi_adc->spidev, &m);

	DPRINTK("spi_write: return \n");
	return count;
}

static int adc_spi_open (struct inode *inode, struct file *filp)
{
    struct spi_device *spi;
    int minor = MINOR (inode->i_rdev);

    /* SPI ? */
    if(minor != SPI0_ADC_MINOR) return -ENXIO;

    if(spi_adc.opened)
        return -EMFILE;

    spi = spi_adc.spidev;
    /* Clear configuration information */
    memset(&spi_adc, 0, sizeof(struct bfin_spi_adc));

    spi_adc.opened = 1;
    spi_adc.cont = 0;
    spi_adc.spidev = spi;

    filp->private_data = &spi_adc;


    DPRINTK("spi_open: return \n");
    return 0;
}

static int adc_spi_release (struct inode *inode, struct file *filp)
{
    spi_adc.opened = 0;

    DPRINTK("spi_release: close() return \n");
    return 0;
}

static struct file_operations bfin_spi_adc_fops = {
    .owner = THIS_MODULE,
    .read = adc_spi_read,
    .write = adc_spi_write,
    .ioctl = adc_spi_ioctl,
    .open = adc_spi_open,
    .release = adc_spi_release,
};

static int __devinit bfin_spi_adc_probe(struct spi_device *spi)
{
	int result;

	spi_adc.spidev = spi;

	result = register_chrdev(SPI_ADC_MAJOR, SPI_ADC_DEVNAME, &bfin_spi_adc_fops);
	printk("spi_adc; major number is %d ***************\n",result);
	if (result < 0)
	{
		printk(KERN_WARNING "SPI: can't get minor %d\n", SPI_ADC_MAJOR);
		return result;
	}
	return 0;
}

static int __devexit bfin_spi_adc_remove(struct spi_device *spi)
{
	unregister_chrdev(SPI_ADC_MAJOR, SPI_ADC_DEVNAME);
	printk("<1>Goodbye SPI \n");
	return 0;
}

static struct spi_driver bfin_spi_adc_driver = {
	.driver = {
		.name	= "bfin_spi_adc",
		.bus	= &spi_bus_type,
		.owner	= THIS_MODULE,
	},
	.probe	= bfin_spi_adc_probe,
	.remove	= __devexit_p(bfin_spi_adc_remove),
};

static int bfin_spi_adc_init(void)
{
	return spi_register_driver(&bfin_spi_adc_driver);
}


static void bfin_spi_adc_exit(void)
{
	spi_unregister_driver(&bfin_spi_adc_driver);
}

module_init(bfin_spi_adc_init);
module_exit(bfin_spi_adc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Luke Yang");
