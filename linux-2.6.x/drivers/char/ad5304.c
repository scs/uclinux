/*
 * File:         drivers/char/ad5304.c
 * Created:      Dec 2006
 * Description:  Control AD53{0,1,2}4 DACs over SPI
 *               Copyright 2006 Analog Devices Inc.
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
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/device.h>
#include <linux/spi/spi.h>
#include <linux/spinlock.h>
#include <asm/cacheflush.h>

#include <linux/ad5304.h>

#define DRIVER_NAME "ad5304"

#define pr_stamp() pr_debug(DRIVER_NAME ":%i:%s: here i am\n", __LINE__, __FUNCTION__)

#define NUM_AD5304_DEVS 1

struct ad5304_device {
	spinlock_t lock;
	int open_count;
	struct spi_device *spidev;
};
static struct ad5304_device ad5304_devices[NUM_AD5304_DEVS];
static DEFINE_SPINLOCK(ad5304_list_lock);

static struct ad5304_device *ad5304_find_by_minor(const int minor)
{
	int i;

	spin_lock(&ad5304_list_lock);

	/* locate the dac associated with this minor */
	for (i=0; i<NUM_AD5304_DEVS; ++i) {
		if (ad5304_devices[i].spidev && ad5304_devices[i].spidev->chip_select == minor) {
			spin_unlock(&ad5304_list_lock);
			return &ad5304_devices[i];
		}
	}

	spin_unlock(&ad5304_list_lock);

	return NULL;
}

static int ad5304_open(struct inode *inode, struct file *filp)
{
	struct ad5304_device *ad5304 = ad5304_find_by_minor(iminor(inode));

	if (!ad5304)
		return -ENODEV;

	pr_stamp();

	spin_lock(&ad5304->lock);

	if (ad5304->open_count) {
		spin_unlock(&ad5304->lock);
		return -EBUSY;
	}

	ad5304->open_count++;
	filp->private_data = ad5304->spidev;

	spin_unlock(&ad5304->lock);

	return 0;
}

static int ad5304_release(struct inode *inode, struct file *flip)
{
	struct ad5304_device *ad5304 = ad5304_find_by_minor(iminor(inode));

	if (!ad5304)
		return -ENODEV;

	pr_stamp();

	spin_lock(&ad5304->lock);

	ad5304->open_count--;

	spin_unlock(&ad5304->lock);

	return 0;
}

static int ad5304_ioctl(struct inode *inode, struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct spi_device *spi = filp->private_data; 

	pr_debug(DRIVER_NAME ": cmd=%X arg=%lX\n", cmd, arg);

	switch (cmd) {
		case AD5304_SET_DAC: {
			u8 cmd_buff[2];
			cmd_buff[0] = (arg & 0xFF);
			cmd_buff[1] = ((arg >> 8) & 0xFF);
			pr_debug(DRIVER_NAME ": setting dac to [%X,%X]\n", cmd_buff[0], cmd_buff[1]);
			return spi_write(spi, cmd_buff, sizeof(cmd_buff));
		}

		default:
			return -ENOIOCTLCMD;
	}

	return 0;
}

static struct file_operations ad5304_fops = {
	.owner   = THIS_MODULE,
	.ioctl   = ad5304_ioctl,
	.open    = ad5304_open,
	.release = ad5304_release,
};

static int __devinit ad5304_spi_probe(struct spi_device *spi)
{
	int i;

	pr_stamp();

	/* locate the next free entry in the list and bind this dac to it */
	spin_lock(&ad5304_list_lock);
	for (i=0; i<NUM_AD5304_DEVS; ++i)
		if (!ad5304_devices[i].spidev) {
			spin_lock_init(&ad5304_devices[i].lock);
			ad5304_devices[i].spidev = spi;
			dev_set_drvdata(&spi->dev, &ad5304_devices[i]);
			break;
		}
	spin_unlock(&ad5304_list_lock);

	printk(KERN_INFO DRIVER_NAME ": handling DAC on CS %i\n", spi->chip_select);

	return 0;
}

static int __devexit ad5304_spi_remove(struct spi_device *spi)
{
	struct ad5304_device *ad5304 = dev_get_drvdata(&spi->dev);

	pr_stamp();

	spin_lock(&ad5304_list_lock);
	ad5304->spidev = NULL;
	spin_unlock(&ad5304_list_lock);

	return 0;
}

static struct spi_driver ad5304_spi_driver = {
	.driver = {
		.name	= "ad5304_spi",
		.bus	= &spi_bus_type,
		.owner	= THIS_MODULE,
	},
	.probe	= ad5304_spi_probe,
	.remove	= __devexit_p(ad5304_spi_remove),
};

static int ad5304_device_major;

static int __init ad5304_spi_init(void)
{
	int ret;
	pr_stamp();

	ret = register_chrdev(0, DRIVER_NAME, &ad5304_fops);
	if (ret < 0) {
		printk(KERN_ERR DRIVER_NAME ": Unable to register character device (ret=%i)\n", ret);
		return ret;
	}
	ad5304_device_major = ret;

	memset(ad5304_devices, 0x00, sizeof(ad5304_devices));

	ret = spi_register_driver(&ad5304_spi_driver);
	if (ret) {
		unregister_chrdev(ad5304_device_major, DRIVER_NAME);
		return ret;
	}

	return 0;
}

static void __exit ad5304_spi_exit(void)
{
	pr_stamp();
	unregister_chrdev(ad5304_device_major, DRIVER_NAME);
	spi_unregister_driver(&ad5304_spi_driver);
}

module_init(ad5304_spi_init);
module_exit(ad5304_spi_exit);

MODULE_AUTHOR("Mike Frysinger <michael.frysinger@analog.com>");
MODULE_DESCRIPTION("Driver for AD5304/AD5314/AD5324 DACs over SPI");
MODULE_LICENSE("GPL");
