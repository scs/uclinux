/*
 * AD1836 SPI driver
 *
 * Copyright (c) 2006 Analog Device Inc.
 * 
 * Author: Roy Huang
 * 
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/spi/spi.h>

#include "ad1836_spi.h"

static struct ad1836_spi *ad1836_spi = NULL;

struct ad1836_spi *ad1836_spi_setup(void)
{
	return ad1836_spi;
}

int ad1836_spi_read(struct ad1836_spi *spi, unsigned short data, 
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

int ad1836_spi_write(struct ad1836_spi *spi, unsigned short data)
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

static int __devinit ad1836_spi_probe(struct spi_device *spi)
{
	struct ad1836_spi	*chip;

	printk(KERN_INFO "%s is called\n", __FUNCTION__);
	chip = kmalloc(sizeof(struct ad1836_spi), GFP_KERNEL);
	if(!chip) {
		return -ENOMEM;	
	}
	dev_set_drvdata(&spi->dev, chip);
	spi->dev.power.power_state = PMSG_ON;

	chip->spi = spi;
	ad1836_spi = chip;	

	return 0;
}

static int __devexit ad1836_spi_remove(struct spi_device *spi)
{
	struct ad1836_spi *chip = dev_get_drvdata(&spi->dev);
	kfree(chip);

	return 0;
}

static struct spi_driver ad1836_spi_driver = {
	.driver = {
		.name	= "ad1836-spi",
		.bus	= &spi_bus_type,
		.owner	= THIS_MODULE,
	},
	.probe		= ad1836_spi_probe,
	.remove		= __devexit_p(ad1836_spi_remove),
};

static int __init ad1836_spi_init(void)
{
	return spi_register_driver(&ad1836_spi_driver);
}
module_init(ad1836_spi_init);

static void __exit ad1836_spi_exit(void)
{
	spi_unregister_driver(&ad1836_spi_driver);
}
module_exit(ad1836_spi_exit);

MODULE_DESCRIPTION("AD1836 SPI driver");
MODULE_LICENSE("GPL");
