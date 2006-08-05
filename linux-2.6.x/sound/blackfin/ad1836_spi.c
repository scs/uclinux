/*
 * File:         sound/blackfin/ad1836_spi.c
 * Based on:
 * Author:       Roy Huang
 *
 * Created:
 * Description:  AD1836 SPI driver
 *
 * Rev:          $Id$
 *
 * Modified:
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

#include <linux/device.h>
#include <linux/init.h>
#include <linux/spi/spi.h>

#include "ad1836_spi.h"

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

void snd_ad1836_spi_probed(struct ad1836_spi *spi);

static int __devinit ad1836_spi_probe(struct spi_device *spi)
{
	struct ad1836_spi *chip;

	chip = kmalloc(sizeof(struct ad1836_spi), GFP_KERNEL);
	if (!chip)
		return -ENOMEM;
	dev_set_drvdata(&spi->dev, chip);
	spi->dev.power.power_state = PMSG_ON;

	chip->spi = spi;

	snd_ad1836_spi_probed(chip);

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

int ad1836_spi_init(void)
{
	return spi_register_driver(&ad1836_spi_driver);
}

void ad1836_spi_done(struct ad1836_spi* spi)
{
	spi_unregister_driver(&ad1836_spi_driver);
}
