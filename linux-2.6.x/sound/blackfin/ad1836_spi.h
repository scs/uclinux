/*
 * File:         sound/blackfin/ad1836_spi.h
 * Based on:
 * Author:       Roy Huang
 *
 * Created:      2006-04-17
 * Description:  ad1836 spi driver.
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

#ifndef __AD1836_SPI_H__
#define __AD1836_SPI_H__

struct ad1836_spi {
	struct spi_device *spi;
};

int ad1836_spi_init(void);

void ad1836_spi_done(struct ad1836_spi *spi);

int ad1836_spi_read(struct ad1836_spi *spi, unsigned short data, unsigned short *buf);

int ad1836_spi_write(struct ad1836_spi *spi, unsigned short data);

#endif
