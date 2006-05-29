/*
 * File:         ad1836_spi.h
 * Description:  ad1836 spi driver.
 * Rev:          $Id:
 * Created:      2006-04-17
 * Author:       Roy Huang
 * 
 * Copyright (C) 2006 Analog Device Inc.
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
