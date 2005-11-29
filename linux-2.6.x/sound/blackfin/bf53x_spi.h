/*
 * File:         bf53x_spi.h 
 * Description:  low level driver for SPI port on blackfin 53x
 *               this should be moved to arch/blackfin/
 * Rev:          $Id$
 * Created:      Tue Sep 21 10:52:42 CEST 2004
 * Author:       Luuk van Dijk
 * mail:         blackfin@mdnmttr.nl
 * 
 * Copyright (C) 2004 Luuk van Dijk, Mind over Matter B.V.
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

#ifndef BF53X_SPI_H
#define BF53X_SPI_H

#include <linux/types.h>
#include <asm/bfin_spi_channel.h>

/* a callback function that is called from the IRQ handler when dma transmit or 
 * receive, or a single word transceive is done */

struct bf53x_spi {
  spi_device_t spi_ad1836_dev;
  int(*callback)(struct bf53x_spi* spi, void* priv);
  void* private;

  unsigned int rx_data;
  void* buf;
  size_t len;
};

typedef int (*spi_callback)(struct bf53x_spi* spi, void* priv);

struct bf53x_spi* bf53x_spi_init(spi_callback callback, void* priv);

void bf53x_spi_done(struct bf53x_spi* spi);

/* transmit/receive a single byte or word over a channel */
int bf53x_spi_transceive(struct bf53x_spi* spi, unsigned short data);

#endif /* BF53X_SPI_H */
