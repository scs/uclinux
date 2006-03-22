/*
 * File:         drivers/mtd/maps/bf5xx-spi-flash.c
 * Based on:     drivers/mtd/maps/bf5xx-flash.c
 * Author:	 Aubrey.li <aubrey.li@analog.com>
 *
 * Created:
 * Description:  SPI Flash memory access on BlackFin BF5xx based devices
 *		 So far the driver is desiged for STM25P64/STM25P32.
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
#include <linux/config.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>

#include <linux/mtd/mtd.h>
#include <linux/mtd/map.h>
#include <linux/mtd/partitions.h>

#include <asm/blackfin.h>
#include <asm/bfin_spi_channel.h>

spi_device_t spi_mtd_dev;

#ifndef CONFIG_BFIN
#error This is for BlackFin BF533 boards only
#endif

#define BAUD_RATE_DIVISOR 2
#define SPI_COM_READ            (0x03)  /* Read data from memory */
#define SPI_COM_RDSR            (0x05)  /* Read Status Register */

static void spi_ready(void);
static void spi_setup(void);
static void spi_read_data(unsigned long start, long count,int *pndata  );

static void spi_setup(void)
{
#if defined(CONFIG_BLKFIN_CACHE) || defined(CONFIG_BLKFIN_DCACHE)
	udelay(get_cclk()/50000000);
#endif
	spi_mtd_dev.bdrate = BAUD_RATE_DIVISOR;
	spi_mtd_dev.phase = CFG_SPI_PHASESTART;
	spi_mtd_dev.polar = CFG_SPI_ACTLOW;
	spi_mtd_dev.master = CFG_SPI_MASTER;
#ifdef CONFIG_BF533
	spi_mtd_dev.flag = 0xFB04;
#endif
#ifdef CONFIG_BF537
	spi_mtd_dev.flag = 0xFD02;
#endif
	spi_mtd_dev.dma  = 0;
	spi_mtd_dev.ti_mod = BIT_CTL_TXMOD;
	spi_channel_request(&spi_mtd_dev);
}

static void spi_ready(void)
{
        unsigned short data;
	do{
	spi_get_stat(&data);
	} while( (data&TXS) || !(data&SPIF) || !(data&RXS));
	/* Read dummy to empty rx register */
	spi_receive_data();
}

static void spi_read_data(unsigned long start, long count,int *pndata  )
{
	unsigned long shiftvalue;
	char *cndata;
	int i,flags;

	cndata = (char *)pndata; /* Pointer cast to be able to increment byte wise */
	/* Start SPI interface*/
	spi_setup();
	local_irq_save(flags);
	spi_enable(&spi_mtd_dev);
	/* Send the read command to SPI device */
	spi_send_data(SPI_COM_READ);
	spi_ready();
	/* Send the highest byte of the 24 bit address at first */
	shiftvalue = (start >> 16);
	spi_send_data(shiftvalue);
	spi_ready();
	/* Send the middle byte of the 24 bit address  at second */
	shiftvalue = (start >> 8);
	spi_send_data(shiftvalue);
	spi_ready();
	 /* Send the lowest byte of the 24 bit address finally */
	spi_send_data(start);
	spi_ready();

	/* After the SPI device address has been placed on the MOSI pin the data can be
	 received on the MISO pin. */
	for (i=0; i<count; i++)
	{
		spi_send_data(0);		/* send dummy */
		spi_ready();
		*cndata++  = (unsigned char)spi_receive_data();
	}
	spi_disable(&spi_mtd_dev);
	local_irq_restore(flags);
	udelay(get_cclk()/50000000);
	spi_channel_release(&spi_mtd_dev);
}
static map_word bf533_read(struct map_info *map, unsigned long ofs)
{
	int nValue = 0x0;
	map_word test;
	spi_read_data(ofs, sizeof(__u16), &nValue);
	test.x[0]=(__u16)nValue;
	return test;	
}

static void bf533_copy_from(struct map_info *map, void *to, unsigned long from, ssize_t len)
{
	spi_read_data(from, len, (int *)to);
}

static void bf533_write(struct map_info *map, map_word d1, unsigned long ofs)
{
	printk(KERN_NOTICE "####################bf533 copy to not implement##################\n");
}

static void bf533_copy_to(struct map_info *map, unsigned long to, const void *from, ssize_t len)
{
	printk(KERN_NOTICE "####################bf533 copy to not implement##################\n");
}

static struct map_info bf533_map = {
	name:    	"BF533 SPI flash",
	0x800000,
	0x0,
	0x0,
	NULL,		
	read:		bf533_read,
	copy_from:	bf533_copy_from,
	write:		bf533_write,
	copy_to:	bf533_copy_to
};


/*
 * Here are partition information for all known BlackFin-based devices.
 * See include/linux/mtd/partitions.h for definition of the mtd_partition
 * structure.
 * 
 * The *_max_flash_size is the maximum possible mapped flash size which
 * is not necessarily the actual flash size.  It must correspond to the 
 * value specified in the mapping definition defined by the
 * "struct map_desc *_io_desc" for the corresponding machine.
 */

static unsigned long bf533_max_flash_size = 0x00800000;

static struct mtd_partition bf533_partitions[] = {
	{
		name: "bootloader",
		size: 0x00040000,
		offset: 0,
		mask_flags: MTD_CAP_ROM
	},{
		name: "kernel",
		size: 0xc0000,
		offset: 0x40000
	},{
		name: "file system", 
		size: 0x300000,
		offset: 0x00100000,
	}	
};

#define NB_OF(x)  (sizeof(x)/sizeof(x[0]))


static struct mtd_info *mymtd;

int __init bf533_mtd_init(void)
{
	struct mtd_partition *parts;
	int nb_parts = 0;
	char *part_type;

	bf533_map.bankwidth = 1;
	bf533_map.size = bf533_max_flash_size;

	printk(KERN_NOTICE "BF533 SPI flash: probing %d-bit flash bus\n", bf533_map.bankwidth*8);
	mymtd = do_map_probe("stm_spi_flash", &bf533_map);
	if (!mymtd)
		return -ENXIO;

	/*
	 * Static partition definition selection
	 */
	part_type = "static";
#ifdef CONFIG_BFIN
	parts = bf533_partitions;
	nb_parts = NB_OF(bf533_partitions);
#endif

	if (nb_parts == 0) {
		printk(KERN_NOTICE "BF533 SPI flash: no partition info available, registering whole flash at once\n");
		add_mtd_device(mymtd);
	} else {
		printk(KERN_NOTICE "Using %s partition definition\n", part_type);
		add_mtd_partitions(mymtd, parts, nb_parts);
	}
	return 0;
}

static void __exit bf533_mtd_cleanup(void)
{
	if (mymtd) {
		del_mtd_partitions(mymtd);
		map_destroy(mymtd);
	}
}

module_init(bf533_mtd_init);
module_exit(bf533_mtd_cleanup);

MODULE_LICENSE("GPL");
