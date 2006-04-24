/*
 * File:        arch/blackfin/mach-bf533/stamp.c
 * Based on:    arch/blackfin/mach-bf533/ezkit.c
 * Author:      Aidan Williams <aidan@nicta.com.au>
 *                Copyright 2005 National ICT Australia (NICTA)
 * Created:     2005
 * Description: Board Info File for the BF533-STAMP
 *
 * Rev:         $Id$
 *
 * Modified:
 *
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

#include <linux/device.h>
#include <linux/platform_device.h>
#include <asm/irq.h>

/*
 * Name the Board for the /proc/cpuinfo
 */
char *bfin_board_name = "ADDS-BF533-STAMP";

/*
 *  Driver needs to know address, irq and flag pin.
 */
static struct resource smc91x_resources[] = {
	[0] = {
	       .start = 0x20300300,
	       .end = 0x20300300 + 16,
	       .flags = IORESOURCE_MEM,
	       },
	[1] = {
	       .start = IRQ_PROG_INTB,
	       .end = IRQ_PROG_INTB,
	       .flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
	       },
	[2] = {
	       /*
	        *  denotes the flag pin and is used directly if
	        *  CONFIG_IRQCHIP_DEMUX_GPIO is defined.
	        */
	       .start = IRQ_PF7,
	       .end = IRQ_PF7,
	       .flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
	       },
};
static struct platform_device smc91x_device = {
	.name = "smc91x",
	.id = 0,
	.num_resources = ARRAY_SIZE(smc91x_resources),
	.resource = smc91x_resources,
};

#ifdef CONFIG_USB_NET2272
static struct resource net2272_bfin_resources[] = {
	[0] = 	{
		.start = 0x20300000,
		.end = 0x20300000 + 0x100,
		.flags = IORESOURCE_MEM,
		},
	[1] =	{
		.start = IRQ_PF10,
		.end = IRQ_PF10,
		.flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
		},
};

static struct platform_device net2272_bfin_device = {
	.name = "net2272",
	.id = -1,
	.num_resources = ARRAY_SIZE(net2272_bfin_resources),
	.resource = net2272_bfin_resources,
};
#endif

#ifdef CONFIG_SPI_BFIN
/* all SPI perpherals info goes here */

static struct mtd_partition bfin_spi_flash_partitions[] = {
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

static struct flash_platform_data bfin_spi_flash_data = {
	.name	        = "m25p80",
	.parts		= bfin_spi_flash_partitions,
	.nr_parts	= ARRAY_SIZE(bfin_spi_flash_partitions),
	.type           = "m25p64",
};

/* SPI flash chip (m25p64) */
static struct bfin5xx_spi_chip spi_flash_chip_info = {
	.ctl_reg = 0x1C00,       /* with enable bit unset */
	.enable_dma = 0,    /* use dma transfer with this chip*/
	.bits_per_word = 8,
};

/* SPI ADC chip */
static struct bfin5xx_spi_chip spi_adc_chip_info = {
	.ctl_reg = 0x1C00,
	.enable_dma = 1,    /* use dma transfer with this chip*/
	.bits_per_word = 16,
};

/* Notice: for blackfin, the speed_hz is the value of register
   SPI_BAUD, not the real baudrate */
static struct spi_board_info bfin_spi_board_info[] __initdata = {
       {
	       /* the modalias must be the same as spi device driver name */
               .modalias = "m25p80", /* Name of spi_driver for this device */
	       /* this value is the baudrate divisor */
               .max_speed_hz = 2,     /* actual baudrate is SCLK/(2xspeed_hz) */
               .bus_num = 1, /* Framework bus number */
               .chip_select = 1, /* Framework chip select. On STAMP537 it is SPISSEL1*/
               .platform_data = &bfin_spi_flash_data,
               .controller_data = &spi_flash_chip_info,
       },
       {
               .modalias = "bfin_spi_adc", /* Name of spi_driver for this device */
               .max_speed_hz = 4,     /* actual baudrate is SCLK/(2xspeed_hz) */
               .bus_num = 1, /* Framework bus number */
               .chip_select = 2, /* Framework chip select. */
               .platform_data = NULL, /* No spi_driver specific config */
               .controller_data = &spi_adc_chip_info,
       },
};

/* SPI controller data */
static struct bfin5xx_spi_master spi_bfin_master_info = {
	.num_chipselect = 8,
	.enable_dma = 1,  /* master has the ability to do dma transfer */
};

static struct platform_device spi_bfin_master_device = {
	.name = "bfin-spi-master",
	.id = 1, /* Bus number */
	.dev = {
		.platform_data = &spi_bfin_master_info, /* Passed to driver */
	},
};
#endif  /* spi master and devices */

#ifdef CONFIG_FB_BF537_LQ035
static struct platform_device bfin_fb_device = {
	.name = "bf537-fb",
};
#endif

static struct platform_device *stamp_devices[] __initdata = {
	&smc91x_device,
#ifdef CONFIG_USB_NET2272
	&net2272_bfin_device,
#endif
#ifdef CONFIG_SPI_BFIN
	&spi_bfin_master_device,
#endif
};

static int __init stamp_init(void)
{
	printk("%s(): registering device resources\n", __FUNCTION__);
	platform_add_devices(stamp_devices, ARRAY_SIZE(stamp_devices));
#ifdef CONFIG_SPI_BFIN
	spi_register_board_info(bfin_spi_board_info,
			       ARRAY_SIZE(bfin_spi_board_info));
#endif
	return 0;
}

arch_initcall(stamp_init);
