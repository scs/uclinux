 /*
  * File:        arch/blackfin/mach-bf537/boards/cm_bf537.c
  * Based on:   arch/blackfin/mach-bf533/boards/ezkit.c
  * Author:      Aidan Williams <aidan@nicta.com.au>
  *                Copright 2005
  * Created:     2005
  * Description: Board description file
  *
  * Rev:         $Id$
  *
  * Modified:
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
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>
#include <linux/spi/spi.h>
#include <linux/spi/flash.h>
#include <linux/usb_isp1362.h>
#include <asm/irq.h>
#include <asm/bfin5xx_spi.h>


#if defined(CONFIG_SPI_BFIN) || defined(CONFIG_SPI_BFIN_MODULE)
/* all SPI perpherals info goes here */

#if defined(CONFIG_MTD_M25P80) \
	|| defined(CONFIG_MTD_M25P80_MODULE)
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
#endif

#if defined(CONFIG_SPI_ADC_BF533) \
	|| defined(CONFIG_SPI_ADC_BF533_MODULE)
/* SPI ADC chip */
static struct bfin5xx_spi_chip spi_adc_chip_info = {
	.ctl_reg = 0x1500,
	.enable_dma = 1,    /* use dma transfer with this chip*/
	.bits_per_word = 16,
};
#endif

#if defined(CONFIG_SND_BLACKFIN_AD1836) \
	|| defined(CONFIG_SND_BLACKFIN_AD1836_MODULE)
static struct bfin5xx_spi_chip ad1836_spi_chip_info = {
	.ctl_reg = 0x1000,
	.enable_dma = 0,
	.bits_per_word = 16,
};
#endif


/* Notice: for blackfin, the speed_hz is the value of register
   SPI_BAUD, not the real baudrate */
static struct spi_board_info bfin_spi_board_info[] __initdata = {
#if defined(CONFIG_MTD_M25P80) \
	|| defined(CONFIG_MTD_M25P80_MODULE)
       {
	       /* the modalias must be the same as spi device driver name */
               .modalias = "m25p80", /* Name of spi_driver for this device */
	       /* this value is the baudrate divisor */
               .max_speed_hz = 2,     /* actual baudrate is SCLK/(2xspeed_hz) */
               .bus_num = 1, /* Framework bus number */
               .chip_select = 2, /* Framework chip select. On STAMP537 it is SPISSEL1*/
               .platform_data = &bfin_spi_flash_data,
               .controller_data = &spi_flash_chip_info,
       },
#endif

#if defined(CONFIG_SPI_ADC_BF533) \
	|| defined(CONFIG_SPI_ADC_BF533_MODULE)
       {
               .modalias = "bfin_spi_adc", /* Name of spi_driver for this device */
               .max_speed_hz = 8,     /* actual baudrate is SCLK/(2xspeed_hz) */
               .bus_num = 1, /* Framework bus number */
               .chip_select = 1, /* Framework chip select. */
               .platform_data = NULL, /* No spi_driver specific config */
               .controller_data = &spi_adc_chip_info,
       },
#endif

#if defined(CONFIG_SND_BLACKFIN_AD1836) \
	|| defined(CONFIG_SND_BLACKFIN_AD1836_MODULE)
	{
		.modalias = "ad1836-spi",
		.max_speed_hz = 16,
		.bus_num = 1,
		.chip_select = CONFIG_SND_BLACKFIN_SPI_PFBIT,
		.controller_data = &ad1836_spi_chip_info,
	},
#endif
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


#if defined(CONFIG_SMC91X) || defined(CONFIG_SMC91X_MODULE)
static struct resource smc91x_resources[] = {
	[0] = {
	       .start = 0x20200300,
	       .end = 0x20200300 + 16,
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
	       .start = IRQ_PF0,
	       .end = IRQ_PF0,
	       .flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
	       },
};
static struct platform_device smc91x_device = {
	.name = "smc91x",
	.id = 0,
	.num_resources = ARRAY_SIZE(smc91x_resources),
	.resource = smc91x_resources,
};
#endif

#if defined(CONFIG_USB_ISP1362_HCD) || defined(CONFIG_USB_ISP1362_HCD_MODULE)
static struct resource isp1362_hcd_resources[] = {
	[0] = {
	       .start = 0x20308000,
	       .end = 0x20308000,
	       .flags = IORESOURCE_MEM,
	       },
	[1] = {
	       .start = 0x20308002,
	       .end = 0x20308002,
	       .flags = IORESOURCE_MEM,
	       },
	[2] = {
		.start = IRQ_PROG_INTA,
		.end = IRQ_PROG_INTA,
		.flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
		},
	[3] = {
	       .start = IRQ_PF0 + CONFIG_USB_ISP1362_BFIN_GPIO,
	       .end = IRQ_PF0 + CONFIG_USB_ISP1362_BFIN_GPIO,
	       .flags = IORESOURCE_IRQ,
	       },

};

static struct isp1362_platform_data isp1362_priv = {
	.sel15Kres	= 1,
	.clknotstop	= 0,
	.oc_enable	= 0,
	.int_act_high	= 0,
	.int_edge_triggered	= 0,
	.remote_wakeup_connected	= 0,
	.no_power_switching	= 1,
	.power_switching_mode	= 0,
};

static struct platform_device isp1362_hcd_device = {
	.name = "isp1362-hcd",
	.id = 0,
	.dev = {
		.platform_data = &isp1362_priv,
	},
	.num_resources = ARRAY_SIZE(isp1362_hcd_resources),
	.resource = isp1362_hcd_resources,
};
#endif

static struct platform_device bfin_mac_device = {
	.name = "bfin_mac",
};

static struct platform_device *cm_bf537_devices[] __initdata = {
#if defined(CONFIG_USB_ISP1362_HCD) || defined(CONFIG_USB_ISP1362_HCD_MODULE)
	&isp1362_hcd_device,
#endif
#if defined(CONFIG_SMC91X) || defined(CONFIG_SMC91X_MODULE)
	&smc91x_device,
#endif

	&bfin_mac_device,


#if defined(CONFIG_SPI_BFIN) || defined(CONFIG_SPI_BFIN_MODULE)
	&spi_bfin_master_device,
#endif

};

static int __init cm_bf537_init(void)
{
	printk("%s(): registering device resources\n", __FUNCTION__);
	return platform_add_devices(cm_bf537_devices,
				    ARRAY_SIZE(cm_bf537_devices));
}

void get_bf537_ether_addr(char *addr)
{
	/* currently the mac addr is saved in flash */
	int flash_mac = 0x203f0000;
	*(u32 *)(&(addr[0])) = *(int *)flash_mac;
	flash_mac += 4;
	*(u16 *)(&(addr[4])) = (u16)*(int *)flash_mac;
}

EXPORT_SYMBOL(get_bf537_ether_addr);

arch_initcall(cm_bf537_init);
