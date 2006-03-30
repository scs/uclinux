 /*
  * File:        arch/blackfin/mach-bf533/boards/cm_bf533.c
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
#include <linux/usb_isp1362.h>
#include <asm/irq.h>

/*
 *  USB-LAN EzExtender board
 *  Driver needs to know address, irq and flag pin.
 */
#ifdef CONFIG_SMC91X
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

#ifdef CONFIG_USB_ISP1362_HCD
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

static struct platform_device *cm_bf533_devices[] __initdata = {
#ifdef CONFIG_USB_ISP1362_HCD
	&isp1362_hcd_device,
#endif
#ifdef CONFIG_SMC91X
	&smc91x_device,
#endif
};

static int __init cm_bf533_init(void)
{
	printk("%s(): registering device resources\n", __FUNCTION__);
	return platform_add_devices(cm_bf533_devices,
				    ARRAY_SIZE(cm_bf533_devices));
}

arch_initcall(cm_bf533_init);
