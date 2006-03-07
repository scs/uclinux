/*
 * File:        arch/blackfin/mach-bf537/stamp.c
 * Based on:    archi/blacfkin/mach-bf533/ezkit.c
 * Author:      Aidan Williams <aidan@nicta.com.au>
 *                Copyright 2005 National ICT Australia (NICTA)
 * Created:
 * Description:
 *
 * Rev:          $Id$
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
#include <linux/usb_isp1362.h>
#include <asm/irq.h>

/*
 *  Driver needs to know address, irq and flag pin.
 */
#ifdef CONFIG_SMC91X
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
#endif

#ifdef CONFIG_USB_SL811_HCD 
static struct resource sl811_hcd_resources[] = {
	[0] = {
	       .start = 0x20340000,
	       .end = 0x20340000,
	       .flags = IORESOURCE_MEM,
	       },
	[1] = {
	       .start = 0x20340004,
	       .end = 0x20340004,
	       .flags = IORESOURCE_MEM,
	       },
	[2] = {
	       .start = IRQ_PROG_INTA,
	       .end = IRQ_PROG_INTA,
	       .flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
	       },
	[3] = {
	       /*
	        *  denotes the flag pin and is used directly if
	        *  CONFIG_IRQCHIP_DEMUX_GPIO is defined.
	        */
	       .start = IRQ_PF5,
	       .end = IRQ_PF5,
	       .flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
	       },
};

static struct platform_device sl811_hcd_device = {
	.name = "sl811-hcd",
	.id = 0,
	.num_resources = ARRAY_SIZE(sl811_hcd_resources),
	.resource = sl811_hcd_resources,
};
#endif

#ifdef CONFIG_USB_ISP1362_HCD
static struct resource isp1362_hcd_resources[] = {
	[0] = {
	       .start = 0x20360000,
	       .end = 0x20360000,
	       .flags = IORESOURCE_MEM,
	       },
	[1] = {
	       .start = 0x20360004,
	       .end = 0x20360004,
	       .flags = IORESOURCE_MEM,
	       },
	[2] = {
	       .start = IRQ_PROG_INTA,
	       .end = IRQ_PROG_INTA,
	       .flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
	       },
	[4] = {
	       .start = IRQ_PF0 + CONFIG_USB_ISP1362_BFIN_GPIO,
	       .end = IRQ_PF0 + CONFIG_USB_ISP1362_BFIN_GPIO,
	       .flags = IORESOURCE_IRQ,
	       },
};

static struct isp1362_platform_data isp1362_priv = {
	.sel15Kres	= 0,
	.clknotstop	= 1,
	.oc_enable	= 0,
	.int_act_high	= 0,
	.int_edge_triggered	= 0,
	.remote_wakeup_connected	= 0,
	.no_power_switching	= 0,
	.power_switching_mode	= 1,
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

#ifdef CONFIG_USB_NET2272
static struct resource net2272_bfin_resources[] = {
	[0] = 	{
		.start = 0x20300000,
		.end = 0x20300000 + 0x100,
		.flags = IORESOURCE_MEM,
		},
	[1] =	{
		.start = IRQ_PF7,
		.end = IRQ_PF7,
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

static struct platform_device *stamp_devices[] __initdata = {
#ifdef CONFIG_USB_SL811_HCD
	&sl811_hcd_device,
#endif
#ifdef CONFIG_USB_ISP1362_HCD
	&isp1362_hcd_device,
#endif
#ifdef CONFIG_SMC91X
	&smc91x_device,
#endif
	&bfin_mac_device,
#ifdef CONFIG_USB_NET2272
	&net2272_bfin_device,
#endif
};

static int __init stamp_init(void)
{
	printk("%s(): registering device resources\n", __FUNCTION__);
	return platform_add_devices(stamp_devices, ARRAY_SIZE(stamp_devices));
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

arch_initcall(stamp_init);
