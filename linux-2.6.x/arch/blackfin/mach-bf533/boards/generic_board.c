/*
 * File:         arch/blackfin/mach-bf533/generic_board.c
 * Based on:     arch/blackfin/mach-bf533/ezkit.c
 * Author:       Aidan Williams <aidan@nicta.com.au>
 *                 Copyright 2005 National ICT Australia (NICTA)
 * Created:      2005
 *
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
#include <asm/irq.h>

/*
 *  Driver needs to know address, irq and flag pin.
 */
static struct resource smc91x_resources[] = {
	[0] = {
		.start	= 0x20300300,
		.end	= 0x20300300 + 16,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= IRQ_PROG_INTB,
		.end	= IRQ_PROG_INTB,
		.flags	= IORESOURCE_IRQ|IORESOURCE_IRQ_HIGHLEVEL,
	},
	[2] = {
		/*
		 *  denotes the flag pin and is used directly if
		 *  CONFIG_IRQCHIP_DEMUX_GPIO is defined.
		 */
		.start	= IRQ_PF7,
		.end	= IRQ_PF7,
		.flags	= IORESOURCE_IRQ|IORESOURCE_IRQ_HIGHLEVEL,
	},
};
static struct platform_device smc91x_device = {
	.name		= "smc91x",
	.id		= 0,
	.num_resources	= ARRAY_SIZE(smc91x_resources),
	.resource	= smc91x_resources,
};

static struct platform_device *generic_board_devices[] __initdata = {
        &smc91x_device,
};

static int __init generic_board_init(void)
{
	printk("%s(): registering device resources\n", __FUNCTION__);
        return platform_add_devices(generic_board_devices, ARRAY_SIZE(generic_board_devices));
}
arch_initcall(generic_board_init);
