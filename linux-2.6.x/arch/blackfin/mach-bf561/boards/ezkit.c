/*
 * File:         arch/blackfin/mach-bf561/ezkit.c
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 *
 * Rev:          $Id$
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
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
#include <linux/platform_device.h>
#include <asm/irq.h>

/*
 * Name the Board for the /proc/cpuinfo
 */
char *bfin_board_name = "ADDS-BF561-EZKIT";

/*
 *  USB-LAN EzExtender board
 *  Driver needs to know address, irq and flag pin.
 */
#if defined(CONFIG_SMC91X) || defined(CONFIG_SMC91X_MODULE)
static struct resource smc91x_resources[] = {
	{
		.name = "smc91x-regs",
		.start = 0x2C010300,
		.end = 0x2C010300 + 16,
		.flags = IORESOURCE_MEM,
	},{
		.start = IRQ_PROG0_INTB,
		.end = IRQ_PROG0_INTB,
		.flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
	},{
		/*
		 *  denotes the flag pin and is used directly if
		 *  CONFIG_IRQCHIP_DEMUX_GPIO is defined.
		 */
		.start = IRQ_PF9,
		.end = IRQ_PF9,
		.flags = IORESOURCE_IRQ | IORESOURCE_IRQ_HIGHLEVEL,
	},
};

#if defined(CONFIG_SERIAL_BFIN) || defined(CONFIG_SERIAL_BFIN_MODULE)
static struct resource bfin_uart_resources[] = {
        {
                .start = 0xFFC00400,
                .end = 0xFFC004FF,
                .flags = IORESOURCE_MEM,
        },
};

static struct platform_device bfin_uart_device = {
        .name = "bfin-uart",
        .id = 1,
        .num_resources = ARRAY_SIZE(bfin_uart_resources),
        .resource = bfin_uart_resources,
};
#endif


static struct platform_device smc91x_device = {
	.name = "smc91x",
	.id = 0,
	.num_resources = ARRAY_SIZE(smc91x_resources),
	.resource = smc91x_resources,
};
#endif

static struct platform_device *ezkit_devices[] __initdata = {
#if defined(CONFIG_SMC91X) || defined(CONFIG_SMC91X_MODULE)
	&smc91x_device,
#endif

#if defined(CONFIG_SERIAL_BFIN) || defined(CONFIG_SERIAL_BFIN_MODULE)
        &bfin_uart_device,
#endif
};

static int __init ezkit_init(void)
{
	printk(KERN_INFO "%s(): registering device resources\n", __FUNCTION__);
	return platform_add_devices(ezkit_devices,
		 ARRAY_SIZE(ezkit_devices));
}

arch_initcall(ezkit_init);
