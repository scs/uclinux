/*
 *  linux/arch/bfinnommu/mach-bf533/stamp.c
 *
 *  Copyright 2004 Analog Devices Inc.
 *  Only SMSC91C1111 was registered, may do more later.
 *
 *  Copyright 2005 National ICT Australia (NICTA), Aidan Williams <aidan@nicta.com.au>
 *  Thanks to Jamey Hicks.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/device.h>
#include <asm/irq.h>

/* 
 * Name the Board for the /proc/cpuinfo
 */
char * bfin_board_name = "ADDS-BF533-STAMP";

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

static struct platform_device *stamp_devices[] __initdata = {
        &smc91x_device,
};

static int __init stamp_init(void)
{
	printk("%s(): registering device resources\n", __FUNCTION__);
        return platform_add_devices(stamp_devices, ARRAY_SIZE(stamp_devices));
}
arch_initcall(stamp_init);
