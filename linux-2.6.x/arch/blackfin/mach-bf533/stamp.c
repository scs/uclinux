/*
 *  linux/arch/bfinnommu/mach-bf533/stamp.c
 *  Copyright 2004 Analog Devices Inc.
 *  Only SMSC91C1111 was registered, may do more later.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 */

#include <linux/device.h>

#define	STAMP_ETH_BASE	0x20300000
static struct resource smc91x_resources[] = {
	[0] = {
		.start	= (STAMP_ETH_BASE + 0x300),
		.end	= (STAMP_ETH_BASE + 0xfffff),
		.flags	= IORESOURCE_MEM,
	}
};

static struct platform_device smc91x_device = {
	.name			= "smc91x",
	.id				= 0,
	.num_resources	= ARRAY_SIZE(smc91x_resources),
	.resource		= smc91x_resources,
};

static int __init stamp_init(void)
{
	printk("%s registe the device resurce to system.\n", __FUNCTION__);
	platform_device_register(&smc91x_device);
	return 0;
}
arch_initcall(stamp_init);
