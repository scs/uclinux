/*
 * arch/arm/mach-ixp425/se4000.c
 *
 * SE4000 board-setup 
 *
 * Copyright (C) 2003-2004 MontaVista Software, Inc.
 * Copyright (C) 2004      Greg Ungerer <gerg@snapgear.com>
 *
 * Author: Deepak Saxena <dsaxena@mvista.com>
 */

#include <linux/init.h>
#include <linux/device.h>
#include <asm/types.h>
#include <asm/setup.h>
#include <asm/memory.h>
#include <asm/hardware.h>
#include <asm/mach-types.h>
#include <asm/mach/arch.h>
#include <asm/mach/flash.h>

extern void ixp425_map_io(void);
extern void ixp425_init_irq(void);

static struct flash_platform_data se4000_flash_data = {
	.map_name	= "cfi_probe",
	.width		= 2,
};

static struct resource se4000_flash_resource = {
	.start		= IXP425_EXP_BUS_CS0_BASE_PHYS,
	.end		= IXP425_EXP_BUS_CS0_BASE_PHYS + 
				IXP425_EXP_BUS_CSX_REGION_SIZE,
	.flags		= IORESOURCE_MEM,
};

static struct platform_device se4000_flash_device = {
	.name		= "IXP425Flash",
	.id		= 0,
	.dev		= {
		.platform_data = &se4000_flash_data,
	},
	.num_resources	= 1,
	.resource	= &se4000_flash_resource,
};

static int __init se4000_init(void)
{
	if (!machine_is_se4000())
		return -ENODEV;

	platform_add_device(&se4000_flash_device);
	return 0;
}

arch_initcall(se4000_init);

MACHINE_START(SE4000, "SnapGear SE4000")
	MAINTAINER("SnapGear Inc.")
	BOOT_MEM(PHYS_OFFSET, IXP425_PERIPHERAL_BASE_PHYS,
		IXP425_PERIPHERAL_BASE_VIRT)
	MAPIO(ixp425_map_io)
	INITIRQ(ixp425_init_irq)
	BOOT_PARAMS(0x100)
MACHINE_END

