/*
 * arch/arm/mach-ixp425/coyote.c
 *
 * Coyote board-setup 
 *
 * Copyright (C) 2003-2004 MontaVista Software, Inc.
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

static struct flash_platform_data coyote_flash_data = {
	.map_name	= "cfi_probe",
	.width		= 2,
};

static struct resource coyote_flash_resource = {
	.start		= IXP425_EXP_BUS_CS0_BASE_PHYS,
	.end		= IXP425_EXP_BUS_CS0_BASE_PHYS + 
				IXP425_EXP_BUS_CSX_REGION_SIZE * 2,
	.flags		= IORESOURCE_MEM,
};

static struct platform_device coyote_flash_device = {
	.name		= "IXP425Flash",
	.id		= 0,
	.dev		= {
		.platform_data = &coyote_flash_data,
	},
	.num_resources	= 1,
	.resource	= &coyote_flash_resource,
};

static int __init coyote_init(void)
{
	if (!machine_is_adi_coyote())
		return -ENODEV;

	platform_add_device(&coyote_flash_device);

	return 0;
}

arch_initcall(coyote_init);

MACHINE_START(ADI_COYOTE, "ADI Engineering IXP425 Coyote Development Platform")
        MAINTAINER("MontaVista Software, Inc.")
        BOOT_MEM(PHYS_OFFSET, IXP425_PERIPHERAL_BASE_PHYS,
                IXP425_PERIPHERAL_BASE_VIRT)
        MAPIO(ixp425_map_io)
        INITIRQ(ixp425_init_irq)
        BOOT_PARAMS(0x0100)
MACHINE_END


