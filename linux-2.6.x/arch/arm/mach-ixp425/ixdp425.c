/*
 * arch/arm/mach-ixp425/ixdp425.c
 *
 * IXDP425/IXCDP1100 board-setup 
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
#include <asm/mach/i2c-gpio.h>

extern void ixp425_map_io(void);
extern void ixp425_init_irq(void);

static struct flash_platform_data ixdp425_flash_data = {
	.map_name	= "cfi_probe",
	.width		= 2,
};

static struct resource ixdp425_flash_resource = {
	.start		= IXP425_EXP_BUS_CS0_BASE_PHYS,
	.end		= IXP425_EXP_BUS_CS0_BASE_PHYS + 
				IXP425_EXP_BUS_CSX_REGION_SIZE,
	.flags		= IORESOURCE_MEM,
};

static struct platform_device ixdp425_flash_device = {
	.name		= "IXP425Flash",
	.id		= 0,
	.dev		= {
		.platform_data = &ixdp425_flash_data,
	},
	.num_resources	= 1,
	.resource	= &ixdp425_flash_resource,
};

static struct i2c_gpio_pins ixdp425_i2c_gpio_pins = {
	.sda_pin	= IXP425_GPIO_PIN_7,
	.scl_pin	= IXP425_GPIO_PIN_6
};

static struct platform_device ixdp425_i2c_controller = {
	.name		= "IXP425-I2C",
	.id		= 0,
	.dev		= {
		.platform_data = &ixdp425_i2c_gpio_pins,
	},
	.num_resources	= 0
};

static int __init ixdp425_init(void)
{
	if (!machine_is_ixdp425() && !machine_is_ixcdp1100())
		return -ENODEV;

	platform_add_device(&ixdp425_flash_device);
	platform_add_device(&ixdp425_i2c_controller);

	return 0;
}

arch_initcall(ixdp425_init);

MACHINE_START(IXDP425, "Intel IXDP425 Development Platform")
	MAINTAINER("MontaVista Software, Inc.")
	BOOT_MEM(PHYS_OFFSET, IXP425_PERIPHERAL_BASE_PHYS,
		IXP425_PERIPHERAL_BASE_VIRT)
	MAPIO(ixp425_map_io)
	INITIRQ(ixp425_init_irq)
	BOOT_PARAMS(0x0100)
MACHINE_END

MACHINE_START(IXCDP1100, "Intel IXCDP1100 Development Platform")
	MAINTAINER("MontaVista Software, Inc.")
	BOOT_MEM(PHYS_OFFSET, IXP425_PERIPHERAL_BASE_PHYS,
		IXP425_PERIPHERAL_BASE_VIRT)
	MAPIO(ixp425_map_io)
	INITIRQ(ixp425_init_irq)
	BOOT_PARAMS(0x0100)
MACHINE_END

