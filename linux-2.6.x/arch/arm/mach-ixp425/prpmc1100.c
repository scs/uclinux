/*
 * arch/arm/mach-ixp425/prpmc1000.c
 *
 * SE4000 board-setup 
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

extern void ixp425_map_io(void);
extern void ixp425_init_irq(void);

MACHINE_START(PRPMC1100, "Motorolla PrPMC 1100")
	MAINTAINER("MontaVista Software, Inc.")
	BOOT_MEM(PHYS_OFFSET, IXP425_PERIPHERAL_BASE_PHYS,
		IXP425_PERIPHERAL_BASE_VIRT)
	MAPIO(ixp425_map_io)
	INITIRQ(ixp425_init_irq)
	BOOT_PARAMS(0x100)
MACHINE_END

