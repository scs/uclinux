/*
 * arch/arm/mach-ixp425/mm.c 
 *
 * Copyright (C) 2002 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/serial.h>
#include <linux/tty.h>
#include <linux/serial_core.h>

#include <asm/io.h>
#include <asm/mach-types.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/irq.h>

#include <asm/mach/map.h>
#include <asm/hardware.h>

/* See asm/arch/ixp425.h for a detailed memory map */

/* Common mappings */
static struct map_desc ixp425_io_desc[] __initdata = {
	/* Map QMgr */
	{
		.virtual	= IXP425_QMGR_BASE_VIRT,
		.physical	= IXP425_QMGR_BASE_PHYS,
		.length		= IXP425_QMGR_REGION_SIZE,
		.type		= MT_DEVICE
	},
	/* UART, Interrupt ctrl, GPIO, timers, NPEs, MACS, USB .... */
	{
		.virtual	= IXP425_PERIPHERAL_BASE_VIRT,
		.physical	= IXP425_PERIPHERAL_BASE_PHYS,
		.length		= IXP425_PERIPHERAL_REGION_SIZE,
		.type		= MT_DEVICE
	},
	/* Expansion Bus Config Registers */
	{
		.virtual	= IXP425_EXP_CFG_BASE_VIRT,
		.physical	= IXP425_EXP_CFG_BASE_PHYS,
		.length		= IXP425_EXP_CFG_REGION_SIZE,
		.type		= MT_DEVICE
	}
};

/*
 * Serial port information. Not sure if this is the best place
 * to put this, but it'll work for now. IXP425 has two-on chip
 * UARTs, but some boards use only one of them and don't have the
 * second one connected at all.
 */
static struct uart_port ixp425_serial_ports[] = {
	{
		.membase	= (char*)(IXP425_UART1_BASE_VIRT+3),
		.mapbase	= (IXP425_UART1_BASE_PHYS+3),
		.irq		= IRQ_IXP425_UART1,
		.flags		= UPF_SKIP_TEST,
		.iotype		= UPIO_MEM,	
		.regshift	= 2,
		.uartclk	= IXP425_UART_XTAL,
		.line		= 0,
		.type		= PORT_XSCALE,
		.fifosize	= 32
	} , {
		.membase	= (char*)(IXP425_UART2_BASE_VIRT+3),
		.mapbase	= (IXP425_UART2_BASE_PHYS+3),
		.irq		= IRQ_IXP425_UART2,
		.flags		= UPF_SKIP_TEST,
		.iotype		= UPIO_MEM,	
		.regshift	= 2,
		.uartclk	= IXP425_UART_XTAL,
		.line		= 1,
		.type		= PORT_XSCALE,
		.fifosize	= 32
	}
};

void __init ixp425_map_io(void)
{
	/* Common Mapping */
  	iotable_init(ixp425_io_desc, ARRAY_SIZE(ixp425_io_desc));

	/* 
	 * Platform specific mappings plus serial port configuration
	 */
	if (machine_is_adi_coyote()) {
		ixp425_serial_ports[1].line = 0;
		early_serial_setup(&ixp425_serial_ports[1]);
	} else  if(machine_is_se4000()) {
		early_serial_setup(&ixp425_serial_ports[0]);
	} else {
		early_serial_setup(&ixp425_serial_ports[0]);
		early_serial_setup(&ixp425_serial_ports[1]);
	}
}
  
