/*
 * arch/arm/mach-ixdp425/ixdp425-pci.c 
 *
 * IXDP425 PCI initialization
 *
 * Copyright (C) 2002 Intel Corporation.
 *
 * Maintainer: Deepak Saxena <dsaxena@mvista.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/config.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/delay.h>

#include <asm/mach/pci.h>
#include <asm/irq.h>
#include <asm/hardware.h>
#include <asm/mach-types.h>


extern void ixp425_pci_preinit(void);
extern int ixp425_setup(int nr, struct pci_sys_data *sys);
extern struct pci_bus *ixp425_scan_bus(int nr, struct pci_sys_data *sys);


/* PCI controller pin mappings */
#define INTA_PIN	IXP425_GPIO_PIN_11
#define INTB_PIN	IXP425_GPIO_PIN_10
#define	INTC_PIN	IXP425_GPIO_PIN_9
#define	INTD_PIN	IXP425_GPIO_PIN_8

void __init ixdp425_pci_preinit(void)
{
	gpio_line_config(INTA_PIN, IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);
	gpio_line_config(INTB_PIN, IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);
	gpio_line_config(INTC_PIN, IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);
	gpio_line_config(INTD_PIN, IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);

	gpio_line_isr_clear(INTA_PIN);
	gpio_line_isr_clear(INTB_PIN);
	gpio_line_isr_clear(INTC_PIN);
	gpio_line_isr_clear(INTD_PIN);

	ixp425_pci_preinit();
}

/*
 * Interrupt mapping
 */
#define INTA			IRQ_IXDP425_PCI_INTA
#define INTB			IRQ_IXDP425_PCI_INTB
#define INTC			IRQ_IXDP425_PCI_INTC
#define INTD			IRQ_IXDP425_PCI_INTD

#define IXDP425_PCI_MAX_DEV      4
#define IXDP425_PCI_IRQ_LINES    4

static int __init ixdp425_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	static int pci_irq_table[IXDP425_PCI_IRQ_LINES] = {
		IRQ_IXDP425_PCI_INTA,
		IRQ_IXDP425_PCI_INTB,
		IRQ_IXDP425_PCI_INTC,
		IRQ_IXDP425_PCI_INTD
	};

	int irq = -1;

	if (slot >= 1 && slot <= IXDP425_PCI_MAX_DEV && 
		pin >= 1 && pin <= IXDP425_PCI_IRQ_LINES) {
		irq = pci_irq_table[(slot + pin - 2) % 4];
	}

	return irq;
}

struct hw_pci ixdp425_pci __initdata = {
	.nr_controllers = 1,
	.preinit	= ixdp425_pci_preinit,
	.swizzle	= pci_std_swizzle,
	.setup		= ixp425_setup,
	.scan		= ixp425_scan_bus,
	.map_irq	= ixdp425_map_irq,
};

int __init ixdp425_pci_init(void)
{
	if (machine_is_ixdp425())
		pci_common_init(&ixdp425_pci);
	return 0;
}

subsys_initcall(ixdp425_pci_init);

