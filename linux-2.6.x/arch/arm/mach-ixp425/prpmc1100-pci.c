/*
 * arch/arm/mach-ixp425/prpmc1100-pci.c 
 *
 * PrPMC1100 PCI initialization
 *
 * Copyright (C) 2003 MontaVista Sofwtare, Inc. 
 * Based on IXDP425 code originally (C) Intel Corporation
 *
 * Author: Deepak Saxena <dsaxena@mvista.com>
 *
 * PrPMC1100 PCI init code.  GPIO usage is similar to that on 
 * IXDP425, but the IRQ routing is completely different and
 * depends on what carrier you are using. This code is written
 * to work on the Motorola PrPMC800 ATX carrier board.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/config.h>
#include <linux/pci.h>
#include <linux/init.h>

#include <asm/mach-types.h>
#include <asm/irq.h>
#include <asm/hardware.h>

#include <asm/mach/pci.h>

extern void ixp425_pci_preinit(void);
extern int ixp425_setup(int nr, struct pci_sys_data *sys);
extern struct pci_bus *ixp425_scan_bus(int nr, struct pci_sys_data *sys);


/* PCI controller pin mappings */
#define INTA_PIN	IXP425_GPIO_PIN_11
#define INTB_PIN	IXP425_GPIO_PIN_10
#define	INTC_PIN	IXP425_GPIO_PIN_9
#define	INTD_PIN	IXP425_GPIO_PIN_8

#define IXP425_PCI_RESET_GPIO   IXP425_GPIO_PIN_13
#define IXP425_PCI_CLK_PIN      IXP425_GPIO_CLK_0
#define IXP425_PCI_CLK_ENABLE   IXP425_GPIO_CLK0_ENABLE
#define IXP425_PCI_CLK_TC_LSH   IXP425_GPIO_CLK0TC_LSH
#define IXP425_PCI_CLK_DC_LSH   IXP425_GPIO_CLK0DC_LSH

void __init prpmc1100_pci_preinit(void)
{
	gpio_line_config(INTA_PIN, IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);
	gpio_line_config(INTB_PIN, IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);
	gpio_line_config(INTC_PIN, IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);
	gpio_line_config(INTD_PIN, IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);

	gpio_line_isr_clear(INTA_PIN);
	gpio_line_isr_clear(INTB_PIN);
	gpio_line_isr_clear(INTC_PIN);
	gpio_line_isr_clear(INTD_PIN);

	ixp425_pci_init();
}


/*
 * Interrupt mapping
 */
#define INTA			IRQ_PRPMC1100_PCI_INTA
#define INTB			IRQ_PRPMC1100_PCI_INTB
#define INTC			IRQ_PRPMC1100_PCI_INTC
#define INTD			IRQ_PRPMC1100_PCI_INTD

#define	PRPMC1100_PCI_MIN_DEV	10
#define	PRPCM1100_PCI_MAX_DEV	16
#define	PRPMC1100_PCI_IRQ_LINES	4

static int __init prpmc1100_map_irq(struct pci_dev *dev, u8 idsel, u8 pin)
{
	const long min_idsel = 10, max_idsel = 16, irqs_per_slot = 4;

	static int pci_irq_table[][4] = 
	{
		{INTD, INTA, INTB, INTC},	/* IDSEL 16 - PMC A1 */
		{INTD, INTA, INTB, INTC},	/* IDSEL 17 - PRPMC-A-B */
		{INTA, INTB, INTC, INTD},	/* IDSEL 18 - PMC A1-B */
		{0, 0, 0, 0},			/* IDSEL 19 - Unused */
		{INTA, INTB, INTC, INTD},	/* IDSEL 20 - P2P Bridge */
		{INTC, INTD, INTA, INTB},	/* IDSEL 21 - PMC A2 */
		{INTD, INTA, INTB, INTC},	/* IDSEL 22 - PMC A2-B */
	};

	if (slot >= PRPCM1100_PCI_MIN_DEV && slot <= PRPMC1100_PCI_MAX_DEV && 
		pin >= 1 && pin <= PRPMC1100_PCI_IRQ_LINES) {
		irq = pci_irq_table[slot - PRPMC1100_PCI_MIN_DEV][pin - 1];
	}
}


struct hw_pci prpmc1100_pci __initdata = {
	.nr_controllers = 1,
	.preinit =	  prpmc1100_pci_preinit,
	.swizzle =	  pci_std_swizzle,
	.setup =	  ixp425_setup,
	.scan =		  ixp425_scan_bus,
	.map_irq =	  prpmc1100_map_irq,
};

int __init prpmc1100_pci_init(void)
{
	if (machine_is_prpmc1100())
		pci_common_init(&prpmc1100_pci);
	return 0;
}

subsys_initcall(prpmc1100_pci_init);

