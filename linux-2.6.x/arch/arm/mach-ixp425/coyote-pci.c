/*
 * arch/arch/mach-ixp425/coyote-pci.c
 *
 * PCI setup routines for ADI Engineering Coyote platform
 *
 * Copyright (C) 2002 Jungo Software Technologies.
 * Copyright (C) 2003 MontaVista Softwrae, Inc.
 *
 * Maintainer: Deepak Saxena <dsaxena@mvista.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#include <linux/pci.h>
#include <linux/init.h>

#include <asm/mach-types.h>
#include <asm/hardware.h>
#include <asm/irq.h>

#include <asm/mach/pci.h>

extern void ixp425_pci_preinit(void);
extern int ixp425_setup(int nr, struct pci_sys_data *sys);
extern struct pci_bus *ixp425_scan_bus(int nr, struct pci_sys_data *sys);

#define COYOTE_PCI_SLOT0	14
#define COYOTE_PCI_SLOT1	15

void __init coyote_pci_preinit(void)
{
	gpio_line_config(IXP425_GPIO_PIN_11, 
			IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);

	gpio_line_config(IXP425_GPIO_PIN_6, 
			IXP425_GPIO_IN | IXP425_GPIO_ACTIVE_LOW);

	gpio_line_isr_clear(IXP425_GPIO_PIN_11);
	gpio_line_isr_clear(IXP425_GPIO_PIN_6);

	ixp425_pci_preinit();
}

static int __init coyote_map_irq(struct pci_dev *dev, u8 slot, u8 pin)
{
	if (slot == COYOTE_PCI_SLOT0)
		return IRQ_COYOTE_PCI_SLOT0;
	else if (slot == COYOTE_PCI_SLOT1)
		return IRQ_COYOTE_PCI_SLOT1;
	else return -1;
}

struct hw_pci coyote_pci __initdata = {
	.nr_controllers = 1,
	.preinit =        coyote_pci_preinit,
	.swizzle =        pci_std_swizzle,
	.setup =          ixp425_setup,
	.scan =           ixp425_scan_bus,
	.map_irq =        coyote_map_irq,
};

int __init coyote_pci_init(void)
{
	if (machine_is_adi_coyote())
		pci_common_init(&coyote_pci);
	return 0;
}

subsys_initcall(coyote_pci_init);
