/*
 * arch/arm/mach-ixp425/ixp425-irq.c 
 *
 * Generic IRQ routines for IXP425 based systems
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
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/bitops.h>
 
#include <asm/irq.h>
#include <asm/hardware.h>
#include <asm/mach-types.h>
#include <asm/bitops.h>
 
#include <asm/mach/irq.h>           

#include <asm/hardware.h>

static void ixp425_irq_mask(unsigned int irq)
{
	*IXP425_ICMR &= ~BIT(irq);
}

static void ixp425_irq_mask_ack(unsigned int irq)
{
	static int irq2gpio[NR_IRQS] = {
		-1, -1, -1, -1, -1, -1,  0,  1,
		-1, -1, -1, -1, -1, -1, -1, -1,
		-1, -1, -1,  2,  3,  4,  5,  6,
		 7,  8,  9, 10, 11, 12, -1, -1,
	};
	int line = irq2gpio[irq];

	if (line > 0)
		gpio_line_isr_clear(line);
	
	ixp425_irq_mask(irq);
}

static void ixp425_irq_unmask(unsigned int irq)
{
	*IXP425_ICMR |= BIT(irq);
}

static struct irqchip ixp425_irq_chip = {
	.ack	= ixp425_irq_mask_ack,
	.mask	= ixp425_irq_mask,
	.unmask	= ixp425_irq_unmask,
};

void __init ixp425_init_irq(void)
{
	int i = 0;

	/* Route all sources to IRQ instead of FIQ */
	*IXP425_ICLR = 0x0;
	/* Disable all interrupt */
	*IXP425_ICMR = 0x0; 

	for(i = 0; i < NR_IRQS; i++)
	{
		set_irq_chip(i, &ixp425_irq_chip);
		set_irq_handler(i, do_level_IRQ);
		set_irq_flags(i, IRQF_VALID);
	}
}
