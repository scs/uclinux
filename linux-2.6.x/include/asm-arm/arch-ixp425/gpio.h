/*
 * arch/arm/mach-ixp425/gpio.h 
 *
 * Copyright (C) 2002 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _ASM_ARCH_GPIO_H_
#define _ASM_ARCH_GPIO_H_

#ifndef __ASSEMBLY__

#include <asm/types.h>

/* GPIO pin mappings */
#define IXP425_GPIO_PIN_15 		15
#define IXP425_GPIO_PIN_14 		14
#define IXP425_GPIO_PIN_13 		13
#define IXP425_GPIO_PIN_12 		12
#define IXP425_GPIO_PIN_11 		11
#define IXP425_GPIO_PIN_10 		10
#define IXP425_GPIO_PIN_9 		9
#define IXP425_GPIO_PIN_8  		8
#define IXP425_GPIO_PIN_7  		7
#define IXP425_GPIO_PIN_6  		6
#define IXP425_GPIO_PIN_5  		5
#define IXP425_GPIO_PIN_4  		4
#define IXP425_GPIO_PIN_3  		3
#define IXP425_GPIO_PIN_2  		2
#define IXP425_GPIO_PIN_1  		1
#define IXP425_GPIO_PIN_0  		0

#define IXP425_GPIO_PIN_MAX		IXP425_GPIO_PIN_15

/* GPIO pin types */
#define IXP425_GPIO_OUT 		1
#define IXP425_GPIO_IN  		2

/* GPIO interrupt types */
#define IXP425_GPIO_ACTIVE_HIGH		0x4 /* Default */
#define IXP425_GPIO_ACTIVE_LOW		0x8
#define IXP425_GPIO_RISING_EDGE		0x10
#define IXP425_GPIO_FALLING_EDGE 	0x20
#define IXP425_GPIO_TRANSITIONAL 	0x40

/* GPIO signal types */
#define IXP425_GPIO_LOW			0
#define IXP425_GPIO_HIGH		1

/* GPIO Clocks */
#define IXP425_GPIO_CLK_0		14
#define IXP425_GPIO_CLK_1		15

/*
 * GPIO clock frequencies. These correspond to fractions of the
 * 66 MHz APB clock.
 */
#define IXP425_GPIO_33_MHZ		0x1	/* Default */
#define IXP425_GPIO_22_MHZ		0x2
#define IXP425_GPIO_16_5_MHZ		0x3
#define IXP425_GPIO_13_2_MHZ		0x4
#define IXP425_GPIO_11_MHZ		0x5
#define IXP425_GPIO_9_4_MHZ		0x6
#define IXP425_GPIO_8_3_MHZ		0x7
#define IXP425_GPIO_7_3_MHZ		0x8
#define IXP425_GPIO_6_6_MHZ		0x9
#define IXP425_GPIO_6_MHZ		0xa
#define IXP425_GPIO_5_5_MHZ		0xb
#define IXP425_GPIO_5_1_MHZ		0xc
#define IXP425_GPIO_4_7_MHZ		0xd
#define IXP425_GPIO_4_4_MHZ		0xf
    
#define IXP425_GPIO_CLK0_ENABLE 	0x100
#define IXP425_GPIO_CLK1_ENABLE 	0x1000000

/* Left shift values to set clock terminal count (TC) and duty cycle (DC)*/
#define IXP425_GPIO_CLK0TC_LSH		4
#define IXP425_GPIO_CLK1TC_LSH		20
#define IXP425_GPIO_CLK0DC_LSH		0
#define IXP425_GPIO_CLK1DC_LSH		16

struct ixp425_gpio {
	unsigned long   gpoutr;
	unsigned long   gpoer;
	unsigned long   gpinr;
	unsigned long   gpisr;
	unsigned long   gpit1r;
	unsigned long   gpit2r;
	unsigned long   gpclkr;
	unsigned long   gpreserved;
};

extern void gpio_line_get(u8 line, int *value);
extern void gpio_line_set(u8 line, int value);
extern void gpio_line_config(u8 line, u32 style);
extern void gpio_line_isr_clear(u8 line);

#endif // __ASSEMBLY__

#endif
