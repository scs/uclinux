/*
 * include/asm-arm/arch-ixp425/uncompress.h 
 *
 * Copyright (C) 2002 Intel Corporation.
 * Copyricht (C) 2003 MontaVista Software, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#ifndef _ARCH_UNCOMPRESS_H_
#define _ARCH_UNCOMPRESS_H_

#include <asm/hardware.h>
#include <asm/mach-types.h>
#include <linux/serial_reg.h>

#define TX_DONE (UART_LSR_TEMT|UART_LSR_THRE)

static volatile u32* uart_base;

static __inline__ void putc(char c)
{
	/* Check THRE and TEMT bits before we transmit the character.
	 */
	while ((uart_base[UART_LSR] & TX_DONE) != TX_DONE); 
	*uart_base = c;
}

/*
 * This does not append a newline
 */
static void puts(const char *s)
{
	while (*s)
	{
		putc(*s);
		if (*s == '\n')
			putc('\r');
		s++;
	}
}

static __inline__ void arch_decomp_setup(void)
{
	unsigned int mach_type;
	
	asm("mov %0, r7" :"=r"(mach_type):);

	if(mach_type == MACH_TYPE_ADI_COYOTE)
		uart_base = (volatile u32*) IXP425_UART2_BASE_PHYS;
	else
		uart_base = (volatile u32*) IXP425_UART1_BASE_PHYS;
}

#define arch_decomp_wdog()

#endif
