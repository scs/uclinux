/*
 * include/asm-arm/arch-ixp425/serial.h
 *
 * Author: Deepak Saxena <dsaxena@mvista.com>
 * Modified for ixp425 offsets pbarry-intel
 *
 * Copyright (c) 2001 MontaVista Software, Inc.
 * 
 * 2002: Modified for IXP425 by Intel Corporation.
 *
 */

#ifndef _ARCH_SERIAL_H_
#define _ARCH_SERIAL_H_

#define	STD_SERIAL_PORT_DEFNS
#define	EXTRA_SERIAL_PORT_DEFNS

/*
 * IXP425 uses 15.6MHz clock for uart
 */
#define BASE_BAUD ( IXP425_UART_XTAL / 16 )

#endif // _ARCH_SERIAL_H_
