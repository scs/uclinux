#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* i2x16_base.h */
#endif
/************************************************************************
 *
 * i2x16_base.h
 *
 * (c) Copyright 2000-2003 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

/* Basic operations on packed 16-bit integers. */

#ifndef _I2x16_BASE_H
#define _I2x16_BASE_H

#include <i2x16_typedef.h>
#include <r2x16_base.h>

#ifdef __cplusplus
extern "C" {
#endif
/*
 * Composition and extraction
 */

static __inline int2x16 compose_i2x16(short _x, short _y) {
	return compose_2x16(_x, _y);
}
static __inline short high_of_i2x16(int2x16 _x) {
	return high_of_2x16(_x);
}
static __inline short low_of_i2x16(int2x16 _x) {
	return low_of_2x16(_x);
}

/*
 * Arithmetic operations
 * add({a,b},{c,d})	=> {a+c, b+d}
 * sub({a,b},{c,d})	=> {a-c, b-d}
 * mult({a,b},{c,d})	=> {a*c, b*d}
 */

#if (defined(__ADSPBLACKFIN__) || defined(__ADSPTS__)) && !defined(__NO_BUILTIN)

static __inline int2x16 add_i2x16(int2x16 _x, int2x16 _y) {
	return __builtin_bfin_add_i2x16(_x, _y);
}
static __inline int2x16 sub_i2x16(int2x16 _x, int2x16 _y) {
	return __builtin_bfin_sub_i2x16(_x, _y);
}
static __inline int2x16 mult_i2x16(int2x16 _x, int2x16 _y) {
	return __builtin_bfin_mult_i2x16(_x, _y);
}

#else
int2x16 add_i2x16(int2x16, int2x16);
int2x16 sub_i2x16(int2x16, int2x16);
int2x16 mult_i2x16(int2x16, int2x16);
#endif


/*
 * Sideways addition:
 * sum({a,b})	=> a+b
 */

#ifdef __ADSPTS__
static __inline int sum_i2x16(int2x16 _x) {
	return __builtin_bfin_sum_i2x16(_x);
}
#else

static __inline int sum_i2x16(int2x16 _x) {
	return high_of_i2x16(_x)+low_of_i2x16(_x);
}

#endif /* __ADSPTS_ */

#ifdef __cplusplus
 } /* extern "C" */
#endif

#endif /* _I2x16_BASE_H */
