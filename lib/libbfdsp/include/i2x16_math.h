#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* i2x16_math.h */
#endif
/************************************************************************
 *
 * i2x16_math.h 
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

/* Additional operations on packed 16-bit integers */

#ifndef _I2x16_MATH_H
#define _I2x16_MATH_H

#include <i2x16_typedef.h>
#include <i2x16_base.h>
#include <stdlib.h>
#include <math.h>
#ifdef __cplusplus
extern "C" {
#endif

/*
 * Standard functions
 * abs({a,b})		=> { abs(a), abs(b) }
 * min({a,b},{c,d})	=> { min(a,c), min(b,d) }
 * max({a,b},{c,d})	=> { max(a,c), max(b,d) }
 */

static __inline int2x16 abs_i2x16(int2x16 _x) {
	return compose_2x16(abs(high_of_i2x16(_x)), abs(low_of_i2x16(_x)));
}
static __inline int2x16 min_i2x16(int2x16 _x, int2x16 _y) {
	return compose_2x16(min(high_of_i2x16(_x), high_of_i2x16(_y)),
                       min(low_of_i2x16(_x), low_of_i2x16(_y)));
}
static __inline int2x16 max_i2x16(int2x16 _x, int2x16 _y) {
	return compose_2x16(max(high_of_i2x16(_x), high_of_i2x16(_y)),
                       max(low_of_i2x16(_x), low_of_i2x16(_y)));
}

/*
 * Cross-wise multiplication
 * ll({a,b},{c,d})	=> a*c
 * lh({a,b},{c,d})	=> a*d
 * hl({a,b},{c,d})	=> b*c
 * hh({a,b},{c,d})	=> b*d
 */

static __inline long int mult_ll_i2x16(int2x16 _x, int2x16 _y) {
	return low_of_i2x16(_x)*low_of_i2x16(_y);
}
static __inline long int mult_hl_i2x16(int2x16 _x, int2x16 _y) {
	return high_of_i2x16(_x)*low_of_i2x16(_y);
}
static __inline long int mult_lh_i2x16(int2x16 _x, int2x16 _y) {
	return low_of_i2x16(_x)*high_of_i2x16(_y);
}
static __inline long int mult_hh_i2x16(int2x16 _x, int2x16 _y) {
	return high_of_i2x16(_x)*high_of_i2x16(_y);
}

#ifdef __cplusplus
  } /* extern "C" */
#endif

#endif /* _I2x16_MATH_H */
