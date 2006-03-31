#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* int_math.h */
#endif
/************************************************************************
 *
 * int_math.h
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

/* Defines builtin functions for the int type.  */

#ifndef _INT_MATH_H
#define _INT_MATH_H

#ifdef __ADSPBLACKFIN__

#include <ccblkfn.h>

#ifdef __cplusplus
extern "C" {
#endif

/* 
 * Abs/Min/Max _short all use the same underlying ops as
 * the _fr1x16 intrinsics, but the builtin name comes from the
 * fract version
 */
static __inline short abs_short(short _x) {
	return __builtin_bfin_abs_fr2x16(_x);
}
static __inline short min_short(short _x, short _y) {
	return __builtin_bfin_min_fr2x16(_x, _y);
}
static __inline short max_short(short _x, short _y) {
	return __builtin_bfin_max_fr2x16(_x, _y);
}

#else

static __inline short abs_short(short _x) {
	return abs(_x);
}
static __inline short min_short(short _x, short _y) {
	return _x > _y ? _y : _x;
}
static __inline short max_short(short _x, short _y) {
	return _x > _y ? _x : _y;
}

#endif /* __ADSPBLACKFIN__ */

#ifdef __cplusplus
  }    /*   extern "C"     */
#endif

#endif /* __INT_MATH_H */
