#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* fr2x16_base.h */
#endif
/************************************************************************
 *
 * fr2x16_base.h
 *
 * (c) Copyright 2000-2004 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

/* Basic operations on packed fractional types, including composition and
 * extraction */

#ifndef _FR2x16_BASE_H
#define _FR2x16_BASE_H

#include <fr2x16_typedef.h>
#include <fract_typedef.h>
#include <r2x16_base.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ADSPTS__) 
#if !defined(__NO_BUILTIN)

/*
 * Arithmetic operations
 * add({a,b},{c,d})		=> {a+c},{b+d}
 * sub({a,b},{c,d})		=> {a-c},{b-d}
 * mult({a,b},{c,d})		=> {a*c},{b*d}
 */


static __inline fract2x16 add_fr2x16(fract2x16 _x, fract2x16 _y) {
	return __builtin_bfin_add_fr2x16(_x,_y);
}
static __inline fract2x16 sub_fr2x16(fract2x16 _x, fract2x16 _y) {
	return __builtin_bfin_sub_fr2x16(_x,_y);
}
static __inline fract2x16 mult_fr2x16(fract2x16 _x, fract2x16 _y) {
	return __builtin_bfin_mult_fr2x16(_x,_y);
}



#else

fract2x16 add_fr2x16(fract2x16, fract2x16);
fract2x16 sub_fr2x16(fract2x16, fract2x16);
fract2x16 mult_fr2x16(fract2x16, fract2x16);

#endif
#endif

#if !defined(__NO_BUILTIN)
static __inline fract16 sum_fr2x16(fract2x16 _x){
  return __builtin_bfin_sum_fr2x16(_x);
}
#else
  fract16 sum_fr2x16(fract2x16);
#endif
/*
 * Composition and extraction
 */

/* Takes two fract16 values, and returns a fract2x16 value.
 * Input: two fract16 values
 * Returns: {_x,_y} */
static __inline fract2x16 compose_fr2x16(fract16 _x, fract16 _y) {
	return compose_2x16(_x,_y);
}

/* Takes a fract2x16 and returns the 'high half' fract16. 
 * Input: _x{a,b}
 * Returns: a. */
static __inline fract16 high_of_fr2x16(fract2x16 _x) {
	return high_of_2x16(_x);
}

/* Takes a fract2x16 and returns the 'low half' fract16
 * Input: _x{a,b}
 * Returns: b */
static __inline fract16 low_of_fr2x16(fract2x16 _x) {
	return low_of_2x16(_x);
}

#ifdef __cplusplus
 }
#endif

#endif /* _FR2x16_BASE_H */
