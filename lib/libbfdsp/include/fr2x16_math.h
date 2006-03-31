#pragma once
#ifndef __NO_BUILTIN
#pragma system_header /* fr2x16_math.h */
#endif
/************************************************************************
 *
 * fr2x16_math.h
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

/* Standard library functions for two packed fractional values. */

#ifndef _FR2x16_MATH_H
#define _FR2x16_MATH_H

#include <fract_typedef.h>  /* get definitions for fract16 and fract32 */
#include <fr2x16_base.h>
#include <fr2x16_typedef.h>

/*
 * Standard functions:
 * abs({a,b})		=> {abs(a), abs(b)}
 * min({a,b},{c,d})	=> {min(a,c),min(b,d)}
 * max({a,b},{c,d})	=> {max(a,c),max(b,d)}
 */

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __NO_BUILTIN
static __inline fract2x16 abs_fr2x16(fract2x16 _x) {
	return __builtin_bfin_abs_fr2x16(_x);
}
static __inline fract2x16 min_fr2x16(fract2x16 _x, fract2x16 _y) {
	return __builtin_bfin_min_fr2x16(_x, _y);
}
static __inline fract2x16 max_fr2x16(fract2x16 _x, fract2x16 _y) {
	return __builtin_bfin_max_fr2x16(_x, _y);
}

/*
 * Cross-over multiplication:
 * ll({a,b}, {c,d})	=> a*c
 * lh({a,b}, {c,d})	=> a*d
 * hl({a,b}, {c,d})	=> b*c
 * hh({a,b}, {c,d})	=> b*d
 */

/*
extern fract2x16 __builtin_bfin_dspaddsubsat(fract2x16, fract2x16);
extern fract2x16 __builtin_bfin_dspsubaddsat(fract2x16, fract2x16);
extern fract16 __builtin_bfin_diff_hl_fr2x16(fr2x16);
extern fract16 __builtin_bfin_diff_lh_fr2x16(fr2x16); */

static __inline fract2x16 add_as_fr2x16(fract2x16 x,fract2x16 y) {
        return __builtin_bfin_dspaddsubsat(x,y);
        }

static __inline fract2x16 add_sa_fr2x16(fract2x16 x,fract2x16 y) {
        return __builtin_bfin_dspsubaddsat(x,y);
        }

static __inline fract16 diff_hl_fr2x16(fr2x16 x) {
        return __builtin_bfin_diff_hl_fr2x16(x);
        }

static __inline fract16 diff_lh_fr2x16(fr2x16 x) {
        return __builtin_bfin_diff_lh_fr2x16(x);
        }

#endif /* __NO_BUILTIN */

static __inline fract32 mult_ll_fr2x16(fract2x16 _x, fract2x16 _y) {
	return low_of_fr2x16(_x)*low_of_fr2x16(_y);
}
static __inline fract32 mult_hl_fr2x16(fract2x16 _x, fract2x16 _y) {
	return high_of_fr2x16(_x)*low_of_fr2x16(_y);
}
static __inline fract32 mult_lh_fr2x16(fract2x16 _x, fract2x16 _y) {
	return low_of_fr2x16(_x)*high_of_fr2x16(_y);
}
static __inline fract32 mult_hh_fr2x16(fract2x16 _x, fract2x16 _y) {
	return high_of_fr2x16(_x)*high_of_fr2x16(_y);
}

#ifdef __cplusplus
}
#endif

#endif /* _FR2x16_MATH_H */
