#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* r2x16_base.h */
#endif
/************************************************************************
 *
 * r2x16.h
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

/* Basic operations on 2x16-base types. */

#ifndef _R2x16_BASE_H
#define _R2x16_BASE_H

#if defined(__ADSPBLACKFIN__) 

#include <r2x16_typedef.h>

#if defined(__cplusplus)
extern "C" {
#endif

#if !defined(__NO_BUILTIN)

static __inline raw2x16 compose_2x16(_raw16 _x, _raw16 _y) {
	return __builtin_bfin_compose_2x16(_x, _y);
}
static __inline _raw16 high_of_2x16(raw2x16 _x) {
	return __builtin_bfin_extract_hi(_x);
}
static __inline _raw16 low_of_2x16(raw2x16 _x) {
	return __builtin_bfin_extract_lo(_x);
}

#else

static __inline raw2x16 compose_2x16(_raw16 _x, _raw16 _y) {
	return (_x << 16) | (_y & 0xFFFF);
}
static __inline _raw16 high_of_2x16(raw2x16 _x) {
	return (_x >> 16);
}
static __inline _raw16 low_of_2x16(raw2x16 _x) {
	return (_x & 0xFFFF);
}
#endif /* __NO_BUILTIN */

#if defined(__cplusplus)
} /* extern "C" */
#endif

#endif /* __ADSPBLACKFIN__ */

#endif /* _R2x16_BASE_H */
