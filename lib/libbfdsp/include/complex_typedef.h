/************************************************************************
 *
 * complex_typedef.h
 *
 * (c) Copyright 2001-2004 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* complex_typedef.h */
#endif

/* Define complex data types (fractional and float) */

#ifndef _COMPLEX_TYPEDEF_H
#define _COMPLEX_TYPEDEF_H

#include <fract_typedef.h>

typedef struct complex_fract16 {
	fract16 re, im;
} __attribute__((aligned(4))) complex_fract16;

/* Composite type used by builtin_bfins */
typedef union composite_complex_fract16 {
  struct complex_fract16 x;
  long raw;
} composite_complex_fract16;

#define CFR16_RE(X) X.x.re
#define CFR16_IM(X) X.x.im
#define CFR16_RAW(X) X.raw


typedef struct complex_fract32 {
	fract32 re, im;
} complex_fract32;

/* Composite type used by builtin_bfins */
typedef union composite_complex_fract32 {
 struct complex_fract32  x;
 long long raw;
} composite_complex_fract32;

#define CFR32_RE(X) X.x.re
#define CFR32_IM(X) X.x.im
#define CFR32_RAW(X) X.raw

/* C++ Template class variant declared in complex */
typedef struct complex_float {
 float  re;  
 float  im;
} complex_float;

typedef struct complex_long_double {
 long double  re; 
 long double  im;
} complex_long_double;

#ifdef __DOUBLES_ARE_FLOATS__          /* 32-bit doubles */
  typedef complex_float          complex_double;
#else                                  /* 64-bit doubles */
  typedef complex_long_double    complex_double;
#endif

#endif /* _COMPLEX_TYPEDEF_H */
