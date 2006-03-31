/************************************************************************
 *
 * float.h
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
 * Copyright (c) 1992-2001 by P.J. Plauger.  ALL RIGHTS RESERVED.

 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * Consult your license regarding permissions and restrictions.
 *
 ************************************************************************/

#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* float.h */
#endif

/* float.h standard header -- IEEE 754 version */
#ifndef _FLOAT
#define _FLOAT
#ifndef _YVALS
 #include <yvals.h>
#endif
_C_STD_BEGIN

                /* COMMON PROPERTIES */
#define FLT_RADIX            2
 #ifdef _FRND
  #define FLT_ROUNDS         _FRND
 #else
  #define FLT_ROUNDS         (-1)   /* indeterminable */
 #endif

                /* float properties */
#define FLT_EPSILON          1.1920928955078125E-07F 
#define FLT_MAX              3.40282346638528860e+38
#define FLT_MIN              1.1754943508222875E-38F

#define FLT_DIG              6
#define FLT_MANT_DIG         24
#define FLT_MAX_10_EXP       38
#define FLT_MAX_EXP          128
#define FLT_MIN_10_EXP       (-37)
#define FLT_MIN_EXP          (-125)

                /* long double properties */
#define LDBL_EPSILON         2.2204460492503131e-16L
#define LDBL_MAX             1.797693134862315708e+308L
#define LDBL_MIN             2.2250738585072014E-308L
#define LDBL_DIG             15
#define LDBL_MANT_DIG        53
#define LDBL_MAX_10_EXP      308
#define LDBL_MAX_EXP         1024
#define LDBL_MIN_10_EXP      (-307)
#define LDBL_MIN_EXP         (-1021)

                /* double properties */
#if defined(__DOUBLES_ARE_FLOATS__)
#define DBL_EPSILON          FLT_EPSILON
#define DBL_MAX              FLT_MAX
#define DBL_MIN              FLT_MIN
#define DBL_DIG              FLT_DIG
#define DBL_MANT_DIG         FLT_MANT_DIG
#define DBL_MAX_10_EXP       FLT_MAX_10_EXP
#define DBL_MAX_EXP          FLT_MAX_EXP
#define DBL_MIN_10_EXP       FLT_MIN_10_EXP
#define DBL_MIN_EXP          FLT_MIN_EXP
#else
#define DBL_EPSILON          LDBL_EPSILON
#define DBL_MAX              LDBL_MAX
#define DBL_MIN              LDBL_MIN
#define DBL_DIG              LDBL_DIG
#define DBL_MANT_DIG         LDBL_MANT_DIG
#define DBL_MAX_10_EXP       LDBL_MAX_10_EXP
#define DBL_MAX_EXP          LDBL_MAX_EXP
#define DBL_MIN_10_EXP       LDBL_MIN_10_EXP
#define DBL_MIN_EXP          LDBL_MIN_EXP
#endif

_C_STD_END
#endif /* _FLOAT */

/*
 * Copyright (c) 1992-2001 by P.J. Plauger.  ALL RIGHTS RESERVED.

 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * Consult your license regarding permissions and restrictions.
 * V3.10:1134 
 * $Revision$
 */
