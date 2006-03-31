/************************************************************************
 *
 * util.h 
 *
 * (c) Copyright 2002-2004 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 * $Revision$
 ************************************************************************/

/* This file contains function declarations and  macros used in the 
** standard C and DSP libraries.
*/

#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* util.h */
#endif

#ifndef _UTIL_H
#define _UTIL_H

#ifdef __ADSPTS__
#include "_divide.h"
#endif

#define DOUBLE  long double
#define FLOAT   float
#define INT     int
#define LONG    long int

#define MPY(x, y)   ((float)x * (float)y)
#define MPYD(x, y)  ((long double)x * (long double)y)

#ifdef  __ADSPTS__
#define DIV(x, y)   (_divide40((float)x,(float)y))
#else
#define DIV(x, y)   ((float)x / (float)y)
#endif
#define DIVD(x, y)  ((long double)x / (long double)y)

#define ADD(x, y)   ((float)x + (float)y)
#define ADDD(x, y)  ((long double)x + (long double)y)

#define SUB(x, y)   ((float)x - (float)y)
#define SUBD(x, y)  ((long double)x - (long double)y)

#define TO_FLOAT(x)    ((float)x)
#define TO_DOUBLE(x)   ((long double)x)
#define TO_LONG(x)     ((long)x)

typedef union 
{
   FLOAT f;
   LONG i;
} FLOAT_BIT_MANIPULATOR;


typedef union 
{
   DOUBLE f;
   LONG i[2];
} DOUBLE_BIT_MANIPULATOR;

#endif /* _UTIL_H */
