// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/***************************************************************************
   File: cexp.c
  
   complex exponential for floating point input

****************************************************************************/

#include <math.h>
#include <complex.h>

complex_float _cexpf(float a )
{
    complex_float c;

    c.re = cosf(a);
    c.im = sinf(a);
    return (c);
}

/*end of file*/
