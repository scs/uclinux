// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
  Func name   : copysignf
  
  Purpose     : This function copies the sign of the second argument to the
                first.

  Domain      : ~ x = [-3.4e38 ... 3.4e38]
                ~ y = [-3.4e38 ... 3.4e38]

*****************************************************************************/

#include <math.h>

float                      /*{ ret - signof(y) * |x| }*/
_copysignf(
    float x,               /*{ (i) - input parameter 1 }*/
    float y                /*{ (i) - input parameter 2 }*/
)
{
    long *yPtr = (long *)&y;
    long *xPtr = (long *)&x;
    long sign;

    /*{ copy sign of y }*/
    sign = *yPtr & 0x80000000;

    /*{ overwrite sign of x with sign of y }*/
    *xPtr = *xPtr & 0x7fffffff;
    *xPtr = *xPtr | sign;

    /*{ return x }*/
    return x;
}

/*end of file*/
