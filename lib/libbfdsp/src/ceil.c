// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


  /*-------------------------------------------------------------------------

  Purpose     : This function computes the ceiling of a 32-bit float input.
  Description : This function rounds up to the next highest whole number that
                is greater than or equal to x.

  Domain      : Full Range

  Accuracy    : ~ Relative error: 0 bits in error
                ~ Assumption: there is no error in the input value

  Data Memory : ~  0
  Prog Memory : ~ 21
  Cycles      : ~ 27 - max
                ~ 21 - min

  Notes       : N/A
  _____________________________________________________________________{!EHDR}
*/
#include <float.h>
#include "math.h"
#include "util.h"
#include <math_const.h>

FLOAT                               /*{ ret - ceil(x)}*/
_ceilf(
    FLOAT x                         /*{ (i) - value for which to compute ceilf }*/
)
{
    FLOAT y;

    /*{ y = |x| }*/
    y = x;
    if (x < (FLOAT)0.0)
    {
        y = -y;
    }

    /*{ if x > 2^24 (max 23-bit int), result = x }*/
    if (y >= (FLOAT)16777216.0)
    {
        return x;
    }

    /*{ y = truncate(x) }*/
    y = TO_FLOAT(TO_LONG(x));

    /*{ if y < x, result = result + 1.0 }*/
    if (y < x)
    {
        y = ADD(y, 1.0);
    }

    return y;
}

/* end of file */
