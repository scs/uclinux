// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
  Func name   : fclipf

  Purpose     : This function returns the clipped value of input parameter 1
                using input parameter 2 as the clipping limit.
  Description : This function returns param1 or (sign of(param1) * param2).

  Domain      :  x         = [-3.4e38 ... 3.4e38]
                 clipLimit = [-3.4e38 ... 3.4e38]

****************************************************************************/

#include <math.h>

float                       /*{ ret - clipped value }*/
_fclipf(
    float x,                /*{ (i) - value to clip }*/
    float clipLimit         /*{ (i) - cliping limit }*/
)

{
    float x_abs = x;
    float clipLimit_abs = clipLimit;
    int inputIsNegative = 0;

    /*{ result = input }*/
    float result = x;

    if (x < 0)
    {
        inputIsNegative = 1;
        x_abs = -x_abs;
    }

    if (clipLimit < 0)
    {
        clipLimit_abs = -clipLimit_abs;
    }

    /*{ if |x| >= |clipLimit|, result = signof(x) * |clipLimit|}*/
    if (x_abs >= clipLimit_abs)
    {
        result = clipLimit_abs;
        if (inputIsNegative)
        {
            result = -result;
        }
    }

    /*{ return result }*/
    return result;
}

/*end of file*/
