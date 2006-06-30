// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/*______________________________________________________________________

  Func name   : tanhf

  ----------------------------------------------------------------------

  Purpose     : This function computes tanh(x) using 32-bit float precision.
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : x = [-88.7 ... 88.7]

  Accuracy    : ~ Relative error:
                ~ * 1 bits of error or less
                ~ Assumption: there is no error in the input value

  Data Memory : ~   0
  Prog Memory : ~  82
  Cycles      : ~ 173 - max
                ~  24 - min

  Notes       : For x outside the domain, this function returns +-1.0.
  _____________________________________________________________________
*/
#include <float.h>
#include "math.h"
#include "util.h"
#include <math_const.h>

FLOAT                                /*{ ret - tanh(x) }*/
_tanhf(
    FLOAT x                          /*{ (i) - value to do tanhf on }*/
)
{
    FLOAT f, g, xnum, xden;
    FLOAT result;
    FLOAT sign = 1.0;

    /*{ f = |x| }*/
    f = x;
    /*{ sign = 1 }*/
    /*{ if x < 0, sign = -sign }*/
    if (x < (FLOAT)0.0)
    {
        f = -f;
        sign = -sign;
    }

    /*{ if f > TANH_BIGNUM, return sign }*/
    if (f > (FLOAT)TANH_BIGNUM)
    {
        return sign;
    }

    /*{ if f > ln(3)/2 }*/
    if (f > (FLOAT)LN3_2)
    {
        /*{ result = 1 - 2/(exp(2f) + 1) }*/
        result = ADD(f, f);
        result = expf(result);
        result = ADD(1.0, result);
        result = DIV(2.0, result);
        result = SUB(1.0, result);
    }
    /*{ else f <= ln(3)/2 }*/
    else
    {
        /*{ if f < EPS, return x }*/
        if (f < (FLOAT)FLT_EPSILON)
        {
            result = x;
            return result;
        }

        /*{ g = f * f }*/
        g = MPY(f, f);

        /*{ R(g) = g * P(g)/Q(g) }*/
        /*{!INDENT}*/
        /*{ P(g) = p1 * g + p0 }*/
        xnum = MPY(TANHP_COEF1, g);
        xnum = ADD(xnum, TANHP_COEF0);

        /*{ Q(g) = (g + q1) * g + q0 }*/
        xden = ADD(TANHQ_COEF1, g);
        xden = MPY(xden, g);
        xden = ADD(xden, TANHQ_COEF0);
        /*{!OUTDENT}*/

        /*{ result = f + f * R(g) }*/
        result = DIV(xnum, xden);
        result = MPY(result, g);
        result = MPY(result, f);
        result = ADD(result, f);

    }

    /*{ if sign < 0, result = -result }*/
    if (sign < (FLOAT)0.0)
    {
        result = -result;
    }

    /*{ return result }*/
    return result;
}

