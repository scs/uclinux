// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/*______________________________________________________________________

  Func name   : sinf

  ----------------------------------------------------------------------

  Purpose     : This function computes sin(x) using 32-bit float precision.
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : x = [-9099 ... 9099]

  Accuracy    : ~ Relative error:
                ~ * Primary range (-PI/2 to PI/2) - 2 bits of error or less
                ~ * Outside primary range         - 3 bits of error or less
                ~ Assumption: There is no error in the input value

  Data Memory : ~  0
  Prog Memory : ~ 91
  Cycles      : ~ 78 - max
                ~ 23 - min

  Notes       : For x outside the domain, this function returns 0.0.
  _____________________________________________________________________
*/
#include <float.h>
#include "math.h"
#include "util.h"
#include <math_const.h>


FLOAT                               /*{ ret - sin(x)}*/
_sinf(
    FLOAT x                         /*{ (i) - value for which to compute sinf }*/
)
{
    LONG n;
    FLOAT xn;
    FLOAT f, g;
    FLOAT x_int, x_fract;
    FLOAT result;
    FLOAT sign = (FLOAT)1.0;

    /*{ sign = 1 }*/

    /*{ if x < 0 }*/

    if (x < (FLOAT)0.0)
    {
        /*{ sign = -sign }*/
        sign = -sign;
        /*{ x = -x }*/
        x = -x;
    }

    /*{ If x is outside the domain, return 0.0 }*/

    if (x > (FLOAT)X_MAX)
    {
        return (FLOAT)0.0;
    }

    /*{ split x into x_int and x_fract for better argument reduction }*/
    x_int = TO_FLOAT(TO_LONG(x));
    x_fract = SUB(x, x_int);

    /*{ Reduce the input to range between -PI/2, PI/2 }*/
    /*{!INDENT}*/
    /*{ n = Rounded long x/PI }*/
    n = TO_LONG(ADD(MPY(x, (float) INV_PI), 0.5));

    /*{ xn = (double)n }*/
    xn = TO_FLOAT(n);

    /*{ f = x - xn*PI }*/
    /* (using higher precision computation) */
    f = SUB(x_int, MPY(xn, PI_C1));
    f = ADD(f, x_fract);
    f = SUB(f, MPY(xn, PI_C2));
    f = SUB(f, MPY(xn, PI_C3));

    /*{ If n is odd, sign = -sign }*/
    if (n & 0x0001)
    {
        sign = -sign;
    }
    /*{!OUTDENT}*/

    if (f < (FLOAT)0.0)
    {
        g = -f;
    }
    else
    {
        g = f;
    }
    /*{ If |f| < eps }*/
    if (g < (FLOAT)EPS_FLOAT)
    {
        /*{ result = f }*/
        result = f;
        /*{ if sign < 0, result = -result }*/
        if (sign < (FLOAT)0.0)
        {
            result = -result;
        }
        /*{return result }*/
        return result;
    }

    /*{ g = f * f }*/
    g = MPY(f, f);

    /*{ Compute sin approximation on reduced argument }*/
    /*{!INDENT}*/
    /*{ result = ((((g * C5 + C4) * g + C3) * g + C2) * g + C1) * g * f + f }*/
    result = MPY(g, SIN_COEF5);
    result = ADD(result, SIN_COEF4);
    result = MPY(result, g);
    result = ADD(result, SIN_COEF3);
    result = MPY(result, g);
    result = ADD(result, SIN_COEF2);
    result = MPY(result, g);
    result = ADD(result, SIN_COEF1);
    result = MPY(result, g);

    result = MPY(result, f);
    result = ADD(result, f);
    /*{!OUTDENT}*/

    /*{ if sign < 0, result = -result }*/
    if (sign < (FLOAT)0.0)
    {
        result = -result;
    }

    /*{ return result }*/
    return (result);
}

/*end of file*/
