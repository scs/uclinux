// Copyright (C) 2000-2003 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/* _____________________________________________________________________

  Purpose     : This function computes arctan(y/x) with 32-bit float precision.
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : ~ x = Full Range
                ~ y = Full Range
                ~ NOT x = y = 0.0

  Accuracy    : ~ Relative error:
                ~ * 3 bits or less for entire range
                ~ Assumption: there is no error in the input value

  Data Memory : ~   4
  Prog Memory : ~ 154
  Cycles      : ~ 190 - max
                ~  33 - min

  Notes       : This function returns 0 for error input of x = y = 0
  _____________________________________________________________________
*/
#include <float.h>
#include "math.h"
#include "util.h"
#include <math_const.h>

FLOAT                               /*{ ret - atan(y/x) }*/
_atan2f(
    FLOAT y,                        /*{ (i) - y coordinate }*/
    FLOAT x                         /*{ (i) - x coordinate }*/
)
{
    FLOAT f, g;
    FLOAT num, den;
    FLOAT result;
    int n;

    static const FLOAT a[4] = {0, (FLOAT)PI_6, (FLOAT)PI_2, (FLOAT)PI_3};

    /*{ Check for x == 0 }*/
    if (x == (FLOAT)0.0)
    {
        /*{ if y == 0, return error }*/
        if (y == (FLOAT)0.0)
        {
            result = 0.0;
            return result;
        }

        result = (FLOAT)PI_2;

        /*{ if y > 0, return PI/2 }*/
        if (y > (FLOAT)0.0)
        {
            return result;
        }

        /*{ if y < 0, return -PI/2 }*/
        if (y < (FLOAT)0.0)
        {
            result = -result;
            return result;
        }
    }

    /*{ n = 0 }*/
    n = 0;

    /*{ num = |y| }*/
    /*{ den = |x| }*/
    num = y;
    den = x;
    if (num < (FLOAT)0.0)
    {
        num = -num;
    }
    if (den < (FLOAT)0.0)
    {
        den = -den;
    }

    /*{ if num > den }*/
    if (num > den)
    {
        /*{ swap den and num }*/
        f = den;
        den = num;
        num = f;
        /*{ n = 2 }*/
        n = 2;
    }
    /*{ f = num/den }*/
    f = DIV(num, den);

    /*{ if f > 2 - sqrt(3) }*/
    if (f > (FLOAT)TWO_MINUS_ROOT3)
    {
        /*{ f = [f * sqrt(3) - 1] / [sqrt(3) + f] }*/
        num = MPY((float)SQRT3_MINUS_1, f);
        num = SUB(num, 0.5);
        num = SUB(num, 0.5);
        num = ADD(num, f);
        den = ADD((float)SQRT3, f);
        f = DIV(num, den);

        /*{ n = n + 1 }*/
        n = n + 1;
    }

    g = f;
    if (g < (FLOAT)0.0)
    {
        g = -g;
    }

    /*{ if |f| < eps }*/
    if (g < (FLOAT)EPS_FLOAT)
    {
        /*{ result = f }*/
        result = f;
    }
    /*{ else |f| >= eps }*/
    else
    {

        /*{ g = f * f }*/
        g = MPY(f, f);
    
        /*{ result = R(g) = g * P(g) / Q(g) }*/
        /*{!INDENT}*/
        /*{ P(g) = p1 * g + p0 }*/
        num = MPY(ATANP_COEF1, g);
        num = ADD(num, ATANP_COEF0);
        num = MPY(num, g);
    
        /*{ Q(g) = (g + q1) * g + q0 }*/
        den = ADD(g, ATANQ_COEF1);
        den = MPY(den, g);
        den = ADD(den, ATANQ_COEF0);
    
        result = DIV(num, den);
        /*{!OUTDENT}*/
    
        /*{ result = result * f + f }*/
        result = MPY(result, f);
        result = ADD(result, f);
    }
    
    /*{ if n > 1, result = -result }*/
    if (n > 1)
    {
        result = -result;
    }
    
    /*{ result = result + a[n] }*/
    result = ADD(a[n], result);

    /*{ if x < 0, result = PI - result }*/
    if (x < (FLOAT)0.0)
    {
        result = SUB((float)PI, result);
    }

    /*{ if y < 0, result = -result }*/
    if (y < (FLOAT)0.0)
    {
        result = -result;
    }

    /*{ return result }*/
    return result;
}

/* end of file */
