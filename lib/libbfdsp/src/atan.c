// Copyright (C) 2000-2003 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


 /* ----------------------------------------------------------------------------

  Purpose     : This function computes arctan(x) using 32-bit float precision.
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : Full Range

  Accuracy    : ~ Relative error:
                ~ * 3 bits or less for entire range
                ~ Assumption: there is no error in the input value

  Data Memory : ~   0
  Prog Memory : ~ 112
  Cycles      : ~ 165 - max
                ~  65 - min
  _____________________________________________________________________{!EHDR}
*/
#include <float.h>
#include "math.h"
#include "util.h"
#include <math_const.h>

FLOAT                               /*{ ret - atanf(x)}*/
_atanf(
    FLOAT x                         /*{ (i) - value for which to compute atanf }*/
)
{
    FLOAT f, g;
    FLOAT num, den;
    FLOAT result;

    static const FLOAT a[4] = {0, (FLOAT)PI_6, (FLOAT)PI_2, (FLOAT)PI_3};

    /*{ n = 0 }*/
    int n = 0;

    /*{ f = |x| }*/
    f = x;
    if (f < (FLOAT)0.0)
    {
        f = -f;
    }

    /*{ if f > 1.0 }*/
    if (f > (FLOAT)1.0)
    {
        /*{ f = 1/f }*/
        f = DIV(1.0, f);
        /*{ n = 2 }*/
        n = 2;
    }

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

    /*{ if x < 0, result = -result }*/
    if (x < (FLOAT)0.0)
    {
        result = -result;
    }

    /*{ return result }*/
    return result;
}

/* end of file */
