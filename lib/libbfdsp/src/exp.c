// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html



/*______________________________________________________________________

  Func name   : expf

  ----------------------------------------------------------------------------

  Purpose     : This function computes exp(x) using 32-bit float precision.
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : x = [-87.3 ... 88.7]

  Accuracy    : ~ Relative error:
                ~ * Primary range (-ln(2)/2 to ln(2)/2) - 1 bits of error or less
                ~ * Outside primary range               - 3 bits of error or less
                ~ Assumption: there is no error in the input value

  Data Memory : ~   0
  Prog Memory : ~  99
  Cycles      : ~ 108 - max
                ~  24 - min

  Notes       : ~ For x = -|x| outside the domain, this function returns 0.0.
                ~ For x = |x| outside the domain, this function returns 3.4e38.
  _____________________________________________________________________
*/
#include <float.h>
#include <math.h>
#include "util.h"
#include <math_const.h>
#include <complex.h>

FLOAT _expf(FLOAT x)                        
{
    FLOAT y;
    LONG n;
    FLOAT xn, x_int, x_fract;
    FLOAT g, z, xnum, xden;
    FLOAT result;
    LONG *resultlp = (LONG *)&result;

    /*{ if x > 88.7, return 3.4e38 }*/
    if (x > (FLOAT)X_MAX_EXP)
    {
        return (FLOAT)FLT_MAX;
    }

    /*{ if x < -87.3, return 0.0 }*/
    if (x < (FLOAT)X_MIN_EXP)
    {
        return (FLOAT)0.0;
    }

    y = x;
    if (y < (FLOAT)0.0)
    {
        y = -y;
    }

    /*{ if |x| < eps, return 1.0 }*/
    if (y < (FLOAT)FLT_EPSILON)
    {
        return (FLOAT)1.0;
    }

    /*{ n = intrnd(x / ln(c)) }*/
    g = (FLOAT)0.5;
    if (x <= (FLOAT)0.0)
    {
        g = -g;
    }
    n = TO_LONG(ADD(MPY(x, (float)INV_LN2), g));

    /*{ xn = (float)n }*/
    xn = TO_FLOAT(n);

    /*{ split x into x_int and x_fract for better argument reduction }*/
    x_int = TO_FLOAT(TO_LONG(x));
    x_fract = SUB(x, x_int);

    /*{ g = x - xn*ln2 }*/
    /* (using higher precision computation) */
    g = SUB(x_int, MPY(xn, LN2_C1));
    g = ADD(g, x_fract);
    g = SUB(g, MPY(xn, LN2_C2));

    /*{ z = g * g }*/
    z = MPY(g, g);

    /*{ Compute exp approximation on reduced argument }*/
    /*{!INDENT}*/
    /*{ xnum = (z * p1 + p0) * g }*/
    xnum = MPY(z, EXPP_COEF1);
    xnum = ADD(xnum, EXPP_COEF0);
    xnum = MPY(xnum, g);

    /*{ xden = (q2 * z + q1) * z + q0 }*/
    xden = MPY(EXPQ_COEF2, z);
    xden = ADD(xden, EXPQ_COEF1);
    xden = MPY(xden, z);
    xden = ADD(xden, EXPQ_COEF0);

    /*{ result = 0.5 + xnum/[xden - xnum] }*/
    result = SUB(xden, xnum);
    result = DIV(xnum, result);
    result = ADD(0.5, result);
    /*{!OUTDENT}*/

    /*{ n = n + 1 to take the scaling of result into account }*/
    n = n + 1;

    /*{ add n to the exponent of result }*/
    n = n << 23;                       /* shift n into exponent position */
    *resultlp = n + *resultlp;         /* add exponent to result */

    /*{ return result }*/
    return result;
}

/*end of file*/
