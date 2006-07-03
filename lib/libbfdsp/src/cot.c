// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html



  /*------------------------------------------------------------------------

  Purpose     : This function computes cot(x) using 32-bit float precision.
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : x = [-9099 ... 9099]

  Accuracy    : ~ Relative error:
                ~ * Primary range (-PI/4 to PI/4) - 2 bits of error or less
                ~ * Outside primary range         - 3 bits of error or less
                ~ * Error near singularities is indeterminate
                ~ Assumption: There is no error in the input value

  Data Memory : ~   0 
  Prog Memory : ~ 130
  Cycles      : ~ 124 - max
                ~  16 - min

  Notes       : For x outside the domain, this function returns 0.0.
  ____________________________________________________________________
*/
#include <float.h>
#include <math.h>
#include "util.h"
#include <math_const.h>


FLOAT                               /*{ ret - cot(x)}*/
_cotf(
    FLOAT x                         /*{ (i) - value for which to compute cotf }*/
)
{
    LONG n;
    FLOAT xn;
    FLOAT f, g;
    FLOAT x_int, x_fract;
    FLOAT result;
    FLOAT xnum, xden;

    /*{ If x is outside the domain, return 0.0 }*/
    if ((x > (FLOAT)X_MAX) || (x < (FLOAT)-X_MAX))
    {
        return (FLOAT)0.0;
    }

    /*{ split x into x_int and x_fract for better argument reduction }*/
    x_int = TO_FLOAT(TO_LONG(x));
    x_fract = SUB(x, x_int);

    /*{ Reduce the input to range between -PI/4, PI/4 }*/
    /*{!INDENT}*/
    /*{ n = Rounded long x/(PI/2) }*/
    if (x > (FLOAT)0.0)
    {
        n = TO_LONG(ADD(MPY(x, (float)INV_PI_2), 0.5));
    }
    else
    {
        n = TO_LONG(ADD(MPY(x, (float)INV_PI_2), -0.5));
    }

    /*{ xn = (double)n }*/
    xn = TO_FLOAT(n);

    /*{ f = x - xn*PI  }*/
    /* (using higher precision computation) */
    f = SUB(x_int, MPY(xn, PI_2_C1));
    f = ADD(f, x_fract);
    f = SUB(f, MPY(xn, PI_2_C2));
    f = SUB(f, MPY(xn, PI_2_C3));

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
        /*{ if n is odd, return -f }*/
        if (n & 0x0001)
        {
            result = -f;
        }
        /*{ else n is even, return 1/f }*/
        else
        {
            result = DIV(1.0, f);
        }            
        return result;
    }

    /*{ g = f * f }*/
    g = MPY(f, f);

    /*{ Compute sin approximation on reduced argument }*/
    /*{!INDENT}*/
    /*{ xnum = ((g * p2 + p1) * g * f + f }*/
    xnum = MPY(g, TANP_COEF2);
    xnum = ADD(xnum, TANP_COEF1);
    xnum = MPY(xnum, g);
    xnum = MPY(xnum, f);
    xnum = ADD(xnum, f);

    /*{ xden = (g * q2 + q1) * g + q0 }*/
    xden = MPY(g, TANQ_COEF2);
    xden = ADD(xden, TANQ_COEF1);
    xden = MPY(xden, g);
    xden = ADD(xden, TANQ_COEF0);
    /*{!OUTDENT}*/

    /*{ if n is odd, result = -xnum/xden }*/
    if (n & 0x0001)
    {
        xnum = -xnum;
    }
    /*{ else n is even, result = xden/xnum }*/
    else
    {
        result = xden;
        xden = xnum;
        xnum = result;
    }            
    result = DIV(xnum, xden);

    /*{ return result }*/
    return result;
}

/*end of file*/
