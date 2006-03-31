// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/*______________________________________________________________________

  Func name   : sinhf

  ----------------------------------------------------------------------

  Purpose     : This function computes sinh(x) using 32-bit float precision.
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : x = [-88.7 ... 88.7]

  Accuracy    : ~ Relative error:
                ~ * Primary range (-1 to 1) - 1 bits of error or less
                ~ * Outside primary range   - 3 bits of error or less
                ~ Assumption: there is no error in the input value

  Data Memory : ~   0
  Prog Memory : ~ 132
  Cycles      : ~ 173 - max
                ~  30 - min

  Notes       : For x outside the domain, this function returns +-3.4e38.
  _____________________________________________________________________
*/
#include <float.h>
#include <math.h>
#include "util.h"
#include <math_const.h>

FLOAT                                /*{ ret - sinh(x) }*/
_sinhf(
    FLOAT x                          /*{ (i) - value to do sinhf on }*/
)
{
    FLOAT y, w, z;
    FLOAT f, xnum, xden;
    FLOAT result;
    FLOAT sign = 1.0;


    /*{ y = |x| }*/
    y = x;
    /*{ sign = 1.0 }*/
    /*{ if x < 0, sign = -sign }*/
    if (x < (FLOAT)0.0)
    {
        y = -y;
        sign = -sign;
    }

    /*{ if (y > 1.0) }*/
    if (y > (FLOAT)1.0)
    {
        /*{ if (y > X_MAX_EXP) }*/
        if (y > (FLOAT)X_MAX_EXP)
        {
            /*{ w = y - ln(v) }*/
            w = SUB(y, (float)LN_V);

            /*{ if w > X_MAX_EXP }*/
            if (w > (FLOAT)X_MAX_EXP)
            {
                /*{ result = +3.4e38 }*/
                result = (FLOAT)FLT_MAX;
                /*{ if sign < 0, result = -result }*/
                if (sign < (FLOAT)0.0)
                {
                    result = -result;
                }
                /*{ return result }*/
                return result;
            }

            /*{ z = exp(w) }*/
            z = expf(w);

            /*{ result = (v/2) * z }*/
            /* using higher precision computation */
            result = MPY((float)V_2_MINUS1, z);
            result = ADD(result, z);
        }
        /*{ else y <= X_MAX_EXP }*/
        else
        {
            /*{ z = exp(y) }*/
            z = expf(y);

            /*{ result = ((z - 1 / z) / 2 }*/
            result = DIV(-0.5, z);
            z = MPY(0.5, z);
            result = ADD(z, result);
        }

     }
    /*{ else y <= 1.0 }*/
    else
    {
        /*{ if y < eps, result = y }*/
        if (y < (FLOAT)FLT_EPSILON)
        {
            result = y;
        }
        else
        {
            /*{ result = y + y * R(x^2) }*/
            /*{!INDENT}*/
            /*{ R(f) = f*P(f)/Q(f) }*/

            /*{ f = x * x }*/
            f = MPY(x, x);

            /*{ P(f) = (p2 * f + p1) * f + p0 }*/
            xnum = MPY(SINHP_COEF2, f);
            xnum = ADD(xnum, SINHP_COEF1);
            xnum = MPY(xnum, f);
            xnum = ADD(xnum, SINHP_COEF0);

            /*{ Q(f) = (f + q1) * f + q0 }*/
            xden = ADD(f, SINHQ_COEF1);
            xden = MPY(xden, f);
            xden = ADD(xden, SINHQ_COEF0);
            /*{!OUTDENT}*/

            result = DIV(xnum, xden);
            result = MPY(result, f);
            result = MPY(result, y);
            result = ADD(result, y);
        }
    }

    /*{ if sign < 0, result = -result }*/
    if (sign < (FLOAT)0.0)
    {
        result = -result;
    }
 
    /*{ return result }*/
    return result;
}

/*end of file*/
