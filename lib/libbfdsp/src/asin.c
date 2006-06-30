// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html



/*  Copyright      : Spectrum Signal Processing Inc., 1998, 1999

// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

                   DSP Systems Worldwide
                       - DSP Hardware
                       - Development Tools
                       - Multi-Processor Operating Systems
                       - High Level Multi-Processing Debuggers
                   http://www.spectrumsignal.com/sharc/

  ----------------------------------------------------------------------------
  Description : This file contains the implementation of asin() and asind()


  Purpose     : This function computes arcsin(x) using 32-bit float precision.
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : x = [-1.0 ... 1.0]

  Accuracy    : ~ Relative error:
                ~ * 3 bits or less for entire range
                ~ Assumption: there is no error in the input value

  Data Memory : ~   4
  Prog Memory : ~ 147
  Cycles      : ~ 176 - max
                ~  32 - min

  Notes       : For x outside the domain, this function returns 0.0.
  _____________________________________________________________________{!EHDR}
*/
#include <float.h>
#include "math.h"
#include "util.h"
#include <math_const.h>


FLOAT                               /*{ ret - asin(x)}*/
_asinf(
    FLOAT x                         /*{ (i) - value for which to compute asinf }*/
)
{
    FLOAT y, g;
    FLOAT num, den, result;
    LONG i;
    FLOAT sign = 1.0;

    /*{ y = |x| }*/
    y = x;
    if (y < (FLOAT)0.0)
    {
        y = -y;
        sign = -sign;
    }

    /*{ if y > 0.5 }*/
    if (y > (FLOAT)0.5)
    {
        /*{ set i = 1 }*/
        i = 1;

        /*{ if y > 0, return error }*/
        if (y > (FLOAT)1.0)
        {
            result = 0.0;
            return result;
        }    

        /*{ g = (1 - y)/2 }*/
        g = SUB(1.0, y);
        g = MPY(0.5, g);

        /*{ y = -2/sqrt(g) }*/
        y = sqrtf(g);
        y = MPY(y, -2.0);
    }
    /*{ else y <= 0.5 }*/
    else
    {
        /*{ set i = 0 }*/
        i = 0;

        /*{ if y < eps }*/
        if (y < (FLOAT)EPS_FLOAT)
        {
            /*{ result = y }*/
            result = y;

            /*{ if sign < 0, result = -result }*/
            if (sign < (FLOAT)0.0)
            {
                result = -result;
            }
            /*{ return result }*/
            return result;
        }

        /*{ g = y * y }*/
        g = MPY(y, y);
    }

    /*{ result = y + y*R(g) }*/
    /*{!INDENT}*/
    /*{ R(g) = g*P(g)/Q(g) }*/
    /*{ P(g) = (p3 * g + p2) * g + p1 }*/
    num = MPY(ASINP_COEF3, g);
    num = ADD(num, ASINP_COEF2);
    num = MPY(num, g);
    num = ADD(num, ASINP_COEF1);
    num = MPY(num, g);

    /*{ Q(g) = ((g + q2) * g + q1) * g + q0 }*/
    den = ADD(g, ASINQ_COEF2);
    den = MPY(den, g);
    den = ADD(den, ASINQ_COEF1);
    den = MPY(den, g);
    den = ADD(den, ASINQ_COEF0);

    result = DIV(num, den);
    result = MPY(result, y);
    result = ADD(result, y);
    /*{!OUTDENT}*/

    /*{ if i == 1, result = PI/2 + result }*/
    /* (but more mathematically stable) */
    if (i == 1)
    {
        result = ADD(result, (float)PI_4);
        result = ADD(result, (float)PI_4);
    }

    /*{ if x < 0, result = -result }*/
    if (sign < (FLOAT)0.0)
    {
        result = -result;
    }

    /*{ return result }*/
    return result;
}

/* end of file */
