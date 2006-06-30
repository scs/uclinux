// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


#include <float.h>
#include "math.h"
#include "util.h"
#include <math_const.h>


FLOAT                                /*{ ret - log10(x) }*/
_log10f(
    FLOAT x                          /*{ (i) - value to do log10f on }*/
)
{
    FLOAT result;
    FLOAT f, w, z, a, b, r;
    FLOAT znum, zden;
    LONG n;
    FLOAT xn;
    LONG *xPtr = (LONG *)&x;
    FLOAT *fPtr = &x;

    /*{ if x <= 0.0, return -3.4e38 }*/
    if (x <= (FLOAT)0.0)
    {
        result = (FLOAT)-FLT_MAX;
        return result;
    }

    /*{ n = exponent part of x }*/
    n = (*xPtr >> 23);
    n = n - 126;

    /*{ f = fractional part of x }*/
    /* f = setxp(x, 0) -- done by setting exponent to 126 */
    *xPtr = (*xPtr & 0x807fffff) | (126 << 23);
    f = *fPtr;

    /*{ if f > sqrt(0.5) }*/
    if (f > (FLOAT)ROOT_HALF)
    {
        /*{ znum = f - 1 }*/
        znum = SUB(f, 0.5);
        znum = SUB(znum, 0.5);
        /*{ zden = f * 0.5 + 0.5 }*/
        zden = MPY(f, 0.5);
        zden = ADD(zden, 0.5);
    }
    /*{ else }*/
    else
    {
        /*{ n = n - 1 }*/
        n = n - 1;
        /*{ znum = f - 0.5 }*/
        znum = SUB(f, 0.5);
        /*{ zden = f * 0.5 + 0.5 }*/
        zden = MPY(znum, 0.5);
        zden = ADD(zden, 0.5);
    }
    xn = (FLOAT)n;

    /*{ z = znum/zden }*/
    z = DIV(znum, zden);

    /*{ w = z * z }*/
    w = MPY(z, z);

    /*{ R(z) = z + z * r(w) }*/
    /*{!INDENT}*/
    /*{ r(w) = w * A(w)/B(w) }*/
    /*{ A(w) = a1 * w + a0 }*/
    a = MPY(LOGA_COEF1, w);
    a = ADD(a, LOGA_COEF0);

    /*{ B(w) = w + b0 }*/
    b = ADD(w, LOGB_COEF0);

    r = DIV(a, b);
    r = MPY(r, w);
    r = MPY(r, z);
    r = ADD(r, z);
    /*{!OUTDENT}*/

    /*{ result = n *c + R(z) }*/
    /* using higher precision calculation */
    result = MPY(xn, LN2_C1);
    result = ADD(result, r);
    r = MPY(xn, LN2_C2);
    result = ADD(result, r);

    /*{ result = result * ln(e) }*/
    result = MPY(result, (float)LN_E);

    /*{ return result }*/
    return result;
}
/*end of file*/
