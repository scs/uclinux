// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/*______________________________________________________________________

  Func name   : powf

  ----------------------------------------------------------------------------

  Purpose     : This function computes x^y using 32-bit float precision
  Description : The algorithm used to implement this function is adapted from
                Cody & Waite, "Software Manual for the Elementary Functions",
                Prentice-Hall, New Jersey, 1980.

  Domain      : ~ x = Full Range
                ~ y = Full Range
                ~ when x < 0, then |y| = 1.0, 2.0, 3.0, 4.0, ...
                ~ NOT x = 0, y < 0

  Accuracy    : ~ Relative error:
                ~ * 4 bits of error or less over entire range
                ~ Assumption: there is no error in the input value

  Data Memory : ~  27
  Prog Memory : ~ 328
  Cycles      : ~ 641 - max
                ~ 523 - min

  Notes       : ~ For x < 0, |y| != 1.0, 2.0, ... , this function returns 0.0.
                ~ For x = 0, y < 0, this function returns 3.4e38.
                ~ For x^y > 3.4e38, this function returns 3.4e38.
                ~ For x^y < -3.4e38, this function returns -3.4e38.
  _____________________________________________________________________
*/
#include <float.h>
#include <math.h>
#include "util.h"
#include <math_const.h>


FLOAT                               /*{ ret - pow(x, y) }*/
_powf(
    FLOAT x,                        /*{ (i) - base }*/
    FLOAT y                         /*{ (i) - power }*/
)
{
    FLOAT tmp;
    FLOAT znum, zden, result;
    FLOAT g, r, u1, u2, v, z;
    LONG m, p, negate, y_int, n;
    LONG mi, pi, iw1;
    FLOAT y1, y2, w1, w2, w;
    FLOAT *a1, *a2;
    FLOAT xtmp;
    LONG *lPtr = (LONG *)&xtmp;
    FLOAT *fPtr = &xtmp;
    static const LONG a1l[] =  {0,            /* 0.0 */
                        0x3f800000,   /* 1.0 */
                        0x3f75257d,   /* 0.9576032757759 */
                        0x3f6ac0c6,   /* 0.9170039892197 */
                        0x3f60ccde,   /* 0.8781260251999 */
                        0x3f5744fc,   /* 0.8408963680267 */
                        0x3f4e248c,   /* 0.8052451610565 */
                        0x3f45672a,   /* 0.7711054086685 */
                        0x3f3d08a3,   /* 0.7384130358696 */
                        0x3f3504f3,   /* 0.7071067690849 */
                        0x3f2d583e,   /* 0.6771277189255 */
                        0x3f25fed6,   /* 0.6484197378159 */
                        0x3f1ef532,   /* 0.6209288835526 */
                        0x3f1837f0,   /* 0.5946035385132 */
                        0x3f11c3d3,   /* 0.5693942904472 */
                        0x3f0b95c1,   /* 0.5452538132668 */
                        0x3f05aac3,   /* 0.5221368670464 */
                        0x3f000000};  /* 0.5 */
    static const LONG a2l[] =  {0,            /* 0.0 */
                        0x31a92436,   /* 4.922664054163e-9 */
                        0x336c2a94,   /* 5.498675648141e-8 */
                        0x31a8fc24,   /* 4.918108587049e-9 */
                        0x331f580c,   /* 3.710015050729e-8 */
                        0x336a42a1,   /* 5.454296925222e-8 */
                        0x32c12342,   /* 2.248419050943e-8 */
                        0x32e75623,   /* 2.693110978669e-8 */
                        0x32cf9890};  /* 2.41673490109e-8 */

    a1 = (FLOAT *)a1l;
    a2 = (FLOAT *)a2l; 
    negate = 0;

    /*{ if x == 0, compute 0^y }*/
    if (x == (FLOAT)0.0)
    {
        /*{ if y == 0, return 0^0 = 1.0 }*/
        if (y == (FLOAT)0.0)
        {
            return (FLOAT)1.0;
        }
        /*{ else if (y > 0), return 0^y = 0.0 }*/
        else if (y > (FLOAT)0.0)
        {
            return (FLOAT)0.0;
        }
        /*{ else (y < 0), return 1/0^y = 3.4e38 }*/
        else
        {
            return (FLOAT)FLT_MAX;
        }
    }
    /*{ else if x < 0, compute -|x|^y }*/
    else if (x < (FLOAT)0.0)
    {
        y_int = TO_LONG(y);
        /*{ if (y is not an integer power), return 0.0 }*/
        if (TO_FLOAT(y_int) != y)
        {
            return (FLOAT)0.0;
        }

        /*{ x = |x| }*/
        x = -x;
        /*{ negate = 1 if y is odd }*/
        negate = y_int & 0x1;
    }

    /*{ at this point, x = |x|, now compute x^y }*/
    xtmp = x;
    
    /*{ m = exponent part of x }*/
    m = (*lPtr >> 23);
    m = m - 126;

    /*{ g = fractional part of x }*/
    /* g = setxp(x, 0) -- done by setting exponent to 126 */
    *lPtr = (*lPtr & 0x807fffff) | (126 << 23);
    g = *fPtr;

    /*{ determine p using binary search }*/
    /*{!INDENT}*/
    /*{ p = 1 }*/
    p = 1;
    /*{ if (g <= A1[9]), then p = 9 }*/
    if (g <= a1[9])
    {
        p = 9;
    }
    /*{ if (g <= A1[p+4], then p = p + 4 }*/
    if (g <= a1[p + 4])
    {
        p = p + 4;
    }
    /*{ if (g <= A1[p+2], then p = p + 2 }*/
    if (g <= a1[p + 2])
    {
        p = p + 2;
    }
    /*{!OUTDENT}*/

    p = p + 1;

    /*{ determine z = 2 * znum / zden }*/
    /*{!INDENT}*/
    /*{ znum = g - A1[p+1] - A2[(p+1)/2] }*/
    znum = SUB(g, a1[p]);
    znum = SUB(znum, a2[p >> 1]);

    /*{ zden = g + A1[p+1] }*/
    zden = ADD(g, a1[p]);
    /*{!OUTDENT}*/

    p = p - 1;

    z = DIV(znum, zden);
    z = ADD(z, z);

    /* At this point, |z| < 0.044 */

    /*{ v = z * z }*/
    v = MPY(z, z);

    /*{ Compute R(z)) = (p2 * v + p1) * v * z }*/
    r = MPY(POWP_COEF2, v);
    r = ADD(r, POWP_COEF1);
    r = MPY(r, v);
    r = MPY(r, z);
    
    /*{ u2 = (z + R)&log2(e) }*/
    /* Using higher precision calculation */
    r = ADD(r, MPY((float)LOG2E_MINUS1, r));
    u2 = MPY((float)LOG2E_MINUS1, z);
    u2 = ADD(r, u2);
    u2 = ADD(u2, z);

    /*{ U1 = (float)(m*16 - p)/16 }*/
    u1 = TO_FLOAT((m * 16) - p);
    u1 = MPY(u1, 0.0625);

    /*{ y1 = REDUCE(y) }*/
    REDUCE_FLOAT(y, y1);

    /*{ y2 = y - y1 }*/
    y2 = SUB(y, y1);

    /*{ w = u2*y + u1*y2 }*/
    w = MPY(u1, y2);
    tmp = MPY(u2, y);
    w = ADD(tmp, w);

    /*{ w1 = reduce(w) }*/
    REDUCE_FLOAT(w, w1);

    /*{ w2 = w - w1 }*/
    w2 = SUB(w, w1);

    /*{ w = w1 + u1*y1 }*/
    w = MPY(u1, y1);
    w = ADD(w, w1);

    /*{ w1 = reduce(w) }*/
    REDUCE_FLOAT(w, w1);

    /*{ w2 = w2 + (w - w1) }*/
    tmp = SUB(w, w1);
    w2 = ADD(w2, tmp);

    /*{ w = REDUCE(w2) }*/
    REDUCE_FLOAT(w2, w);

    /*{ iw1 = INT(16 * (w1+w)) }*/
    tmp = ADD(w1, w);
    tmp = MPY(16.0, tmp);
    iw1 = TO_LONG(tmp);

    /*{ w2 = w2 - w }*/
    w2 = SUB(w2, w);

    /*{ if iw1 > INT(16*log2(FLT_MAX) - 1), return +-3.8e34 }*/
    if (iw1 > POW_BIGNUM)
    {
        result = (FLOAT)FLT_MAX;
        if (negate == 1)
        {
            result = -result;
        }
        return result;
    }

    /*{ if w2 > 0 then w2 = w2 - 1/16 and iw1 = iw1 + 1 }*/
    if (w2 > 0)
    {
        w2 = SUB(w2, 0.0625);
        iw1++;
    }

    /*{ if iw1 < INT(16*log2(FLT_MIN) + 1), return 0.0 }*/
    if (iw1 < POW_SMALLNUM)
    {
        return (FLOAT)0.0;
    }

    /*{ form p', m' }*/
    if (iw1 < 0)
    {
        mi = 0;
    }
    else
    {
        mi = 1;
    }
    n = iw1 / 16;
    mi = mi + n;
    pi = (mi * 16) - iw1;

    /*{ evaluate 2^w2 - 1 using min-max polynomial }*/
    /*{!INDENT}*/
    /*{ z = ((((q5 * w2 + q4) * w2 + q3) * w2 + q2) * w2 + q1) * w2 }*/
    z = MPY(POWQ_COEF5, w2);
    z = ADD(z, POWQ_COEF4);
    z = MPY(z, w2);
    z = ADD(z, POWQ_COEF3);
    z = MPY(z, w2);
    z = ADD(z, POWQ_COEF2);
    z = MPY(z, w2);
    z = ADD(z, POWQ_COEF1);
    z = MPY(z, w2);
    /*{!OUTDENT}*/

    /*{ z = (z + 1)*2^(-pi/16) }*/
    z = MPY(z, a1[pi + 1]);
    z = ADD(a1[pi + 1], z);

    /*{ result = add exponent mi into z }*/
    fPtr = &z;
    lPtr = (LONG *)fPtr;
    n = (*lPtr >> 23) & 0xff;   /* exponent of z */
    n = n - 127;                /* subtract exponent offset */
    mi = mi + n;                /* add exponents */
    mi = mi + 127;              /* add exponent offset */

    /* there is no need to check if max exponent exceeded */
    
    mi = mi & 0xff;             /* mask exponent */
    *lPtr = *lPtr & (0x807fffff); /* add exponent back into number */
    *lPtr = *lPtr | mi << 23;

    result = *fPtr;

    /*{ if negate, result = -result }*/
    if (negate)
    {
        result = -result;
    }

    /*{ return result }*/
    return result;
}

/*end of file*/
