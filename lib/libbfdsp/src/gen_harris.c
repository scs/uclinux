// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


#if 0
  Func name   : gen_harris_fr16
  Purpose     : Calculate Harris Window.
  Description : This function generates a vector containing the Harris window.  
                The length is specified by parameter `N`.  This window is also 
                known as the ``Blackman-Harris`` window.
#endif  

#include <window.h>
#include <math.h>
#include <fract.h>
#include "Lib_cos16_2PIx.h"


#ifndef NBITS1
#if defined(__ADSP21XX__) || defined(__ADSPBLACKFIN__)
#define NBITS1 15
#else
#error NBITS1 not defined
#endif
#endif


void
gen_harris_fr16(
    fract16 w[],      /* Window array `w` */
    int a,            /* Address stride   */
    int n             /* Window length    */
)
{
    int    i, scaled_i, n_half, n_offset;
    float  inv_n, tmp;

    /* Check window length and stride */
    if( n==1 )
    {
        /* window length of 1 would result in division by zero 
             -> return default */
        w[0] = 0x0;
        return;
    }
    else if (n > 1 && a > 0)
    {
        /* If window length is greater than one and the stride is
            greater than zero, initialize constants and window index */
        n_half = n / 2;
        n--;
        n_offset = n * a;
        inv_n = 1.0 / (float) n;

        /* Harris / Blackman-Harris window:
                       w[j] = a1 - a2 * cos(2pi * ( i/(n-1) ))
                                 + a3 * cos(4pi * ( i/(n-1) ))
                                 - a4 * cos(6pi * ( i/(n-1) ))
                                where i = 0,1,..,n-1,
                                      j = 0,a,..,a*(n-1)
                                coefficients in fract16: a1 = 0.35875 = 0x2deb,
                                                         a2 = 0.48829 = 0x3e81,
                                                         a3 = 0.14128 = 0x1215,
                                                         a4 = 0.01168 = 0x017f 
                                                                             */

        /*  First element: 
                        a1 - a2*cos(0) + a3*cos(0) - a4*cos(0) = 6e-5 (=0x1) */
        w[0] = 0x1;
        scaled_i = a;

        tmp = 0.0;
        /*  Loop for window length                    */
        /*   ! Loop does not compute final element !  */
        for (i = 1; i < n_half; i++)
        {
            /* Calculate Hamming coefficient */
            tmp += inv_n;
            w[scaled_i] = 0x2deb 
                   - (((long) 0x3e81 * (long) __cos16_2PIx(tmp) ) >> NBITS1)
                   + (((long) 0x1215 * (long) __cos16_2PIx(tmp * 2) ) >> NBITS1)
                   - (((long) 0x017f * (long) __cos16_2PIx(tmp * 3) ) >> NBITS1);
            
            /* function is symetric => fill array from far end 
                index: w[ ( ((n-1)-i) * a) ] = w[ (i * a) ]  */
            w[n_offset - scaled_i] = w[scaled_i];

            scaled_i += a;
        }

        /*  Last element: 
                  a1 - a2*cos(2pi) + a3*cos(4pi) - a4*cos(6pi) = 6e-5 (=0x1) */
        w[n_offset] = 0x1;

        /* At midpoint (=n/2) the function value will be 1, causing overflow
           => need to set to a valid maximum value
           This is only an issue with arrays of odd length */
        n++;
        if( n&1 !=0 )
            w[n_half * a] = 0x7fff;
    }
}

/* end of file */
