// Copyright (C) 2000-2004 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


#if 0
  Func name   : gen_gaussian_fr16

  Purpose     : Calculate Gaussian Window.
  Description : This function generates a vector containing the Gaussian window.
                The length is specified by parameter `N`.
#endif

#define  ETSI_SOURCE
#include "math.h"
#include <window.h>
#include <fract.h>
#include <fract_math.h>


void
gen_gaussian_fr16(
    fract16 w[],        /* Window array `w` */
    float alpha,        /* Gaussian alpha parameter */
    int a,              /* Address stride */
    int n               /* Window length */
)
{
    int i, j;
    float d, tmp, alpha_over_n;

    /* Check window length and stride */
    if (n > 0 && a > 0)
    {
        /* If window length is greater than zero and the stride is
           greater than zero, initialize constants and window index */
        j = 0;

        /* Gaussian window:
                      w[j] = exp( -0.5*( (alpha * (i - n/2 - 1/2) / (n/2))^2 ))
                  or  w[j] = exp( -0.5*( (alpha * (2i - n - 1) / (n))^2 ))
                               where   i = 0,1,..,n-1,
                                       j = 0,a,..,a*(n-1) */

        /* expf( -0.5 * d * d ), with d = alpha * (..) / n =>
           expf( -d * d ), with d = sqrt(0.5) * alpha * (..) / n =>
           alpha_over_n = sqrt(0.5) * alpha / n                     */
        alpha_over_n = (float) 0.70710678118655 * (alpha / (float) n);

        /* Loop for window length */
        /*{ need to test for j to avoid array overflow for a>1 }*/
        for (i = 0; i < n; i++)
        {
            /* Calculate Gaussian coefficient */
            d = alpha_over_n * (float) (2 * i - n - 1);
            tmp = expf( -d * d );
            w[j] = saturate( (fract32)(tmp * 32768) );
            j += a;
        }
    }
}

/*end of file*/
