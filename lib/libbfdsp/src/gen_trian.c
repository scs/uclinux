// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


#if 0
  Func name   : gen_triangle_fr16
  Purpose     : Calculate Triangle Window.
  Description : This function generates a vector containing the Triangle window.
                The length is specified by parameter `N`.  Refer to the 
                Bartlett window regarding the relationship between it and 
                the Triangle window.
#endif

#include <window.h>
#include <fract.h>

void
gen_triangle_fr16(
    fract16 w[],      /*{ Window array `w` }*/
    int a,            /*{ Address stride }*/
    int n             /*{ Window length }*/
)
{
    int    i, scaled_i, n_half, n_offset;
    float  inv_n;

    /* Check window length and stride */
    if (n > 0 && a > 0)
    {
        /* If window length is greater than zero and the stride is
            greater than zero, initialize constants and window index */
        scaled_i = 0;
        n_half   = n/2;

        /* Check if `n` is even */
        if( n%2 == 0 )
        {
            /* Even Triangular window:
                                 w[j] = (2i + 1) / n,       0 < i < n/2
                                 w[j] = (2n - 2i - 1) / n,  n/2 <= i < n
                                        where  j = 0,a,..,a*(n-1)     */

            inv_n    = 1.0 / (float) n;
            n_offset = n_half * a;

            /* Calculate triangle coefficients for even length window */
            for (i = 0; i < n_half; i++)
            {
                /* Compute coefficients for range:  0 < i < n/2       
                     w[ i*a ] = (2i + 1) / n                          */
                w[scaled_i] = ( (float)(2 * i + 1) * inv_n ) * 32768;

                /* Compute coefficients for range:  n/2 <= i < n      
                   w[ (n_half+i)*a ] = (2n - 2(n/2+i) - 1) / n        */
                w[n_offset+scaled_i] = ((float)(n - 2*i - 1) * inv_n ) * 32768;

                scaled_i += a;
            }
        }
        else
        {
            /* Odd Triangular window:
                                 w[j] = (2i + 2) / (n + 1),    0 < i < n/2
                                 w[j] = (2n - 2i) / (n + 1),   n/2 <= i < n
                                        where  j = 0,a,..,a*(n-1)     */
            
            inv_n    = 1.0 / (float) (n+1);
            n_offset = (n_half+1) * a;
            
            /* Calculate triangle coefficients for odd length window */
            for (i = 0; i < n_half; i++)
            {
                /* Compute coefficients for range:  0 < i < n/2
                     w[ i*a ] = (2i + 2) / (n + 1)                   */
                w[scaled_i] = ( (float)(2 * i + 2) * inv_n) * 32768;

                /* Compute coefficients for range:  n/2 <= i < n
                   w[ (n_half+1+i)*a ] = (2n - 2((n+1)/2 + i) / (n + 1)        */
                w[n_offset+scaled_i] = ((float)(n - 1 - 2 * i) * inv_n) * 32768;

                scaled_i += a;
            }

            /* At midpoint (=n/2) the function value will be 1, causing overflow
               => need to set to a valid maximum value 
               This is only an issue with arrays of odd length */
            w[n_half * a] = 0x7fff;
        }
    }
}

/*end of file*/
