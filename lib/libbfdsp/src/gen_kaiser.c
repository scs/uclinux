// Copyright (C) 2000-2004 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


#if 0
  Func name   : bessel0 
  Purpose     : Calculate Bessel function J0(x).
  Description : The function implements the zero-th order Bessel 
                Function J0(x):
#endif


#define  ETSI_SOURCE
#include <window.h>
#include <math.h>
#include <fract.h>
#include <fract_math.h>


/************************************************************************/
static 
float           /* Bessel J0(x) approximation */
__bessel0(
    float   x   /* Input */
)
{
   float abs_x;
   float result;
   float y;

    /* Take absolute value of `x` */
    if (x < 0)
        abs_x = -x;
    else
        abs_x = x;

    /* Calculate Bessel approximation */
   if (abs_x < 3.75)
    {
      y = x / 3.75;
      y *= y;
      result = 1.0 + y * (3.5156229 + y * (3.0899424 + y * (1.2067492
         + y * (0.2659732 + y * (0.360768e-1 + y * 0.45813e-2)))));
    }
   else
    {
      y = 3.75 / abs_x;
      result = (expf(abs_x) / sqrtf(abs_x)) * (0.39894228 + y * (0.1328592e-1
         + y * (0.225319e-2 + y * (-0.157565e-2 + y * (0.916281e-2
         + y * (-0.2057706e-1 + y * (0.2635537e-1 + y * (-0.1647633e-1
          + y * 0.392377e-2))))))));
   }
   return (result);
}


/************************************************************************
  Func name   : gen_kaiser_fr16
  Purpose     : Calculate Kaiser Window.
  Description : This function generates a vector containing the Kaiser window.  
                The length is specified by parameter `N`.  The beta value is 
                specified by parameter `beta`.  Refer to signal processing
                texts for details on obtaining a value of `beta`.
 ************************************************************************/
void
gen_kaiser_fr16(
    fract16 w[],      /* Window array `w`      */
    float beta,       /* Kaiser beta parameter */
    int a,            /* Address stride        */
    int n             /* Window length         */
)
{
    int    i, scaled_i, n_half, n_offset;
    float  inv_c, d;
    float  alpha, tmp;

    /* Check window length and stride */
    if( n==1 )
    {
        /*{ window length of 1 would result in 
            division by zero -> return default }*/
        w[0] = 0x0;
        return;
    }
    else if (beta == 0.0)
    {
        /* For beta = 0, Kaiser window is equal to Rectangular window */

        scaled_i = 0;
        /* Loop for window length */
        for (i = 0; i < n; i++)
        {
            w[scaled_i] = 0x7fff;
            scaled_i += a;
        }
    }
    else if (n > 1 && a > 0)
    {
        /* If window length is greater than one and the stride is
            greater than zero, initialize constants and window index */
        n_half = n/2;
        n_offset = (n-1) * a;
        scaled_i = 0;

        /* Kaiser window:
                w[j] = fI(beta * (1 - ((i - alpha)/alpha)^2)^0.5 ) / fI(beta)
                         where  i = 0,1,..,n-1,
                                j = 0,a,..,a*(n-1),
                                fI()  = zero-th order modified Bessel function
                                        first kind,
                                alpha = (n-1) / 2                           */

        inv_c = 1.0 / __bessel0(beta);
        alpha = 1.0 / (float) (n-1);
      
        /* Loop for window length */
        for (i = 0; i < n_half; i++)
        {
            /* Calculate Kaiser coefficient */
            d = (float) (2*i - n + 1) * alpha;
            d = sqrtf(1 - d * d);
            tmp = __bessel0(beta * d) * inv_c;
            w[scaled_i] = saturate( (fract32)(tmp * 32768) );

            /* function is symetric => fill array from far end
               index: w[ ( ((n-1)-i) * a) ] = w[ (i * a) ]  */
            w[n_offset - scaled_i] = w[scaled_i];
             
            scaled_i += a;
        }

        /* At midpoint (=n/2) the function value will be 1, causing overflow
           => need to set to a valid maximum value
           This is only an issue with arrays of odd length */
        if( n&1 !=0 )
          w[n_half*a] = 0x7fff;
    }
}

/* end of file */
