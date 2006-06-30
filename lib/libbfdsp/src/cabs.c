// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/**************************************************************************
   File: cabs.c
 
   This function gives the absolute value of a complex number.    

***************************************************************************/

#include "math.h"
#include <complex.h>

float _cabsf(complex_float a)
{
    float output,abs_re,abs_im;
    int *temp_re, *temp_im, *temp_out;
    unsigned int exp_re, exp_im, exp_mean, exp_new_re, exp_new_im, exp_out;
    int exp_diff;

    abs_re = fabsf(a.re);
    abs_im = fabsf(a.im);

    if(abs_im == 0)
    {
      return(abs_re);        
    }
    else if(abs_re == 0)
    {
      return(abs_im); 
    }

    temp_re = (int *) &(a.re);
    temp_im = (int *) &(a.im);

    exp_re = *temp_re & 0x7f800000;
    exp_im = *temp_im & 0x7f800000;

    exp_diff = (int) exp_re - (int) exp_im;
    
    if (exp_diff > 109051904)
        return (abs_re);

    if (exp_diff < -109051904)
        return (abs_im);

    exp_mean = (exp_re + exp_im);
    exp_mean >>= 1;
    exp_mean &= 0x7f800000;

    exp_new_re = exp_re - exp_mean;
    exp_new_im = exp_im - exp_mean;

    /* Add the offset */
    exp_new_re += 0x3f800000; 
    exp_new_im += 0x3f800000;

    /* Replace the old exponents with the new ones */
    *temp_re &= 0x807fffff;
    *temp_im &= 0x807fffff;
    *temp_re |= exp_new_re;
    *temp_im |= exp_new_im;

    /*{ Calculate absolute value of complex number }*/
    output = sqrtf((a.re * a.re) + (a.im * a.im));

    /* Get int pointer */
    temp_out = (int *) &output;

    /* Obtain exponent of result */
    exp_out = *temp_out & 0x7f800000;

    /*{ Add the mean input exponent to the result exponent }*/
    exp_mean -= 0x3f800000;     //127 << 23
    exp_out += exp_mean;

    /* Replace the old exponent with the proper one */
    *temp_out &= 0x807fffff;
    *temp_out |= exp_out;

    return (output);
}

/* end of file */
