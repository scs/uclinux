// Copyright (C) 2002 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/******************************************************************************
  File Name      : twidfftrad2_fr16.c

  Purpose        : This function generates twiddle factors for the given length
                   for radix-2 algorithm.

  Notes          : This function takes FFT length 'n' as input parameter and
                   generates the lookup table of complex twiddle coefficients
                   of size n/2. The function can be used to generate twiddle
                   factors only for radix-2 FFT algorithm. The FFT length 'n'
                   must be a power of two and at least 16.

                   The twiddle factor stored in complex array 'w'
                   will have cosine and -sine values.

  $Revision$
*******************************************************************************/
#include <filter.h>
#include <math.h>
#include <math_const.h>


/* Define macro if static memory can be used for temporary array.
   This will improve performance and it is the default setting
   for building libraries
*/
#define __USE_FAST_LOOKUP__  1


void twidfftrad2_fr16(
  complex_fract16 w[],  /* pointer to complex twiddle array */
  int n                 /* FFT length */
  )
{
  int      i, idx;
  int      nquart = n/4;
#ifdef __USE_FAST_LOOKUP__
  fract16  val[nquart+1]; //index starting at 1!
#else
  fract16  val;
#endif 
  float    step;

  step = 1.0/(float)nquart;
  idx  = 0;

  // 1. Quadrant
  // Compute cosine and -sine values for the range [0..PI/2)
  w[idx].re = 0x7fff;  //=cos(0)
  w[idx].im = 0x0;     //=sin(0)
  for(i = 1; i < nquart; i++)
  {
    idx++;
#ifdef __USE_FAST_LOOKUP__
    val[i] = (fract16) ((i*step) * 32767.0); //count up
    w[idx].re = cos_fr16(val[i]);
    w[idx].im = -sin_fr16(val[i]);
#else
    val = (fract16) ((i*step) * 32767.0); //count up
    w[idx].re = cos_fr16(val);
    w[idx].im = -sin_fr16(val);
#endif
  }

  // 2. Quadrant
  // Compute cosine values for the range [PI/2..PI)
  // Since sin( [PI/2..PI] ) a mirror image of sin( [0..PI/2] )
  // no need to compute sine again
  idx++;
  w[idx].re = 0x0;      //=cos(PI/2)
  w[idx].im = 0x8000;   //=-sin(PI/2);
  for(i = 1; i < nquart; i++)
  {
    idx++;
#ifdef __USE_FAST_LOOKUP__
    w[idx].re = -cos_fr16(val[nquart-i]);
    w[idx].im = w[nquart-i].im; 
#else
    val = (fract16) (((nquart-i)*step) * 32767.0); //count down
    w[idx].re = -cos_fr16(val);
    w[idx].im = w[nquart-i].im;
#endif
  }
}

/* End of file */
