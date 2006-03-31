// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/*******************************************************************
   Func Name:    csub_fr16

   Description:  subtraction of two complex numbers

*******************************************************************/

#include <complex.h>

complex_fract16 _csub_fr16( complex_fract16 a, complex_fract16 b)
{
    complex_fract16 result;
    fract32 real, imag;
	 
    real = a.re - b.re;
    imag = a.im - b.im;

    if(real >= 32767)
      result.re = 0x7fff;
    else if(real <= -32768)
      result.re = 0x8000;
    else
      result.re = real;

    if(imag >= 32767)
      result.im = 0x7fff;
    else if(imag <= -32768)
      result.im = 0x8000;
    else
      result.im = imag;

    return (result);
}
/*end of file*/
