// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   File: cdiv.c

   Complex floating point division

****************************************************************************/

#include <complex.h>
#include <math.h>

complex_float _cdivf( complex_float a, complex_float b )
{
    complex_float   c;
    float           fractio, denum;

    /*
        This function performs a complex division of two numbers:

                       a.real * b.real + a.imag * b.imag
              c.real = ---------------------------------
                       b.real * b.real + b.imag * b.imag

                       a.imag * b.real - a.real * b.imag
              c.imag = ---------------------------------
                       b.real * b.real + b.imag * b.imag

       To prevent avoidable overflows, underflow or loss of precision,
       the following alternative algorithm is used:

       If |b.re| >= |b.im|
         c.re = (a.re + a.im * (b.im / b.re)) / (b.re + b.im * (b.im / b.re));
         c.im = (a.im - a.re * (b.im / b.re)) / (b.re + b.im * (b.im / b.re));

       Else    // |b.re| < |b.im|
         c.re = (a.re * (b.re / b.im) + a.im) / (b.re * (b.re / b.im) + b.im);
         c.im = (a.im * (b.re / b.im) - a.re) / (b.re * (b.re / b.im) + b.im);
     */

    if( (b.re == 0) && (b.im == 0) )
    {
       // return 0
       c.re = 0.0F;
       c.im = 0.0F;
    }
    else if (b.re == 0)
    {
       c.re =   a.im / b.im;
       c.im = -(a.re / b.im);
    }
    else if (b.im == 0)
    {
       c.re =   a.re / b.re;
       c.im =   a.im / b.re;
    }
    else if( fabsf(b.re) >= fabsf(b.im) )
    {
       fractio = b.im / b.re;
       denum   = 1.0F / (b.re + b.im * fractio);
       c.re    = (a.re + a.im * fractio) * denum;
       c.im    = (a.im - a.re * fractio) * denum;
    }
    else
    {
       fractio = b.re / b.im;
       denum   = 1.0F / (b.re * fractio + b.im);
       c.re    = (a.re * fractio + a.im) * denum;
       c.im    = (a.im * fractio - a.re) * denum;
    }

    return (c);
}
/* end of file */
