// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   Func Name:    normf

   Description:  normalizing the complex input a

****************************************************************************/

#include <math.h>
#include <complex.h>

complex_float _normf(complex_float a )
{
   complex_float  c;
   float          d;

   d = cabsf(a);

   if( d == 0.0F )
   {
      c.re = 0.0F;
      c.im = 0.0F;
   }
   else
   {
      d = 1.0F / d;
      c.re = a.re * d;
      c.im = a.im * d;
   }

   return (c);
}

/*end of file*/
