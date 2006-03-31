// Copyright (C) 2000-2003 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/**************************************************************
   Func Name:    conj_fr16

   Description:  conjungate the complex input
                    re(result) = re(a)
                    im(result) = - im(a)

**************************************************************/

#include <complex.h>
#include <fract_math.h>

complex_fract16 _conj_fr16 ( complex_fract16 a )
{	
  complex_fract16 c;
  
  c.re = a.re;
  c.im = negate_fr1x16(a.im);

  return (c); 
}

/*end of file*/
