// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/*********************************************************************
   Func Name:    argf

   Description:  return phase of the complex input a

*********************************************************************/

#include <math.h>
#include <complex.h>

float _argf( complex_float a )
{
  float arg;

  arg = atan2f(a.im, a.re);
  return(arg);
}

/* end of file */
