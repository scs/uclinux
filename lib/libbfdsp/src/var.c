// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   File: var.c

   Calculates the variance of the floating point input vector.

***************************************************************************/

#include <math.h>
#include <stats.h>
#include "means.h"

float varf(const float *a, int n)
{
  // a is the input vector and n its size.
      float m, ms, v;

      if(n <= 1)
	return 0;

      m = meanf (a, n);
      ms = _meansf (a, n);
      
      v = ms - m*m;
      v = (v * n) / (n-1);

       // v stores the variance of vector a.
      return v;
}
/*end of file*/
