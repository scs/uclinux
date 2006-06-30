// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   File: rms.c

   Calculates the root mean square value for the floating point input vector.

***************************************************************************/

#include <stats.h>
#include "math.h"
#include "means.h"


float _rmsf(const float *a, int n) 
{
  // a is the input vector and n is its size.
      float m;

      if(n <= 0)
        return 0.0;

      m = _meansf (a, n);
      m = sqrtf(m);   // m is the rms value of a
	  
      return m;
}
/*end of file*/
