// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/**************************************************************************
   Func Name:    means

   Description:  Internal function required for calculating rms, var value. 
                 It computes the mean of squared a[i]

**************************************************************************/

#include "means.h"

float _meansf (const float *a, int n)
{
   int i, m;
   float k, sum;

   if( n <= 0)
      return 0.0;
   else
   {	
      sum = 0;
      for (i = 0; i < n; i++) {
            k = (*a++);
            k *= k;
            sum += k;
      }
      sum = sum / n;
      return sum;
   }
} 
/*end of file*/
