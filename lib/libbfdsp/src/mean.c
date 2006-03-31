// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/**************************************************************************
   File: mean.c

   Calculates the mean value of a vector.

***************************************************************************/

#include <stats.h>

float _meanf(const float *a, int n)
{
      // a is the input vector and n is its size.
      int i; 
      float sum =0;

      if(n <= 0)
	   return 0;

      for (i = 0; i < n; i++) 
           sum += (*a++);   // calculates the summation for mean

      sum = sum / n;        // i stores the mean value
      return sum;
}
/*end of file*/
