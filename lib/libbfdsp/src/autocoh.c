// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/**************************************************************************
   File: autocoh.c

   Auto Coherrance of a vector.

***************************************************************************/
#include <stats.h>

void _autocohf(const float *a, int n, int m, float *c)
{   
  /* a is the input vector
     n is the size of vector
     m is the number of bins
     c is the output vector.
  */
    int i,j;
    float mean =0;

    if (n <= 0 || m <= 0)
    {
      return;
    }

    /*{ Calculate the mean value of input vector }*/
    for (i = 0; i < n; i++)
    {
        mean += a[i];
    }
    mean = mean / n;

    for (i=0; i < m; i++)
    {
        /*Calculate the autocorrelation of input vector */
        c[i] = 0.0;
        for (j = 0; j < n-i; j++)
        {
            c[i] += (a[j] * a[j+i]);
        }

        c[i] = c[i] / n;
        /*Autocorrelation minus the squared mean*/
        c[i] -= mean * mean;
    }
  
}
/* end of file */
