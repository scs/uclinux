// Copyright (C) 2000-2003 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/**************************************************************************
   File: histogram.c

   Calculates the histogram of a vector.

   The function counts the number of input samples that fall into 
   each of the output bins.
   The size of the output vector is equal to the number of bins.

***************************************************************************/

#include <stats.h>

void _histogramf(const float *a, int *c, float max, float min, int n, int m)
{
    /* 
     * a is the input vector
     * c is the output vector
     * max is the maximum value of the elements of vector a 
     * min is the minimum value of the elements of vector a
     * n is the size of vector a
     * m is the number of bins.
     */

    int    i, bin;
    float  scalar;
   
    if ( (n <= 0) || (m <= 0) || (max <= min) )
    {
        return;
    }

    /* 
     * To determine which bin to associate with input A[i]
     * scale input value:
     *    BIN = ((A[i] - MIN_O) / RANGE_O) * RANGE_S - MIN_S
     *
     * Where:  BIN     = [0 .. Number of bins)
     *         MIN_O   = Minimum expected input value
     *         RANGE_O = Maximum - Minimum expected input value
     *         RANGE_S = Number of bins
     *         MIN_S   = Minimum bin (=0 always)
     *
     * Formula used:
     *    BIN = ((A[i] + MIN_O) * (RANGE_S / RANGE_0)
     *    =bin    =a[i]  =(-min)             = scalar
     */

    scalar = ((float) m) / (max - min);
    if(scalar == 0)
    {
        return;
    }

    // Initializes the output vector   
    for (i = 0; i < m; i++)
    {
        c[i] = 0;
    }

    // floating point addition is faster
    min = -min;
    // Calculates the histogram.
    for (i = 0; i < n; i++)
    {
        bin = (int)((a[i] + min) * scalar);
         
        if (bin >= 0 && bin < m)
        {
            c[bin]++;
        }	
    }
}

/*end of file*/
