// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   Func name   : vecdotf

   Purpose     : Real vector dot product for float data types.
   Description : This function multiplies the i-th element of input vector `a[]` 
                 with the i-th element of input vector `b[]` 
                 and returns the sum of all products a[i]*b[i] for 0<=i<n.

****************************************************************************/

#include <vector.h>

float           /*{ ret - Dot product }*/
_vecdotf(
    const float a[],    /*{ (i) - Input vector `a[]` }*/
    const float b[],    /*{ (i) - Input vector `b[]` }*/
    int n               /*{ (i) - Number of elements in vector }*/
)
{
    int i;
    float acc = 0.0;

    /*{ Multiply each element of vector `a[]` with each element of
        vector `b[]` and accumulate result. }*/
    for (i = 0; i < n; i++)
        acc += a[i] * b[i];

    return (acc);
}

/*end of file*/

