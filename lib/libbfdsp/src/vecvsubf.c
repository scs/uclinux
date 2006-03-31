// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html



/*}______________________________________________________________________

  Func name   : vecvsubf

  ----------------------------------------------------------------------------

  Purpose     : Real vector - vector subtraction for float data types.
  Description : This function subtracts each element of vector `b[]` from 
                each element of input vector `a[]` and stores the result in 
                vector `c[]`.

  Domain      : Full Range.

  Accuracy    : 0 bits in error.
  _____________________________________________________________________
*/
#include <vector.h>

void
_vecvsubf(
    const float a[],    /*{ (i) - Input vector `a[]` }*/
    const float b[],    /*{ (i) - Input vector `b[]` }*/
    float c[],          /*{ (o) - Output vector `c[]` }*/
    int n               /*{ (i) - Number of elements in vector }*/
)
{
    int i;

    /*{ Each element of vector `b[]` is subtracted from each element
        of vector `a[]` and stored in vector `c[]`. }*/
    for (i = 0; i < n; i++)
        c[i] = a[i] - b[i];
}

/*end of file*/
