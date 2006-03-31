// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/*****************************************************************************
  Func name   : cvecvaddf

  Purpose     : Complex vector + vector addition for float data types.
  Description : This function adds each element i of vector `a[]` to each 
                element i of input vector `b[]` and stores the result in 
                vector `c[]`, where 0 <= i < n and n = length a[] = length b[]

*****************************************************************************/                
#include <complex.h>
#include <vector.h>

void
_cvecvaddf(
	const complex_float a[],   /*{ (i) - Input vector `a[]` }*/
	const complex_float b[],   /*{ (i) - Input vector `b[]` }*/
	complex_float c[],         /*{ (o) - Output vector `c[]` }*/
	int n                      /*{ (i) - Number of elements in vector }*/
)
{
    int i;

    /*{ Each element of vector `a[]` is added with each element of vector 
        `b[]` and stored in vector `c[]`. }*/
    for (i = 0; i < n; i++)
    {
	    c[i].re = a[i].re + b[i].re;
	    c[i].im = a[i].im + b[i].im;
    }
}
/*end of file*/

