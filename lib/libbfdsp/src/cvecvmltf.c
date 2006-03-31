// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
  Func name   : cvecvmltf

  Purpose     : Complex vector * vector multiplication for float data types.
  Description : This function multiplies each element i in vector `a[]` with
                each element i in input vector `b[]` and stores the result in 
		vector `c[]`, where 0 <= i < n and n = length a[] = length b[]

****************************************************************************/

#include <complex.h>
#include <vector.h>


void
_cvecvmltf(
	const complex_float a[],   /*{ (i) - Input vector `a[]` }*/
	const complex_float b[],   /*{ (i) - Input vector `b[]` }*/
	complex_float c[],         /*{ (o) - Output vector `c[]` }*/
	int n                      /*{ (i) - Number of elements in vector }*/
)
{
    int i;

    /*{ Perform a complex multiplication for each element of
        vector `a[]` and `b[]` and store in vector `c[]`. }*/
    for (i = 0; i < n; i++)
    {
        c[i].re = a[i].re * b[i].re - a[i].im * b[i].im;
        c[i].im = a[i].re * b[i].im + a[i].im * b[i].re;
    }
}

/*end of file*/ 

