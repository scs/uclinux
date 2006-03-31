// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/*****************************************************************************
   Func Name:    cvecsmltf

   Description:  multiply each complex member a[i] in a[] with complex scalar b

*****************************************************************************/

#include <complex.h>
#include <vector.h>

void
_cvecsmltf(
	const complex_float a[],   /*{ (i) - Input vector `a[]` }*/
	complex_float b,           /*{ (i) - Input scalar `b` }*/
	complex_float c[],         /*{ (o) - Output vector `c[]` }*/
	int n                      /*{ (i) - Number of elements in vector }*/
)
{
     int i;

     for (i=0;i<n;i++)
     {
       c[i].re = a[i].re * b.re - a[i].im * b.im;
       c[i].im = a[i].re * b.im + a[i].im * b.re;
     }
}

/*end of file*/
