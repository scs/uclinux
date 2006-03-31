// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   File: transpm.c
 
   This function calculates the transpose of a floating point matrix.
    
***************************************************************************/

#include <matrix.h>
 
void _transpmf(const float *a, int n, int m, float *c )
{
  /* a is the input matrix
     n is the number of rows in a 
     m is the number of colums in a
     c is the output matrix.
  */
    int i,j;  

    if(m<=0 || n <= 0)
      return;

    for(i=0; i<n; i++)
      for(j=0; j<m; j++)
        c[j*n+i] = a [i*m+j];
}
/*end of file*/
