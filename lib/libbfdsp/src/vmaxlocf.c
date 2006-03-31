/*************************************************************************
 *
 * vmaxlocf.c : $Revision$
 *
 * (c) Copyright 2000-2002 Analog Devices, Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

/*
   This function finds maximum value index from given float vector
*/

#include <vector.h>

int vecmaxlocf(const float a[], int n)
{
   int max_loc = 0;      /* index of location of maximum no in a vector */
   float max = a[0];
   int i;

   for(i=1; i<n; i++)
   {
      if(a[i]>max)
      {
         max = a[i];
         max_loc = i;
      }
   }
   return max_loc;
}

/* end of file */
