/*************************************************************************
 *
 * vminlocf.c : $Revision$
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
   This function finds minimum value index from given float vector
*/

#include <vector.h>

int vecminlocf(const float a[], int n)
{
   int min_loc = 0;    /* index of location of minimum no in a vector */
   float min = a[0];
   int i;

   for(i=1; i<n; i++)
   {
      if(a[i]<min)
      {
         min = a[i];
         min_loc = i;
      }
   }
   return min_loc;
}

/* end of file */
