// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/********************************************************************
   File: counti.c

   Counting number of one bits in an integer 
********************************************************************/              

#include "math.h"

int _countones(int a) 
{
  int res=0;

  while( a != 0 )
  {
    if (a<0) 
      res++;
  
    a = a << 1;
  }
  
  return res;
} 

    
/*end of file*/
