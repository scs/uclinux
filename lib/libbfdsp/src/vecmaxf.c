// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   File: vecmaxf.c
 
   Returns maximum value stored in input vector a
    
***************************************************************************/

#include <vector.h>

float _vecmaxf(const float a[],int n)
{
	float max;	
	int i;

 	if( n<= 0 )
		return 0.0;  //as done for fract16

	max = a[0];
	for(i=1;i<n;i++)
	{
		if(a[i]>max)
		{
			max = a[i];
		}
	}
   
        return max;
}

/*end of file*/
