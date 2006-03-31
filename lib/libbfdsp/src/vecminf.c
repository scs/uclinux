// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   File: vecminf.c
 
   Returns minimum value stored in input vector a
    
***************************************************************************/
#include <vector.h>

float _vecminf(const float a[],int n)
{
	float min;
	int i;

	if( n <= 0 )
		return 0.0;

	min = a[0];
	for(i=1;i<n;i++)
	{
		if(a[i]<min)
		{
			min = a[i];
		}
	}

        return min;
}

/*end of file*/
