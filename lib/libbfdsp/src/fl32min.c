// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/**************************************************************************** 
  Func name   : float32_min

  Purpose     : This function returns the lesser of 2 input values.
  Description : 

  Domain      : ~ x = [-3.4e38 ... 3.4e38]
                ~ y = [-3.4e38 ... 3.4e38]

 *****************************************************************************/
#include "math.h"

float                      /*{ ret - min of (x, y) }*/
_float32_min(
    float x,               /*{ (i) - input parameter 1 }*/
    float y                /*{ (i) - input parameter 2 }*/
)
{

    /*{ result = y }*/
    float result = y;

    /*{ if x < y, result = x }*/
    if (x < y)
    {
        result = x;
    }

    /*{ return result }*/
    return result;
}

/*end of file*/
