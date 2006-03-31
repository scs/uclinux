// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
  Func name   : min
  
  Purpose     : This function returns the lesser of 2 input values.

  Domain      : ~ x = [-MAX_INT ... MAX_INT]
                ~ y = [-MAX_INT ... MAX_INT]

*****************************************************************************/

#include <math.h>

int                        /*{ ret - min of (x, y) }*/
_min(
    int x,                 /*{ (i) - input parameter 1 }*/
    int y                  /*{ (i) - input parameter 2 }*/
)
{
    /*{ result = y }*/
    int result = y;

    /*{ if x < y, result = x }*/
    if (x < y)
    {
        result = x;
    }

    /*{ return result }*/
    return result;
}

/*end of file*/
