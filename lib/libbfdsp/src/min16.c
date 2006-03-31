// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/********************************************************************
   File Name      : min16.c

   Description    : Returning the smaller of two fractional values

********************************************************************/

#include <fract.h>
#include <math.h>

fract16 _fmin_fr16(fract16 param1,fract16 param2)
{
    fract16 result = param2;

    /*{ if param1 > param2, result = x }*/
    if (param1 < param2)
    {
        result = param1;
    }

    /*{ return result }*/
    return result;
}

/*end of file*/
