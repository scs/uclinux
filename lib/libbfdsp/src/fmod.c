// Copyright (C) 2000 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html



/*______________________________________________________________________

  Func name   : fmodf

  ----------------------------------------------------------------------

  Purpose     : This function returns the 32-bit float remainder of x/y.
  Description : 

  Domain      : ~ x = Full Range
                ~ y = Full Range

  Accuracy    : ~ Relative error: 0 bits in error
                ~ Assumption: there is no error in the input value

  Data Memory : ~   0
  Prog Memory : ~  72
  Cycles      : ~ 118 - max
                ~  21 - min
  _____________________________________________________________________
*/
#include <float.h>
#include <math.h>
#include "util.h"
#include <math_const.h>


FLOAT                      /*{ ret - fmod(x)}*/
_fmodf(
    FLOAT x,               /*{ (i) - numerator }*/
    FLOAT y                /*{ (i) - denominator }*/
)
{
    FLOAT x_abs, y_abs, y_1, y_2;
    FLOAT val, val_int;
    FLOAT remainder;
    LONG *lyPtr = (LONG *)&y_1;

    /*{ if y == 0 and x/y = +-INF for |x| > 0, return 0.0 }*/
    /*{ if y == 0 and x/y = undefined for x = 0, return 0.0 }*/
    if (y == (FLOAT)0.0)
    {
        return (FLOAT)0.0;
    }

    /*{ x_abs = |x| }*/
    /*{ y_abs = |y| }*/
    x_abs = x;
    if (x < (FLOAT)0.0)
    {
        x_abs = -x_abs;
    }
    y_abs = y;
    if (y < (FLOAT)0.0)
    {
        y_abs = -y_abs;
    }
    if (x_abs < y_abs)
    {
        return x;
    }
    
    /*{ val_int = integer part of x_abs/y_abs }*/
    val = DIV(x_abs, y_abs);
    modff(val, &val_int);

    /* 
     * val_int = integer part of (x_abs / y_abs) 
     * the floating point remainder is simply sign(x)*(x_abs - val_int * y_abs)
     */

    /*{ y_1 = upper bits of y }*/
    y_1 = y_abs;
    *lyPtr = *lyPtr & 0xfffff000;
    /*{ y_2 = y - y_1 }*/
    y_2 = y_abs - y_1;


    /*{ remainder = x_abs - val_int * y_abs (using higher precision )}*/
    /*{!INDENT}*/
    /*{ remainder = x_abs - (val_int * y_1) }*/
    /*{ remainder = remainder - (val_int * y_2) }*/
    remainder = SUB(x_abs, MPY(val_int, y_1));
    remainder = SUB(remainder, MPY(val_int, y_2));
    /*{!OUTDENT}*/

    /* { if remainder < 0.0, then a rounding error has occurred }*/
    if (remainder < (FLOAT)0.0)
    {
        /* rounding error occurred */

        /*{ val_int-- }*/
        val_int = SUB(val_int, 1.0);
        /*{ re-compute remainder }*/
        remainder = SUB(x_abs, MPY(val_int, y_1));
        remainder = SUB(remainder, MPY(val_int, y_2));
    }


    /*{ if x < 0, remainder = -remainder }*/
    if (x < (FLOAT)0.0)
    {
        remainder = -remainder;
    }

    /*{ return remainder }*/
    return remainder;
}

/*end of file*/
