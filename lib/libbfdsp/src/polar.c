// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


/****************************************************************************
   Func Name:     polarf

   Description:   This function takes the magnitude and phase, 
                  describing a complex number result in polar
                  notation, as input argument.
                  The output argument is a complex number in 
                  cartesian notation:

                      a.real = Magnitude * cos(Phase);
                      a.imag = Magnitude * sin(Phase);

****************************************************************************/

#include "math.h"
#include <complex.h>

complex_float _polarf(float mag, float phase )
{
    
    complex_float result;

    result.re = (float)(mag * cosf(phase));
    result.im = (float)(mag * sinf(phase));

    return (result);
}

/*end of file*/
