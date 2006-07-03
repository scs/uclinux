// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


#if 0
  Func name   : gen_vonhann_fr16

  Purpose     : Calculate Vonhann Window.
  Description : This function generates a vector containing the Hanning window. 
                The length is specified by parameter `N`.
#endif

#include <math.h>
#include <window.h>
#include <fract.h>

void
gen_vonhann_fr16(
    fract16 w[],      /* Window array `w` */
    int a,            /* Address stride */
    int n             /* Window length */
)
{
  gen_hanning_fr16(w,a,n);
}

/*end of file*/
