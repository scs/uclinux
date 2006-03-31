// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


#if 0
  Func name   : gen_rectangular_fr16
  Purpose     : Calculate rectangular Window.
  Description : This function generates a vector containing the rectangular 
                window.  The length is specified by parameter `N`.
#endif    

#include <window.h>
#include <fract.h>

void
gen_rectangular_fr16(
    fract16 w[],       /* Window array `w`*/
    int a,             /* Address stride */
    int n              /* Window length */
)
{
    int i, j;

    /* Check window length and stride */
    if (n > 0 && a > 0)
    {
        /* If window length is greater than zero and the stride is
           greater than zero, initialize constants and window index */
        j = 0;

        /*{ Loop for window length }*/
        for (i = 0; i < n; i++)
        {
           /*{ Calculate rectangular coefficient }*/
           w[j] = 0x7fff;
           j += a;
        }
    }
}

/* end of file */
