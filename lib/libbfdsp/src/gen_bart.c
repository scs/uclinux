// Copyright (C) 2000, 2001 Analog Devices Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html


#if 0
  Func name   : gen_bartlett_fr16

  Purpose     : Calculate Bartlett Window.
  Description : This function generates a vector containing the Bartlett window.  
                The length is specified by parameter `N`.  
                Note that this window is similar to the Triangle window 
                but has the following different properties: 

                The Bartlett window always returns a window with two zeros 
                on either end of the sequence, so that for odd `n`, the center 
                section of a `N`+2 Bartlett window equals a `N` Triangle window.

                For even n, the Bartlett window is still the convolution of 
                two rectangular sequences.  There is no standard definition for 
                the Triangle window for even `n`; the slopes of the Triangle 
                window are slightly steeper than those of the Bartlett window.
#endif

#include <window.h>
#include <fract.h>

void
gen_bartlett_fr16(
    fract16 w[],      /*{ Window array `w` }*/
    int a,            /*{ Address stride }*/
    int n             /*{ Window length }*/
)
{
    int i,j;
    float c,d,tmp;

    /*{ Check window length and stride }*/
    if( n==1 )
    {
        /*{ window length of 1 would result in 
            division by zero -> return default }*/
        w[0] = 0x0;
        return;
    }
    else if (n > 1 && a > 0)
    {
        /*{ If window length is greater than one and the stride is
            greater than zero, initialize constants and window index }*/
        c = (n - 1.0) / 2.0;
        j = 0;

        /*{ Loop for window length }*/
        for (i = 0; i < n; i++)
        {
            /*{ Calculate Bartlett coefficient }*/
            d = ((float) i - c) / c;
            if (d < (float) 0.0)
                d = -d;
            tmp  = 1.0 - d;
            w[j] = tmp * 32768;
            j += a;
        }

        /* At midpoint (=n/2) the function value will be 1, causing overflow
           => need to set to a valid maximum value
           This is only an issue with arrays of odd length */
        if( n%2==1 )
          w[(n/2)*a] = 0x7fff;
    }
}

/*end of file*/
