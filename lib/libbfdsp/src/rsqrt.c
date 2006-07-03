/************************************************************************
 *
 * rsqrtd.c : $Revision$
 *
 * (c) Copyright 2003 Analog Devices, Inc.
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ************************************************************************/

/*
 * Description :  Reciprocal Square Root
 */

#include <math.h>
#include <float.h>

/*____________________________________________________________________________

  Func name   : rsqrtf

  ----------------------------------------------------------------------------

  Purpose     : This function computes the reciprocal of sqrtf(x) using 32-bit
                float precision.

  Description : The function computes 1.0 / sqrtf(x)

  Domain      : x = [0.0 ... FLT_MAX]

  Notes       : For x outside the domain, this function returns 0.0; when x
                is 0.0 the function returns 0.0
  ____________________________________________________________________________
*/

float
rsqrtf(float x)
{
   if (x <=  0.0)
      return 0.0;
   else
      return (1.0 / sqrtf(x));

}
