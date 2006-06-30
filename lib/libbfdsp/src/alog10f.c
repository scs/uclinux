/************************************************************************
 *
 * alog10f.c : $Revision$
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
 * Description    : This file contains the implementation of alog10f()
 */

#include "math.h"

#if defined(__ADSPBLACKFIN__) || defined(__ADSP219X__)
#define LOGE_10 2.302585092994046
#else
#include "math_const.h"
#include "util.h"
#endif

/*____________________________________________________________________________

  Func name   : alog10f

  ----------------------------------------------------------------------------

  Purpose     : Base-10 anti-log
  Description : This function calculates the base-10 anti-log of its argument.

  Domain      : domain of exp / log(10.0)

  Notes       : An anti-log function performs the reverse of a log function
                and is therefore equivalent to an exponentation operation.

                Thus alog10f(x) === 10 ^ x
                                === exp(x * log(10.0))
  ____________________________________________________________________________
*/

float
alog10f(float x)
{

   return expf(x * ((float)(LOGE_10)));

}
