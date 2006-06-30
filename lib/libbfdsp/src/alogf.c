/************************************************************************
 *
 * alogf.c : $Revision$
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
 * Description    : This file contains the implementation of alogf()
 */

#include "math.h"

/*____________________________________________________________________________

  Func name   : alogf

  ----------------------------------------------------------------------------

  Purpose     : Natural anti-log
  Description : This function calculates the natural (base e) anti-log of
                its argument.

  Domain      : as for expf

  Notes       : An anti-log function performs the reverse of a log function
                and is therefore equivalent to an exponentation operation.
  ____________________________________________________________________________
*/

float
alogf(float x)
{

   return expf(x);

}
