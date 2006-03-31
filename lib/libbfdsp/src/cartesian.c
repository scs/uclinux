/***************************************************************************
 *
 * cartesianf.c : $Revision$
 *
 * Copyright (c) 2003 Analog Devices Inc
// This file is subject to the terms and conditions of the GNU Library General
// Public License. See the file "COPYING.LIB" in the main directory of this
// archive for more details.

// Non-LGPL License also available as part of VisualDSP++
// http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html

 *
 ***************************************************************************/

/* This function converts a complex number 
   from cartesian to polar notation. 
 */

#include <complex.h>

float _cartesianf( complex_float a, float* phase )
{
   *phase = argf(a);      /* compute phase     */
   return( cabsf(a) );    /* compute magnitude */
}

