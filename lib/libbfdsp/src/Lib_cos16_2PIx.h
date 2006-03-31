/*************************************************************************
 *
 * Lib_cos16_2PIx.h : $Revision$
 *
 * (c) Copyright 2000-2002 Analog Devices, Inc.
 *
 ************************************************************************/

/*
   Fract16 Cosine function that works across the range 0 to 2pi

   Input:  0.0 .. 1.0
   Output  0x8000 .. 0x7fff

   The function has been designed specifically for the case:

   float   pi = 3.14...;
   fract16 x16;
   ..
   for( i=0; i<n; i++)
     x16 = ( cosf(2*pi*(i/n)) ) * 32768;
   ...

   The expression can now be rewriten as:
     x16 = __cos16_2PIx( i/n ); 
*/

#ifndef Lib_cos16_2PIx
#define Lib_cos16_2PIx

#include <fract_typedef.h>

fract16 __cos16_2PIx(float x);

#endif
