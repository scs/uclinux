#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* flt2fr.h */
#endif
/************************************************************************
 *
 * flt2fr.h
 *
 * (c) Copyright 1998-2003 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

/* Conversion routines for C fract types and float. */

#ifndef _FLT2FR_H
#define _FLT2FR_H

/*
 * Conversion Float => Fract16
 * -------------------------------------------------------------------------
 * Step 1)
 *    Scale floating point data to floating point data ranging
 *    from -1.0 to 0.999969.
 *        xS = ( (xO - minO) / rangeO ) * rangeS + minS,
 *             where:  xO       input before scaling,
 *                     minO     minimum value of input range 
 *                     rangeO   range of input (=abs(minO)+abs(maxO))
 *                     rangeS   range of scaled output (=abs(minS)+abs(maxS))
 *                     minS     minimum value of scaled range
 *                     xS       scaled output
 *
 * Step 2)
 *    Multiply scaled values by 32768 to obtain fract value.
 *        xF = xS * 32768,
 *             where:  xF       fractional output
 *
 *
 * Conversion: Fract16 => Float
 * ---------------------------------------------------------------------------
 * Step 1)
 *    Revert fractional value to scaled floating point value
 *        xS = xF / 32768
 *
 * Step 2)
 *    Reverse original floating point scaling done 
 *        xO = ( (xS - minS) / rangeS ) * rangeO + minO
 */

#include <fract_typedef.h>

/*
 * The following constants describe the properties of a
 * scaled floating point range, equivalent to the range
 * for fract16 values between 0x8000 and 0x7fff
 * ==>> DO NOT MODIFY
 */
#define   _MIN_FRACT_RANGE    ( -1.0      )
#define   _MAX_FRACT_RANGE    (  0.999969 )
#define   _RANGE_FRACT        ( -_MIN_FRACT_RANGE + _MAX_FRACT_RANGE )

/*
 * The following data are to be supplied by the user. 
 * They describe the original data set
 * ==>> TO BE MODIFIED
 */
#define  _MIN_FLOAT_RANGE     ( -1.0     )      
#define  _MAX_FLOAT_RANGE     (  0.99996 )  
#define  _RANGE_X             ( -_MIN_FLOAT_RANGE + _MAX_FLOAT_RANGE )

/*
 * The following macros are used by the conversion functions
 * ==>> DO NOT MODIFY
 */
#define  _TERM_A    (_RANGE_FRACT / _RANGE_X)
#define  _TERM_B    ((-_MIN_FLOAT_RANGE * _TERM_A) + _MIN_FRACT_RANGE ) 
#define  _TERM_a    (_RANGE_X / _RANGE_FRACT)
#define  _TERM_b    ((-_MIN_FRACT_RANGE * _TERM_a) + _MIN_FLOAT_RANGE ) 
#define  _INV_2_POW_15    (1.0 / 32768.0)

/* Function to convert floating point data into fract16 data */
__inline fract16  float_to_fract16(float _x)
{ 
  return ( ( _x * _TERM_A + _TERM_B ) * 32768 );
}


/* Function to convert fract16 data into floating point data */
__inline float  fract16_to_float(fract16 _x16)
{ 
  return ( _x16 * _TERM_a * _INV_2_POW_15 + _TERM_b );
}

#endif  /* _FLT2FR_H */
