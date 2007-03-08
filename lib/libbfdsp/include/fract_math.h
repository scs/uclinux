#pragma once
#ifndef __NO_BUILTIN
#pragma GCC system_header /* fract_math.h */
#endif
/************************************************************************
 *
 * fract_math.h
 *
 * (c) Copyright 2000-2004 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

/* Definitions of math.h-style functions for fractional types. */

#ifndef _FRACT_MATH_H
#define _FRACT_MATH_H

#include <fract_typedef.h>
#include <ccblkfn.h>
#include <fr2x16_math.h>

#if !defined(__NO_BUILTIN)
#ifdef __cplusplus
extern "C" {
#endif

/****************************************/
/*                                      */
/*   fract16 and fract2x16 arithmetic   */
/*                                      */
/****************************************/

/* Although the fract16 arithmetic looks like it takes fract16s and
   returns them, they're parallel operations, and actually take/return
   pairs, as ints. Therefore, the real intrinsics are 2x16,
   and the 1x16 functions cast params and results for the 2x16s. */

/* Adds two packed fracts.
 * Input: _x{a,b} _y{c,d}
 * Returns: {a+c,b+d} */
static __inline fract2x16 add_fr2x16(fract2x16 _x, fract2x16 _y)
  { return __builtin_bfin_add_fr2x16(_x,_y); }

/* Performs 16-bit addition of the two input parameters (_x+_y) */
static __inline fract16 add_fr1x16(fract16 _x, fract16 _y)
  { return __builtin_bfin_add_fr1x16(_x,_y); }

/* Subtracts two packed fracts.
 * Input: _x{a,b} _y{c,d}
 * Returns: {a-c,b-d} */
static __inline fract2x16 sub_fr2x16(fract2x16 _x, fract2x16 _y)
  { return __builtin_bfin_sub_fr2x16(_x,_y); }

/* Performs 16-bit subtraction of the two input parameters (_x-_y) */
static __inline fract16 sub_fr1x16(fract16 _x, fract16 _y)
  { return __builtin_bfin_sub_fr1x16(_x,_y); }

/* Multiplies two packed fracts.  Truncates the results to 16 bits.
 * Inputs: _x{a,b} _y{c,d}
 * Returns: {trunc16(a*c),trunc16(b*d)} */
static __inline fract2x16 mult_fr2x16(fract2x16 _x, fract2x16 _y)
  { return __builtin_bfin_mult_fr2x16(_x,_y); }

/* Performs 16-bit multiplication of the input parameters (_x*_y).
 * The result is truncated to 16 bits. */
static __inline fract16 mult_fr1x16(fract16 _x, fract16 _y)
  { return __builtin_bfin_mult_fr1x16(_x,_y); }

/* Multiplies two packed fracts.  Rounds the result to 16 bits.  Whether the
 * rounding is biased or unbiased depends on what the RND_MOD bit in the ASTAT
 * register is set to.
 * Input: _x{a,b} _y{c,d}
 *  Returns: {round16{a*c},round16{b*d}} */
static __inline fract2x16 multr_fr2x16(fract2x16 _x, fract2x16 _y)
  { return __builtin_bfin_multr_fr2x16(_x,_y); }

/* Performs a 16-bit fractional multiplication (_x*_y) of the two input
 * parameters. The result is rounded to 16 bits. Whether the rounding is biased
 * or unbiased depends what the RND_MOD bit in the ASTAT register is set to. */
static __inline fract16 multr_fr1x16(fract16 _x, fract16 _y)
  { return __builtin_bfin_multr_fr1x16(_x,_y); }

/* Negates both 16 bit fracts in the packed fract.  If one of the fract16
 * values is 0x8000, saturation occurs and 0x7fff is the result of the negation.
 * Input: _x{a,b}
 * Returns: {-a,-b} */
static __inline fract2x16 negate_fr2x16(fract2x16 _x)
  { return __builtin_bfin_negate_fr2x16(_x); }

/* Returns the 16-bit result of the negation of the input parameter (-_x).  If
 * the input is 0x8000, saturation occurs and 0x7fff is returned. */
static __inline fract16 negate_fr1x16(fract16 _x)
  { return __builtin_bfin_negate_fr1x16(_x); }

/* Arithmetically shifts both fract16s in the fract2x16 left by _y places,and
 * returns the packed result.  The empty bits are zero filled.  If shft is
 * negative, the shift is to the right by abs(shft) places with sign extension.
 *
 * WARNING: All the bits except for the lowest 4 bits of
 * _y are ignored.  If you want to shift by numbers larger than 4 bit signed
 * ints, you should use shl_fr2x16_clip.
 *
 * Inputs: _x{a,b} _y
 * Returns: {a<<shft,b<<shft} */
static __inline fract2x16 shl_fr2x16(fract2x16 _x, short _y)
  { return __builtin_bfin_shl_fr2x16(_x,_y); }

/* Arithmetically shifts both fract16s in the fract2x16 left by _y places,and
 * returns the packed result.  The empty bits are zero filled.  If shft is
 * negative, the shift is to the right by abs(_y) places with sign extension.
 *
 * This avoids the limitation whereby all the bits
 * except the lowest 4 bits of _y are ignored.
 *
 * Inputs: _x{a,b} _y
 * Returns: {a<<_y,b<<_y}
 */
static __inline fract2x16 shl_fr2x16_clip(fract2x16 _x, short _y)
{
  _y = _y > 15 ? 15 : _y;
  _y = _y < -16 ? -16 : _y;
  return __builtin_bfin_shl_fr2x16(_x,_y);
}

/* Arithmetically shifts the src variable left by _y places.  The empty bits
 * are zero filled. If shft is negative, the shift is to the right by abs(_y)
 * places with sign extension.
 *
 * WARNING: All the bits except for the lowest 4 bits
 * of _y are ignored.  To shift by numbers larger than 4 bit signed
 * ints, shl_fr1x16_clip should be used.
 */
static __inline fract16 shl_fr1x16(fract16 _x, short _y)
  { return __builtin_bfin_shl_fr1x16(_x,_y); }

/* Arithmetically shifts the src variable left by _y places.  The empty bits
 * are zero filled. If shft is negative, the shift is to the right by abs(shft)
 * places with sign extension.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represended in 4 bits.
 */
static __inline fract16 shl_fr1x16_clip(fract16 _x, short _y)
{
  _y = _y > 15 ? 15 : _y;
  _y = _y < -16 ? -16 : _y;
  return __builtin_bfin_shl_fr1x16(_x,_y);
}

/* Arithmetically shifts both fract16s in the fract2x16 right by shft places
 * with sign extension, and returns the packed result.  If shft is negative,
 * the shift is to the left by abs(shft) places, and the empty bits are zero
 * filled.
 *
 * WARNING: All the bits except for the lowest 4 bits of
 * _y are ignored.  If you want to shift by numbers larger than 4 bit signed
 * ints, you should use shr_fr2x16_clip.
 *
 * Inputs: _x{a,b} _y
 * Returns: {a<<shft,b<<shft}
 */
static __inline fract2x16 shr_fr2x16(fract2x16 _x, short _y)
  { return __builtin_bfin_shl_fr2x16(_x,-_y); }

/* Arithmetically shifts both fract16s in the fract2x16 right by shft places
 * with sign extension, and returns the packed result.  If shft is negative,
 * the shift is to the left by abs(_y) places, and the empty bits are zero
 * filled.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represended in 4 bits.
 */
static __inline fract2x16 shr_fr2x16_clip(fract2x16 _x, short _y)
{
  _y = _y > 16 ? 16 : _y;
  _y = _y < -15 ? -15 : _y;
  return __builtin_bfin_shl_fr2x16 (_x,-_y);
}

/* Arithmetically shifts the src variable right by shft places with sign
 * extension.  If shft is negative, the shift is to the left by abs(_y) places,
 * and the empty bits are zero filled.
 *
 * WARNING: All the bits except for the lowest 4 bits of
 * _y are ignored.  If you want to shift by numbers larger than 4 bit signed
 * ints, you should use shr_fr1x16_clip.
 */
static __inline fract16 shr_fr1x16(fract16 _x, short _y)
  { return __builtin_bfin_shl_fr1x16(_x,-_y); }

/* Arithmetically shifts the src variable right by shft places with sign
 * extension.  If shft is negative, the shift is to the left by abs(_y) places,
 * and the empty bits are zero filled.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represended in 4 bits.
 */
static __inline fract16 shr_fr1x16_clip(fract16 _x, short _y)
{
  _y = _y > 16 ? 16 : _y;
  _y = _y < -15 ? -15 : _y;
  return __builtin_bfin_shl_fr1x16(_x,-_y);
}

/* Logically shifts both fract16s in the fract2x16 right by shft places.  There
 * is no sign extension and no saturation - the empty bits are zero filled.
 *
 * WARNING: All the bits except for the lowest 4 bits of
 * _y are ignored.  If you want to shift by numbers larger than 4 bit signed
 * ints, you should use shrl_fr2x16_clip.
 */
static __inline fract2x16 shrl_fr2x16(fract2x16 _x, short _y)
	{ return __builtin_bfin_lshl_fr2x16(_x,-_y); }

/* Logically shifts both fract16s in the fract2x16 right by shft places.  There
 * is no sign extension and no saturation - the empty bits are zero filled.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represended in 4 bits.
 */
static __inline fract2x16 shrl_fr2x16_clip(fract2x16 _x, short _y)
{
  _y = _y > 16 ? 16 : _y;
  _y = _y < -15 ? -15 : _y;
  return __builtin_bfin_lshl_fr2x16 (_x,-_y);
}

/* Logically shifts a fract16 right by shft places.  There is no sign extension
 * and no saturation - the empty bits are zero filled.
 *
 * WARNING: All the bits except for the lowest 4 bits of
 * _y are ignored.  If you want to shift by numbers larger than 4 bit signed
 * ints, you should use shrl_fr1x16_clip.
 */
static __inline fract16 shrl_fr1x16(fract16 _x, short _y)
	{ return __builtin_bfin_lshl_fr1x16(_x,-_y); }

/* Logically shifts a fract16 right by _x places.  There is no sign extension
 * and no saturation - the empty bits are zero filled.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represended in 4 bits.
 */
static __inline fract16 shrl_fr1x16_clip(fract16 _x, short _y)
{
  _y = _y > 16 ? 16 : _y;
  _y = _y < -15 ? -15 : _y;
  return __builtin_bfin_lshl_fr1x16 (_x,-_y);
}



/**************************/
/*                        */
/*   fract32 arithmetic   */
/*                        */
/**************************/

/* Performs 32-bit addition of the two input parameters (_x+_y). */
static __inline fract32 add_fr1x32(fract32 _x, fract32 _y)
  { return __builtin_bfin_add_fr1x32(_x,_y); }

/* Performs 32-bit subtraction of the two input parameters (_x-_y). */
static __inline fract32 sub_fr1x32(fract32 _x, fract32 _y)
  { return __builtin_bfin_sub_fr1x32(_x,_y); }

/* Performs 32-bit multiplication of the input parameters (_x*_y).
 * The result (which is calculated internally with an accuracy of 40 bits)
 * is rounded (biased rounding) to 32 bits.  */
static __inline fract32 mult_fr1x32x32(fract32 _x, fract32 _y)
  { return __builtin_bfin_mult_fr1x32x32(_x,_y); }

/* Performs 32-bit non-saturating multiplication of the input parameters
 * (_x*_y). This is somewhat faster than mult_fr1x32x32. The result (which is
 * calculated internally with an accuracy of 40 bits) is rounded (biased
 * rounding) to 32 bits.  */
static __inline fract32 mult_fr1x32x32NS(fract32 _x, fract32 _y)
  { return __builtin_bfin_mult_fr1x32x32NS(_x,_y); }

/*   Function
 *    long fract24_8mul_asm(fract32 A, fract32 B);
 *
 *   Description   : calculates 24.8 Fractional multiplication
 *    fract32 A       : 24.8 fractional number
 *    fract32 B       : 24.8 fractional number
 *    return-value : 24.8 fractional number
*/

fract32 fract24_8mul_asm(fract32, fract32) asm("_fract24_8mul_asm");


/*   Function
 *    long fract28_4mul_asm(fract32 A, fract32 B);
 *
 *   Description   : calculates 28.4 Fractional multiplication
 *    fract32 A       : 28.4 fractional number
 *    fract32 B       : 28.4 fractional number
 *    return-value : 28.4 fractional number
*/

fract32 fract28_4mul_asm(fract32, fract32) asm("_fract28_4mul_asm");

/* Returns the 32-bit value that is the absolute value of the input parameter.
 * Where the input is 0x80000000, saturation occurs and 0x7fffffff is returned.
 */
static __inline fract32 abs_fr1x32(fract32 _x)
  { return __builtin_bfin_abs_fr1x32(_x); }

/* used by negate_fr1x32 */
static __inline fract32 __builtin_bfin_negate_fr1x32(fract32 _x) {
  return __builtin_bfin_sub_fr1x32(0, _x);
}
/* Returns the 32-bit result of the negation of the input parameter (-_x).  If
 * the input is 0x80000000, saturation occurs and 0x7fffffff is returned.  */
static __inline fract32 negate_fr1x32(fract32 _x) {
  return __builtin_bfin_sub_fr1x32(0, _x);
}

/* Returns the minimum of the two input parameters */
static __inline fract32 min_fr1x32(fract32 _x, fract32 _y)
  { return __builtin_bfin_min_fr1x32(_x,_y); }

/* Returns the maximum of the two input parameters */
static __inline fract32 max_fr1x32(fract32 _x, fract32 _y)
  { return __builtin_bfin_max_fr1x32(_x,_y); }

/* Arithmetically shifts the src variable left by shft places.  The empty bits
 * are zero filled. If shft is negative, the shift is to the right by abs(shft)
 * places with sign extension.
 *
 * WARNING: All the bits except for the lowest 6 bits of
 * _y are ignored.  If you want to shift by numbers larger than 6 bit signed
 * ints, you should use shl_fr1x32_clip.
*/
static __inline fract32 shl_fr1x32(fract32 _x, short _y)
  { return __builtin_bfin_shl_fr1x32(_x,_y); }

/* Arithmetically shifts the src variable left by shft places.  The empty bits
 * are zero filled. If shft is negative, the shift is to the right by abs(_y)
 * places with sign extension.
 *
 * This clipping variant allows shifts of numbers that are too big to be
 * represented in 6 bits.
*/
static __inline fract32 shl_fr1x32_clip(fract32 _x, short _y)
	{ return __builtin_bfin_shl_fr1x32_clip(_x,_y); }

/* Arithmetically shifts the src variable right by shft places with sign
 * extension.  If shft is negative, the shift is to the left by abs(_y) places,
 * and the empty bits are zero filled.
 *
 * WARNING: All the bits except for the lowest 6 bits of
 * _y are ignored.  If you want to shift by numbers larger than 6 bit signed
 * ints, you should use shr_fr1x32_clip.
*/
static __inline fract32 shr_fr1x32(fract32 _x, short _y)
  { return __builtin_bfin_shr_fr1x32(_x,_y); }

/* Arithmetically shifts the src variable right by shft places with sign
 * extension.  If shft is negative, the shift is to the left by abs(_y) places,
 * and the empty bits are zero filled.
 *
 * This clipping variant allows shifts of numbers that are too big to bei
 * represented in 6 bits.
*/
static __inline fract32 shr_fr1x32_clip(fract32 _x, short _y)
	{ return __builtin_bfin_shr_fr1x32_clip(_x,_y); }

/* Performs a fractional multiplication on two 16-bit fractions, returning the
 * 32-bit result. There will be loss of precision. */
static __inline fract32 mult_fr1x32(fract16 _x, fract16 _y)
  { return __builtin_bfin_mult_fr1x32(_x,_y); }

/*****************************/
/*                           */
/*   Conversion operations   */
/*                           */
/*****************************/

/* used by sat_fr1x32 */
static __inline fract16 __builtin_bfin_sat_fr1x32(fract32 _x)
  { return shl_fr1x32(_x,16)>>16;}

/* If _x>0x00007fff, returns 0x7fff. If _x<0xffff8000, returns 0x8000.
   Otherwise returns the lower 16 bits of _x. */
static __inline fract16 sat_fr1x32(fract32 _x)
  { return shl_fr1x32(_x,16)>>16;}

/* This function rounds the 32-bit fract to a 16-bit fract using biased
 * rounding.  */
static __inline fract16 round_fr1x32(fract32 _x)
  { return __builtin_bfin_round_fr1x32(_x); }

/* Returns the number of left shifts required to normalize the input variable
 * so that it is either in the interval 0x40000000 to 0x7fffffff, or in the
 * interval 0x80000000 to 0xc0000000.  In other words,
 *
 *  fract32 x;
 *  shl_fr1x32(x,norm_fr1x32(x));
 *
 * will return a value in the range 0x40000000 to 0x7fffffff, or in the range
 * 0x80000000 to 0xc0000000.
 */
static __inline int norm_fr1x32(fract32 _x)
  { return __builtin_bfin_norm_fr1x32(_x); }

/* Returns the number of left shifts required to normalize the input variable
 * so that it is either in the interval 0x4000 to 0x7fff, or in the interval
 * 0x8000 to 0xc000. In other words,
 *
 *  fract16 x;
 *  shl_fr1x16(x,norm_fr1x32(x));
 *
 * will return a value in the range 0x4000 to 0x7fff, or in the range 0x8000
 * to 0xc000.
 */
static __inline int norm_fr1x16(fract16 _x)
  { return __builtin_bfin_norm_fr1x16(_x); }

/* This function returns the top 16 bits of _x, i.e. it truncates _x to 16
 * bits.  */
static __inline fract16 trunc_fr1x32(fract32 _x)
  { return _x>>16; }

/* Returns the 16-bit value that is the absolute value of the input parameter.
 * Where the input is 0x8000, saturation occurs and 0x7fff is returned. */
static __inline fract16 abs_fr16 (fract16 _x)
  { return __builtin_bfin_abs_fr1x16 (_x); }

/* Returns the 16-bit value that is the absolute value of the input parameter.
 * Where the input is 0x8000, saturation occurs and 0x7fff is returned. */
static __inline fract16 abs_fr1x16 (fract16 _x)
  { return __builtin_bfin_abs_fr1x16(_x); }

/* Returns the maximum of the two input parameters. */
static __inline fract16 max_fr16 (fract16 _x, fract16 _y)
  { return __builtin_bfin_max_fr1x16 (_x, _y); }

/* Returns the maximum of the two input parameters. */
static __inline fract16 min_fr16 (fract16 _x, fract16 _y)
  { return __builtin_bfin_min_fr1x16 (_x, _y); }

/*********************/
/*                   */
/*   ETSI Builtins   */
/*                   */
/*********************/

#ifdef ETSI_SOURCE /* { */
#ifndef NO_ETSI_BUILTINS /* { */
static __inline fract16 add(fract16 _x, fract16 _y) { return (fract16)add_fr1x16(_x, _y); }
static __inline fract16 sub(fract16 _x, fract16 _y) { return (fract16)sub_fr1x16(_x, _y); }
static __inline fract16 abs_s(fract16 _x) { return (fract16)abs_fr1x16(_x); }
#if defined(_ADI_FAST_ETSI)
/* These are fast, but see the shift fr1x16 documentation for their limitations */
static __inline fract16 shl(fract16 _x, short _y) { return (fract16)shl_fr1x16(_x, _y); }
static __inline fract16 shr(fract16 _x, short _y) { return (fract16)shr_fr1x16(_x, _y); }
#else /* _ADI_FAST_ETSI */
/* These are conformant, but not so fast */
static __inline fract16 shl(fract16 _x, short _y) { return (fract16)shl_fr1x16_clip(_x, _y); }
static __inline fract16 shr(fract16 _x, short _y) { return (fract16)shr_fr1x16_clip(_x, _y); }
#endif /* _ADI_FAST_ETSi */
static __inline fract16 mult(fract16 _x, fract16 _y) { return mult_fr1x16(_x, _y); }
static __inline fract16 mult_r(fract16 _x, fract16 _y) { return multr_fr1x16(_x, _y); }
#ifndef RENAME_ETSI_NEGATE
static __inline fract16 negate(fract16 _x) { return (fract16)negate_fr1x16(_x); }
#else
/* The ETSI negate function conflicts with the C++ standard declaration of
   the template negate.
 */
static __inline fract16 etsi_negate(fract16 _x) { return (fract16)negate_fr1x16(_x); }
#endif
#if 0 /* @@@ Name clash with standard C library.  */
static __inline fract16 round(fract32 _x) { return (fract16)round_fr1x32(_x); }
#endif
static __inline fract32 L_add(fract32 _x, fract32 _y) { return add_fr1x32(_x, _y); }
static __inline fract32 L_sub(fract32 _x, fract32 _y) { return sub_fr1x32(_x, _y); }
static __inline fract32 L_abs(fract32 _x) { return abs_fr1x32(_x); }
static __inline fract32 L_negate(fract32 _x) { return negate_fr1x32(_x); }
#if defined(_ADI_FAST_ETSI)
/* These are fast, but see the shift fr1x32 documentation for their limitations */
static __inline fract32 L_shl(fract32 _x, short _y) { return shl_fr1x32(_x, _y); }
static __inline fract32 L_shr(fract32 _x, short _y) { return shr_fr1x32(_x, _y); }
#else /* _ADI_FAST_ETSI */
/* These are conformant, but not so fast */
static __inline fract32 L_shl(fract32 _x, short _y) { return shl_fr1x32_clip(_x, _y); }
static __inline fract32 L_shr(fract32 _x, short _y) { return shr_fr1x32_clip(_x, _y); }
#endif /* _ADI_FAST_ETSI */
static __inline fract32 L_mult(fract16 _x, fract16 _y) { return mult_fr1x32(_x, _y); }
static __inline fract16 saturate(fract32 _x) { return sat_fr1x32(_x); }
static __inline fract32 L_mac(fract32 _a,fract16 _x, fract16 _y) { return (L_add(_a,L_mult(_x, _y))); }
static __inline fract32 L_msu(fract32 _a,fract16 _x, fract16 _y) { return (L_sub(_a,L_mult(_x, _y))); }
static __inline fract16 extract_h(fract32 _x) { return (fract16)(_x>>16); }
static __inline fract16 extract_l(fract32 _x) { return (fract16)(_x); }
static __inline fract32 L_deposit_h(fract16 _x) { return ((int)(_x))<<16; }
static __inline fract32 L_deposit_l(fract16 _x) { return ((int)((fract16)(_x))); }
static __inline fract32 L_Comp(fract16 _x, fract16 _y) { return L_add(L_deposit_h(_x), L_shl(_y,1))  ; }

static __inline int norm_l(fract32 _x) {
  return _x==0 ? 0 : norm_fr1x32(_x);
}

static __inline int norm_s(fract32 _x) {
  return _x==0 ? 0 : norm_fr1x16(_x);
}

/* Multiplies a fract32 (decomposed to hi and lo) by a fract16, and returns the
 * result as a fract32. */
static __inline fract32 Mpy_32_16(short _a, short _b, short _c) {
  return L_mac(L_mult(_a,_c), mult(_b,_c),1);
}

/* Decomposes a 32-bit fract into two 16-bit fracts. */
static __inline void L_Extract(fract32 _a, fract16 *_b, fract16 *_c) {
  *_b=extract_h(_a);
  *_c=L_msu(L_shr(_a,1), *_b, 16384);
}

/* Multiplies two fract32 numbers, and returns the result as a fract32.  The
 * input fracts have both been split up into two shorts. */
static __inline fract32 Mpy_32(short _a, short _b, short _c, short _d) {
  int x = L_mult(_a, _c);
  x = L_mac(x, mult(_a, _d), 1);
  return L_mac(x, mult(_b, _c), 1);
}

/* Produces a result which is the fractional division of f1 by f2. Not a builtin
 * as written in C code. */
static __inline fract16 div_s(fract16 _a, fract16 _b) {
  int x = (int)_a;
  int y = (int)_b;
  int i;
  if (x==0) return 0;
  if (x>=y) return 0x7fff;
  x <<= 16;
  x = __builtin_bfin_divs(x, y);
  for (i=0; i<15; i++) {
    x = __builtin_bfin_divq(x, y);
  }
  return x;
}

#endif /*  } NO_ETSI_BUILTINS */
#include <libetsi.h>
#endif /* } ETSI_SOURCE */

#undef __OP1RT
#undef __BOP1RT
#undef __OP2RT
#undef __BOP2RT
#undef __OP1
#undef __BOP1
#undef __OP2
#undef __BOP2

#ifdef __cplusplus
}
#endif

#else

  fract16 max_fr16 (fract16 _x, fract16 _y) asm("__fmax_fr16");
 fract16 min_fr16 (fract16 _x, fract16 _y) asm("__fmin_fr16");
 fract16 abs_fr16 (fract16 _x) asm("__abs_fr16");
#include <math_bf.h>

#endif /* __ADSPBLACKFIN__  && !__NO_BUILTIN */

#endif /* _FRACT_MATH_H */
