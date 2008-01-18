/* mpfr_set -- copy of a floating-point number

Copyright 1999, 2001, 2002, 2003, 2004, 2005 Free Software Foundation.

This file is part of the MPFR Library.

The MPFR Library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or (at your
option) any later version.

The MPFR Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the MPFR Library; see the file COPYING.LIB.  If not, write to
the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston,
MA 02111-1307, USA. */

#include "mpfr-impl.h"

/* Note: In case of even rounding when rnd = GMP_RNDN, MPFR_EVEN_INEX (2)
   or -MPFR_EVEN_INEX (-2) is returned. This is used internally. This is
   no longer valid in the CVS trunk. */

/* set a to abs(b) * signb: a=b when signb = SIGN(b), a=abs(b) when signb=1 */
int
mpfr_set4 (mpfr_ptr a, mpfr_srcptr b, mp_rnd_t rnd_mode, int signb)
{
  int inex;
  
  if (MPFR_UNLIKELY( MPFR_IS_SINGULAR(b) ))
    {
      if (MPFR_IS_NAN(b))
	{
	  MPFR_SET_NAN(a);
	  MPFR_RET_NAN;
	}
      else if (MPFR_IS_INF(b))
	{
	  MPFR_CLEAR_FLAGS(a);
	  MPFR_SET_INF(a);
	  inex = 0;
	}
      else
	{
	  MPFR_ASSERTD(MPFR_IS_ZERO(b));
          MPFR_SET_ZERO(a);
          inex = 0;
        }
    }
  else if (MPFR_LIKELY(MPFR_PREC(b) == MPFR_PREC(a)))
    {
      /* Same precision and b is not special: 
       * just copy the mantissa, and set the exponent and the sign */
      MPFR_CLEAR_FLAGS(a);
      MPN_COPY(MPFR_MANT(a), MPFR_MANT(b), MPFR_LIMB_SIZE(b));
      MPFR_SET_SIGN(a, signb);
      MPFR_SET_EXP(a, MPFR_GET_EXP(b));
      MPFR_RET(0);
    }
  else
    {
      mp_limb_t *ap;
      mp_prec_t aq;
      int carry;
      
      MPFR_CLEAR_FLAGS(a);

      ap = MPFR_MANT(a);
      aq = MPFR_PREC(a);
      
      carry = mpfr_round_raw(ap, MPFR_MANT(b), MPFR_PREC(b),
			     MPFR_IS_NEG_SIGN(signb),
			     aq, rnd_mode, &inex);
      /* carry is unlikely since it has probability < 2^(-aq) */
      if (MPFR_UNLIKELY(carry))
	{
	  mp_exp_t exp = MPFR_GET_EXP (b);
	  
	  if (MPFR_UNLIKELY(exp == __gmpfr_emax))
	    return mpfr_set_overflow(a, rnd_mode, signb);
	  
	  MPFR_SET_EXP(a, exp + 1);
	  ap[(MPFR_PREC(a)-1)/BITS_PER_MP_LIMB] = MPFR_LIMB_HIGHBIT;
	}
      else
	MPFR_SET_EXP (a, MPFR_GET_EXP (b));
    }

  MPFR_SET_SIGN(a, signb);
  MPFR_RET(inex);
}

/* Set a to b (Define function which calls the macro) */
int
(mpfr_set) (mpfr_ptr a, mpfr_srcptr b, mp_rnd_t rnd_mode)
{
  return mpfr_set (a, b, rnd_mode);
}

/* Set a to |b| (Define function which calls the macro) */
int
(mpfr_abs) (mpfr_ptr a, mpfr_srcptr b, mp_rnd_t rnd_mode)
{
  return mpfr_abs (a, b, rnd_mode);
}
