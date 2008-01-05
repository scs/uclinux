/* mpfr_sin -- sine of a floating-point number

Copyright 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

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

/* determine the sign of sin(x) using argument reduction.
   Assumes x is not an exact multiple of Pi (this excludes x=0). */
static int
mpfr_sin_sign (mpfr_srcptr x)
{
  mpfr_t c, k;
  mp_exp_t K;
  int sign;
  mp_prec_t m;
  mpfr_srcptr y;

  K = MPFR_GET_EXP(x);
  m = (K < 0) ? 0 : K;

  mpfr_init2 (c, 2);
  mpfr_init2 (k, 2);

  do
    {
      m += BITS_PER_MP_LIMB;

      mpfr_set_prec (c, m);
      mpfr_set_prec (k, m);

      /* first determine round(x/Pi): does not have to be exact since
         the result is an integer */
      mpfr_const_pi (c, GMP_RNDN); /* err <= 1/2*ulp(c) = 2^(1-m) */
      /* we need that k is not-to-badly rounded to an integer,
         i.e. ulp(k) <= 1, so m >= EXP(k). */
      mpfr_div (k, x, c, GMP_RNDN);
      mpfr_round (k, k);

      sign = 1;

      if (MPFR_NOTZERO(k)) /* subtract k*approx(Pi) */
        {
          /* determine parity of k for sign */
          if (MPFR_EXP(k)<=0 || (mpfr_uexp_t) MPFR_EXP(k) <= m)
            {
              mp_size_t j = BITS_PER_MP_LIMB * MPFR_LIMB_SIZE(k) - MPFR_EXP(k);
              mp_size_t l = j / BITS_PER_MP_LIMB;
              /* parity bit is j-th bit starting from least significant bits */
              if ((MPFR_MANT(k)[l] >> (j % BITS_PER_MP_LIMB)) & 1)
                sign = -1; /* k is odd */
            }
          K = MPFR_GET_EXP (k); /* k is an integer, thus K >= 1, k < 2^K */
          mpfr_mul (k, k, c, GMP_RNDN); /* err <= oldk*err(c) + 1/2*ulp(k)
                                               <= 2^(K+2-m) */
          mpfr_sub (k, x, k, GMP_RNDN);
          /* assuming |k| <= Pi, err <= 2^(1-m)+2^(K+2-m) < 2^(K+3-m) */
	  MPFR_ASSERTN(MPFR_EXP(k) <= 2); 
          y = k;
        }
      else
        {
          K = 1;
          y = x;
        }
      /* sign of sign(y) is uncertain if |y| <= err < 2^(K+3-m),
         thus EXP(y) < K+4-m */
    }
  while (MPFR_IS_ZERO (y) || (MPFR_GET_EXP (y) < K + 4 - (mp_exp_t) m));

  if (MPFR_IS_NEG(y))
    sign = -sign;

  mpfr_clear (k);
  mpfr_clear (c);
  
  return sign;
}

int 
mpfr_sin (mpfr_ptr y, mpfr_srcptr x, mp_rnd_t rnd_mode) 
{
  int precy, m, ok, e, inexact, sign;
  mpfr_t c;

  if (MPFR_UNLIKELY( MPFR_IS_SINGULAR(x) ))
    {
      if (MPFR_IS_NAN(x) || MPFR_IS_INF(x))
	{
	  MPFR_SET_NAN(y);
	  MPFR_RET_NAN;
	}
      else /* x is zero */
	{
          MPFR_ASSERTD(MPFR_IS_ZERO(x));
	  MPFR_CLEAR_FLAGS(y);
	  MPFR_SET_ZERO(y);
	  MPFR_SET_SAME_SIGN(y, x);
	  MPFR_RET(0);
	}
    }

  precy = MPFR_PREC(y);
  m = precy + __gmpfr_ceil_log2 ((double) precy)
    + MAX (0, MPFR_GET_EXP (x)) + 13;
  
  sign = mpfr_sin_sign (x);

  mpfr_init2 (c, m);

  do
    {
      mpfr_cos (c, x, GMP_RNDZ);
      mpfr_mul (c, c, c, GMP_RNDU);
      mpfr_ui_sub (c, 1, c, GMP_RNDN);
      e = 2 + (- MPFR_GET_EXP (c)) / 2;
      mpfr_sqrt (c, c, GMP_RNDN);
      if (MPFR_IS_NEG_SIGN(sign))
	MPFR_CHANGE_SIGN(c);

      /* the absolute error on c is at most 2^(e-m) = 2^(EXP(c)-err) */
      e = MPFR_GET_EXP (c) + m - e;
      ok = (e >= 0) && mpfr_can_round (c, e, GMP_RNDN, GMP_RNDZ,
                                       precy + (rnd_mode == GMP_RNDN));

      if (ok == 0)
	{
	  m += BITS_PER_MP_LIMB;
	  mpfr_set_prec (c, m);
	}
    }
  while (!ok);

  inexact = mpfr_set (y, c, rnd_mode);

  mpfr_clear (c);

  return inexact; /* inexact */
}
