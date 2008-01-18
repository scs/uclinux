/* mpfr_cos -- cosine of a floating-point number

Copyright 2001, 2002, 2003, 2004 Free Software Foundation.

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

#include <stdio.h>
#include "mpfr-impl.h"

static int mpfr_cos2_aux       _MPFR_PROTO ((mpfr_ptr, mpfr_srcptr));
 
int
mpfr_cos (mpfr_ptr y, mpfr_srcptr x, mp_rnd_t rnd_mode)
{
  int K0, K, precy, m, k, l;
  int inexact;
  mpfr_t r, s;
  mp_limb_t *rp, *sp;
  mp_size_t sm;
  mp_exp_t exps, cancel = 0;
  TMP_DECL (marker);

  if (MPFR_UNLIKELY(MPFR_IS_SINGULAR(x)))
    {
      if (MPFR_IS_NAN(x) || MPFR_IS_INF(x))
	{
	  MPFR_SET_NAN(y);
	  MPFR_RET_NAN;
	}
      else
        {
          MPFR_ASSERTD(MPFR_IS_ZERO(x));
	  return mpfr_set_ui (y, 1, GMP_RNDN);
        }
    }

  mpfr_save_emin_emax ();

  precy = MPFR_PREC(y);
  K0 = __gmpfr_isqrt(precy / 2); /* Need K + log2(precy/K) extra bits */
  m = precy + 3 * (K0 + 2 * MAX(MPFR_GET_EXP (x), 0)) + 3;

  TMP_MARK(marker);
  sm = (m + BITS_PER_MP_LIMB - 1) / BITS_PER_MP_LIMB;
  MPFR_TMP_INIT(rp, r, m, sm);
  MPFR_TMP_INIT(sp, s, m, sm);

  for (;;)
    {
      mpfr_mul (r, x, x, GMP_RNDU); /* err <= 1 ulp */

      /* we need that |r| < 1 for mpfr_cos2_aux, i.e. up(x^2)/2^(2K) < 1 */
      K = K0 + MAX (MPFR_GET_EXP (r), 0);

      mpfr_div_2ui (r, r, 2 * K, GMP_RNDN); /* r = (x/2^K)^2, err <= 1 ulp */

      /* s <- 1 - r/2! + ... + (-1)^l r^l/(2l)! */
      l = mpfr_cos2_aux (s, r);

      MPFR_SET_ONE (r);
      for (k = 0; k < K; k++)
	{
	  mpfr_mul (s, s, s, GMP_RNDU);       /* err <= 2*olderr */
	  mpfr_mul_2ui (s, s, 1, GMP_RNDU);   /* err <= 4*olderr */
	  mpfr_sub (s, s, r, GMP_RNDN);
	}

      /* absolute error on s is bounded by (2l+1/3)*2^(2K-m) */
      for (k = 2 * K, l = 2 * l + 1; l > 1; l = (l + 1) >> 1)
	k++;
      /* now the error is bounded by 2^(k-m) = 2^(EXP(s)-err) */

      exps = MPFR_GET_EXP(s);
      if (MPFR_LIKELY(mpfr_can_round (s, exps + m - k, GMP_RNDN, GMP_RNDZ,
				      precy + (rnd_mode == GMP_RNDN))))
	break;

      m += BITS_PER_MP_LIMB;
      if (exps < cancel)
        {
          m += cancel - exps;
          cancel = exps;
        }
      sm = (m + BITS_PER_MP_LIMB - 1) / BITS_PER_MP_LIMB;
      MPFR_TMP_INIT(rp, r, m, sm);
      MPFR_TMP_INIT(sp, s, m, sm);
    }

  mpfr_restore_emin_emax ();
  inexact = mpfr_set (y, s, rnd_mode); /* FIXME: Dont' need check range? */

  TMP_FREE(marker);
  
  return inexact;
}

/* s <- 1 - r/2! + r^2/4! + ... + (-1)^l r^l/(2l)! + ...
   Assumes |r| < 1.
   Returns the index l0 of the last term (-1)^l r^l/(2l)!.
   The absolute error on s is at most 2 * l0 * 2^(-m).
*/
static int
mpfr_cos2_aux (mpfr_ptr s, mpfr_srcptr r)
{
  unsigned int l, b = 2;
  long int prec, m = MPFR_PREC(s);
  mpfr_t t;

  MPFR_ASSERTD (MPFR_GET_EXP (r) <= 0);

  mpfr_init2 (t, m);
  MPFR_SET_ONE (t);
  mpfr_set (s, t, GMP_RNDN);

  for (l = 1; MPFR_GET_EXP (t) + m >= 0; l++)
    {
      mpfr_mul (t, t, r, GMP_RNDU);                /* err <= (3l-1) ulp */
      mpfr_div_ui (t, t, (2*l-1)*(2*l), GMP_RNDU); /* err <= 3l ulp */
      if (l % 2 == 0)
	mpfr_add (s, s, t, GMP_RNDD);
      else
	mpfr_sub (s, s, t, GMP_RNDD);
      MPFR_ASSERTD (MPFR_GET_EXP (s) == 0);        /* check 1/2 <= s < 1 */
      /* err(s) <= l * 2^(-m) */
      if (MPFR_UNLIKELY(3 * l > (1U << b)))
	b++;
      /* now 3l <= 2^b, we want 3l*ulp(t) <= 2^(-m)
	 i.e. b+EXP(t)-PREC(t) <= -m */
      prec = m + MPFR_GET_EXP (t) + b;
      if (MPFR_LIKELY(prec >= MPFR_PREC_MIN))
	mpfr_prec_round (t, prec, GMP_RNDN);
    }
  mpfr_clear (t);

  return l;
}
