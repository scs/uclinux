/* mpfr_tan -- tangent of a floating-point number

Copyright 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.

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

/* computes tan(x) = sign(x)*sqrt(1/cos(x)^2-1) */
int 
mpfr_tan (mpfr_ptr y, mpfr_srcptr x, mp_rnd_t rnd_mode)
{
  int precy, m, inexact;
  mpfr_t s, c;

  if (MPFR_UNLIKELY(MPFR_IS_SINGULAR(x)))
    {
      if (MPFR_IS_NAN(x) || MPFR_IS_INF(x))
	{
	  MPFR_SET_NAN(y);
	  MPFR_RET_NAN;
	}
      else /* x is zero */
	{
          MPFR_ASSERTD(MPFR_IS_ZERO(x));
	  MPFR_SET_ZERO(y);
	  MPFR_SET_SAME_SIGN(y, x);
	  MPFR_RET(0);
	}
    }

  mpfr_save_emin_emax ();

  /* Compute initial precision */
  precy = MPFR_PREC(y);
  m = precy + __gmpfr_ceil_log2 ((double) precy)
    + ABS (MPFR_GET_EXP (x)) + 13;

  mpfr_init2 (s, m);
  mpfr_init2 (c, m);

  for (;;)
    {
      /* The only way to get an overflow is to get ~ Pi/2
         But the result will be ~ 2^Prec(y). */
      mpfr_sin_cos (s, c, x, GMP_RNDN); /* err <= 1/2 ulp on s and c */
      mpfr_div (c, s, c, GMP_RNDN);     /* err <= 2 ulps */
      MPFR_ASSERTD (!MPFR_IS_SINGULAR (c));
      if (MPFR_LIKELY (mpfr_can_round (c, m - 1, GMP_RNDN, GMP_RNDZ,
                                       precy + (rnd_mode == GMP_RNDN))))
	break;
      m += BITS_PER_MP_LIMB;
      mpfr_set_prec (s, m);
      mpfr_set_prec (c, m);
    }

  inexact = mpfr_set (y, c, rnd_mode);

  mpfr_clear (s);
  mpfr_clear (c);

  mpfr_restore_emin_emax ();
  return mpfr_check_range (y, inexact, rnd_mode);
}
