/* mpfr_sub_one_ulp -- subtract one unit in last place

Copyright 1999, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

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

/* sets x to x-sign(x)*ulp(x) */
int
mpfr_sub_one_ulp(mpfr_ptr x, mp_rnd_t rnd_mode)
{
  mp_size_t xn;
  int sh;
  mp_limb_t *xp;
  
  if (MPFR_UNLIKELY( MPFR_IS_SINGULAR(x) ))
    {
      if (MPFR_IS_NAN(x))
	MPFR_RET_NAN;
      MPFR_ASSERTD (MPFR_IS_INF(x) || MPFR_IS_ZERO(x));
      MPFR_RET (0);
    }

  xn = MPFR_LIMB_SIZE(x); 
  MPFR_UNSIGNED_MINUS_MODULO(sh, MPFR_PREC(x) );
  xp = MPFR_MANT(x);
  mpn_sub_1 (xp, xp, xn, MPFR_LIMB_ONE << sh);
  if (MPFR_UNLIKELY( MPFR_LIMB_MSB (xp[xn-1]) == 0))
    { /* was an exact power of two: not normalized any more */
      mp_exp_t exp = MPFR_EXP (x);
      /* Note: In case of underflow and rounding to the nearest mode,
         x won't be changed. Beware of infinite loops! */
      if (MPFR_UNLIKELY( exp == __gmpfr_emin ))
        return mpfr_set_underflow(x, rnd_mode, MPFR_SIGN(x));
      else
        {
          mp_size_t i;
          MPFR_ASSERTD (exp > __gmpfr_emin);
          MPFR_SET_EXP (x, exp - 1);
          xp[0] = (sh + 1 == BITS_PER_MP_LIMB) ? 0 : MP_LIMB_T_MAX << (sh + 1);
          for (i = 1; i < xn; i++)
            xp[i] = MP_LIMB_T_MAX;
        }
    }
  MPFR_RET (0);
}
