/* mpfr_set_ld -- convert a machine long double to
                  a multiple precision floating-point number

Copyright 2002, 2003, 2004, 2005 Free Software Foundation, Inc.

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

#include <float.h>
#include "mpfr-impl.h"

/* Various i386 systems have been seen with float.h LDBL constants equal to
   the DBL ones, whereas they ought to be bigger, reflecting the 10-byte
   IEEE extended format on that processor.  gcc 3.2.1 on FreeBSD and Solaris
   has been seen with the problem, and gcc 2.95.4 on FreeBSD 4.7.  */

#if HAVE_LDOUBLE_IEEE_EXT_LITTLE
static const struct {
  char         bytes[10];
  long double  dummy;  /* for memory alignment */
} ldbl_max_struct = {
  { '\377','\377','\377','\377',
    '\377','\377','\377','\377',
    '\376','\177' }, 0.0
};
#define MPFR_LDBL_MAX   (* (const long double *) ldbl_max_struct.bytes)
#else
#define MPFR_LDBL_MAX   LDBL_MAX
#endif

int
mpfr_set_ld (mpfr_ptr r, long double d, mp_rnd_t rnd_mode)
{
  mpfr_t t, u;
  int inexact, shift_exp = 0;
  long double x;

  LONGDOUBLE_NAN_ACTION (d, goto nan);

  if (d > MPFR_LDBL_MAX)
    {
      mpfr_set_inf (r, 1);
      return 0;
    }

  if (d < -MPFR_LDBL_MAX)
    {
      mpfr_set_inf (r, -1);
      return 0;
    }

  if (d == 0.0)
    return mpfr_set_d (r, (double) d, rnd_mode);

  mpfr_init2 (t, MPFR_LDBL_MANT_DIG);
  mpfr_init2 (u, IEEE_DBL_MANT_DIG);
  mpfr_save_emin_emax ();

 convert:
  x = d;
  mpfr_set_ui (t, 0, GMP_RNDN);
  while (x != (long double) 0.0)
    {
      if ((x > (long double) DBL_MAX) || ((-x) > (long double) DBL_MAX))
        {
          long double div9, div10, div11, div12, div13;

#define TWO_64 18446744073709551616.0 /* 2^64 */
#define TWO_128 (TWO_64 * TWO_64)
#define TWO_256 (TWO_128 * TWO_128)
          div9 = (long double) (double) (TWO_256 * TWO_256); /* 2^(2^9) */
          div10 = div9 * div9;
          div11 = div10 * div10; /* 2^(2^11) */
          div12 = div11 * div11; /* 2^(2^12) */
          div13 = div12 * div12; /* 2^(2^13) */
          if (ABS(x) >= div13)
            {
              x /= div13; /* exact */
              shift_exp += 8192;
            }
          if (ABS(x) >= div12)
            {
              x /= div12; /* exact */
              shift_exp += 4096;
            }
          if (ABS(x) >= div11)
            {
              x /= div11; /* exact */
              shift_exp += 2048;
            }
          if (ABS(x) >= div10)
            {
              x /= div10; /* exact */
              shift_exp += 1024;
            }
          /* warning: we may have DBL_MAX=2^1024*(1-2^(-53)) < x < 2^1024,
             therefore we have one extra exponent reduction step */
          if (ABS(x) >= div9)
            {
              x /= div9; /* exact */
              shift_exp += 512;
            }
        }
      else
        {
          long double div9, div10, div11;
          div9 = (long double) (double) 7.4583407312002067432909653e-155;
          /* div9 = 2^(-2^9) */
          div10 = div9  * div9;  /* 2^(-2^10) */
          div11 = div10 * div10; /* 2^(-2^11) if extended precision */
          /* since -DBL_MAX <= x <= DBL_MAX, the cast to double should not
             overflow here */
	  inexact = mpfr_set_d (u, (double) x, GMP_RNDZ);
	  MPFR_ASSERTD(inexact == 0);
          if (x != (long double) 0.0 &&
              ABS(x) < div10 &&
              div11 != (long double) 0.0 &&
              div11 / div10 == div10) /* possible underflow */
            {
              long double div12, div13;
              /* After the divisions, any bit of x must be >= div10,
                 hence the possible division by div9. */
              div12 = div11 * div11; /* 2^(-2^12) */
              div13 = div12 * div12; /* 2^(-2^13) */
	      if (ABS(x) <= div13)
		{
		  x /= div13; /* exact */
		  shift_exp -= 8192;
		}
	      if (ABS(x) <= div12)
		{
		  x /= div12; /* exact */
		  shift_exp -= 4096;
		}
	      if (ABS(x) <= div11)
		{
		  x /= div11; /* exact */
		  shift_exp -= 2048;
		}
	      if (ABS(x) <= div10)
		{
		  x /= div10; /* exact */
		  shift_exp -= 1024;
		}
	      if (ABS(x) <= div9)
		{
		  x /= div9;  /* exact */
		  shift_exp -= 512;
		}
	    }
          else
            {
              if (mpfr_add (t, t, u, GMP_RNDZ) != 0)
                {
                  if (!mpfr_number_p (t))
                    break;
                  /* Inexact. This cannot happen unless the C implementation
                     "lies" on the precision or when long doubles are
                     implemented with FP expansions like under Mac OS X. */
                  if (MPFR_PREC (t) != MPFR_PREC (r) + 1)
                    {
                      /* We assume that MPFR_PREC (r) < MPFR_PREC_MAX.
                         The precision MPFR_PREC (r) + 1 allows us to
                         deduce the rounding bit and the sticky bit. */
                      mpfr_set_prec (t, MPFR_PREC (r) + 1);
                      goto convert;
                    }
                  else
                    {
                      mp_limb_t *tp;
                      int rb_mask;

                      /* Since mpfr_add was inexact, the sticky bit is 1. */
                      tp = MPFR_MANT (t);
                      rb_mask = MPFR_LIMB_ONE <<
                        (BITS_PER_MP_LIMB - 1 -
                         (MPFR_PREC (r) & (BITS_PER_MP_LIMB - 1)));
                      if (rnd_mode == GMP_RNDN)
                        rnd_mode = (*tp & rb_mask) ^ MPFR_IS_NEG (t) ?
                          GMP_RNDU : GMP_RNDD;
                      *tp |= rb_mask;
                      break;
                    }
                }
              x -= (long double) mpfr_get_d1 (u); /* exact */
            }
        }
    }
  inexact = mpfr_mul_2si (r, t, shift_exp, rnd_mode);
  mpfr_clear (t);
  mpfr_clear (u);
  mpfr_restore_emin_emax ();

  return mpfr_check_range (r, inexact, rnd_mode);


 nan:
  MPFR_SET_NAN(r);
  MPFR_RET_NAN;
}
