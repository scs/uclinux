/* tfmod -- test file for mpfr_fmod

Copyright 2007, 2008, 2009 Free Software Foundation, Inc.
Contributed by the Arenaire and Cacao projects, INRIA.

This file is part of the GNU MPFR Library.

The GNU MPFR Library is free software; you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published by
the Free Software Foundation; either version 2.1 of the License, or (at your
option) any later version.

The GNU MPFR Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
License for more details.

You should have received a copy of the GNU Lesser General Public License
along with the GNU MPFR Library; see the file COPYING.LIB.  If not, write to
the Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
MA 02110-1301, USA. */

#include <stdio.h>
#include <stdlib.h>

#include "mpfr-test.h"

#if MPFR_VERSION >= MPFR_VERSION_NUM(2,4,0)

#define TEST_FUNCTION mpfr_fmod
#define TWO_ARGS
#include "tgeneric.c"

/* compute remainder as in definition:
   r = x - n * y, where n = trunc(x/y).
   warning: may change flags. */
static int
slow_fmod (mpfr_ptr r, mpfr_srcptr x, mpfr_srcptr y, mp_rnd_t rnd)
{
  mpfr_t q;
  int inexact;
  if (MPFR_UNLIKELY (MPFR_IS_SINGULAR (x) || MPFR_IS_SINGULAR (y)))
    {
      if (MPFR_IS_NAN (x) || MPFR_IS_NAN (y) || MPFR_IS_INF (x)
          || MPFR_IS_ZERO (y))
        {
          MPFR_SET_NAN (r);
          MPFR_RET_NAN;
        }
      else                      /* either y is Inf and x is 0 or non-special,
                                   or x is 0 and y is non-special,
                                   in both cases the quotient is zero. */
        return mpfr_set (r, x, rnd);
    }
  /* regular cases */
  /* if 2^(ex-1) <= |x| < 2^ex, and 2^(ey-1) <= |y| < 2^ey,
     then |x/y| < 2^(ex-ey+1) */
  mpfr_init2 (q,
              MAX (MPFR_PREC_MIN, mpfr_get_exp (x) - mpfr_get_exp (y) + 1));
  mpfr_div (q, x, y, GMP_RNDZ);
  mpfr_trunc (q, q);                            /* may change inexact flag */
  mpfr_prec_round (q, mpfr_get_prec (q) + mpfr_get_prec (y), GMP_RNDZ);
  inexact = mpfr_mul (q, q, y, GMP_RNDZ);       /* exact */
  inexact = mpfr_sub (r, x, q, rnd);
  mpfr_clear (q);
  return inexact;
}

static void
test_failed (mpfr_t erem, mpfr_t grem, mpfr_t x, mpfr_t y, mp_rnd_t rnd)
{
  printf ("error : mpfr_fmod (r, x, y, rnd)\n  x = ");
  mpfr_out_str (stdout, 10, 0, x, GMP_RNDD);
  printf ("\n  y = ");
  mpfr_out_str (stdout, 10, 0, y, GMP_RNDD);
  printf ("\nrnd = %s\n", mpfr_print_rnd_mode (rnd));
  printf ("\n  expected r = ");
  mpfr_out_str (stdout, 10, 0, erem, GMP_RNDD);
  printf ("\n  got      r = ");
  mpfr_out_str (stdout, 10, 0, grem, GMP_RNDD);
  putchar ('\n');

  mpfr_clears (erem, grem, x, y, (mpfr_ptr) 0);
  exit (1);
}

static void
check (mpfr_t r0, mpfr_t x, mpfr_t y, mp_rnd_t rnd)
{
  int inex0, inex1;
  mpfr_t r1;
  mpfr_init2 (r1, mpfr_get_prec (r0));

  inex0 = mpfr_fmod (r0, x, y, rnd);
  inex1 = slow_fmod (r1, x, y, rnd);
  if (!mpfr_equal_p (r0, r1))
    test_failed (r1, r0, x, y, rnd);
  MPFR_ASSERTN (inex0 == inex1);
  mpfr_clear (r1);
}

static void
special (void)
{
  int inexact;
  mpfr_t x, y, r;
  mpfr_inits (x, y, r, (mpfr_ptr) 0);

  /* NaN mod NaN is NaN */
  mpfr_set_nan (x);
  mpfr_set_nan (y);
  inexact = mpfr_fmod (r, x, y, GMP_RNDN);
  if (!mpfr_nan_p (r))
    test_failed (r, x, x, y, GMP_RNDN);
  if (inexact)
    {
      printf ("error : mpfr_fmod (NaN, NaN) should be exact\n");
      goto error;
    }

  /* NaN mod +0 is NaN */
  mpfr_set_ui (y, 0, GMP_RNDN);
  inexact = mpfr_fmod (r, x, y, GMP_RNDN);
  if (!mpfr_nan_p (r))
    test_failed (r, x, x, y, GMP_RNDN);
  if (inexact)
    {
      printf ("error : mpfr_fmod (NaN, +0) should be exact\n");
      goto error;
    }

  /* 3.1415 mod +0 is NaN */
  mpfr_set_d (x, 3.1415, GMP_RNDN);
  inexact = mpfr_fmod (r, x, y, GMP_RNDN);
  if (!mpfr_nan_p (r))
    test_failed (r, x, x, y, GMP_RNDN);
  if (inexact)
    {
      printf ("error : mpfr_fmod (3.1415, NaN) should be exact\n");
      goto error;
    }

  /* 3.1415 mod +Inf is 3.1415 */
  mpfr_set_inf (y, 1);
  inexact = mpfr_fmod (r, x, y, GMP_RNDN);
  if (MPFR_IS_SINGULAR (r))
    test_failed (r, x, x, y, GMP_RNDN);
  if (inexact)
    {
      printf ("error : mpfr_fmod (3.1415, +Inf) should be exact\n");
      goto error;
    }

  mpfr_clears (x, y, r, (mpfr_ptr) 0);
  return;

 error:
  mpfr_clears (x, y, r, (mpfr_ptr) 0);
  exit (1);


}

int
main (int argc, char *argv[])
{
  mpfr_t x, y, r;

  tests_start_mpfr ();
  mpfr_inits (x, y, r, (mpfr_ptr) 0);

  test_generic (2, 100, 100);

  special ();

  /* remainder = 0 */
  mpfr_set_str (y, "FEDCBA987654321p-64", 16, GMP_RNDN);
  mpfr_pow_ui (x, y, 42, GMP_RNDN);
  check (r, x, y, GMP_RNDN);

  /* x < y */
  mpfr_mul_d (x, y, .12345, GMP_RNDN);
  check (r, x, y, GMP_RNDN);

  /* sign(x) = sign (r) */
  mpfr_set_str (x, "123798", 10, GMP_RNDN);
  mpfr_set_str (y, "10", 10, GMP_RNDN);
  check (r, x, y, GMP_RNDN);

  /* huge difference between precisions */
  mpfr_set_prec (x, 314);
  mpfr_const_pi (x, GMP_RNDD); /* x = pi */
  mpfr_set_prec (y, 8);
  mpfr_set_ui (y, 1, GMP_RNDD);
  mpfr_div_2ui (y, y, 3, GMP_RNDD); /* y = 1/8 */
  mpfr_set_prec (r, 123);
  check (r, x, y, GMP_RNDD);
  mpfr_clears (x, y, r, (mpfr_ptr) 0);

  tests_end_mpfr ();
  return 0;
}

#else

int
main (void)
{
  printf ("Warning! Test disabled for this MPFR version.\n");
  return 0;
}

#endif
