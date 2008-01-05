/* Test file for mpfr_expm1.

Copyright 2001, 2002, 2003 Free Software Foundation.
Adapted from tsinh.c.

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
#include <stdlib.h>

#include "mpfr-test.h"

#define TEST_FUNCTION mpfr_expm1
#include "tgeneric.c"

static void
special (void)
{
  mpfr_t x, y;

  mpfr_init (x);
  mpfr_init (y);

  mpfr_set_nan (x);
  mpfr_expm1 (y, x, GMP_RNDN);
  if (!mpfr_nan_p (y))
    {
      printf ("Error for expm1(NaN)\n");
      exit (1);
    }

  mpfr_set_inf (x, 1);
  mpfr_expm1 (y, x, GMP_RNDN);
  if (!mpfr_inf_p (y) || mpfr_sgn (y) < 0)
    {
      printf ("Error for expm1(+Inf)\n");
      exit (1);
    }

  mpfr_set_inf (x, -1);
  mpfr_expm1 (y, x, GMP_RNDN);
  if (mpfr_cmp_si (y, -1))
    {
      printf ("Error for expm1(-Inf)\n");
      exit (1);
    }

  mpfr_set_ui (x, 0, GMP_RNDN);
  mpfr_expm1 (y, x, GMP_RNDN);
  if (mpfr_cmp_ui (y, 0) || mpfr_sgn (y) < 0)
    {
      printf ("Error for expm1(+0)\n");
      exit (1);
    }

  mpfr_neg (x, x, GMP_RNDN);
  mpfr_expm1 (y, x, GMP_RNDN);
  if (mpfr_cmp_ui (y, 0) || mpfr_sgn (y) > 0)
    {
      printf ("Error for expm1(-0)\n");
      exit (1);
    }

  mpfr_clear (x);
  mpfr_clear (y);
}

int
main (int argc, char *argv[])
{
  tests_start_mpfr ();

  special ();

  test_generic (2, 100, 100);

  tests_end_mpfr ();
  return 0;
}
