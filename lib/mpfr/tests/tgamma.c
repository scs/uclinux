/* mpfr_tgamma -- test file for gamma function

Copyright 2001, 2002, 2003, 2004 Free Software Foundation.

This file is part of the MPFR Library, and was contributed by Mathieu Dutour.

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

int mpfr_gamma (mpfr_ptr, mpfr_srcptr, mp_rnd_t);

#define TEST_FUNCTION mpfr_gamma
#include "tgeneric.c"

static void
special (void)
{
  mpfr_t x, y;
  int inex;

  mpfr_init (x);
  mpfr_init (y);
  
  mpfr_set_nan (x);
  mpfr_gamma (y, x, GMP_RNDN);
  if (!mpfr_nan_p (y))
    {
      printf ("Error for gamma(NaN)\n");
      exit (1);
    }
  
  mpfr_set_inf (x, -1);
  mpfr_gamma (y, x, GMP_RNDN);
  if (!mpfr_nan_p (y))
    {
      printf ("Error for gamma(-Inf)\n");
      exit (1);
    }
  
  mpfr_set_inf (x, 1);
  mpfr_gamma (y, x, GMP_RNDN);
  if (!mpfr_inf_p (y) || mpfr_sgn (y) < 0)
    {
      printf ("Error for gamma(+Inf)\n");
      exit (1);
    }

  mpfr_set_ui (x, 0, GMP_RNDN);
  mpfr_gamma (y, x, GMP_RNDN);
  if (!mpfr_inf_p (y) || mpfr_sgn (y) < 0)
    {
      printf ("Error for gamma(+0)\n");
      exit (1);
    }

  mpfr_set_ui (x, 0, GMP_RNDN);
  mpfr_neg (x, x, GMP_RNDN);
  mpfr_gamma (y, x, GMP_RNDN);
  if (!mpfr_inf_p (y) || mpfr_sgn (y) > 0)
    {
      printf ("Error for gamma(-0)\n");
      exit (1);
    }

  mpfr_set_ui (x, 1, GMP_RNDN);
  mpfr_gamma (y, x, GMP_RNDN);
  if (mpfr_cmp_ui (y, 1))
    {
      printf ("Error for gamma(1)\n");
      exit (1);
    }

  mpfr_set_prec (x, 53);
  mpfr_set_prec (y, 53);

#define CHECK_X1 "1.0762904832837976166"
#define CHECK_Y1 0.96134843256452096050

  mpfr_set_str (x, CHECK_X1, 10, GMP_RNDN);
  mpfr_gamma (y, x, GMP_RNDN);
  if (mpfr_get_d (y, GMP_RNDN) != CHECK_Y1 )
    {
      printf ("mpfr_gamma("CHECK_X1") is wrong: expected %1.20e, got %1.20e\n",
              CHECK_Y1, mpfr_get_d (y, GMP_RNDN));
      exit (1);
    }

#define CHECK_X2 "9.23709516716202383435e-01"
#define CHECK_Y2 1.0502315560291053398
  mpfr_set_str (x, CHECK_X2, 10, GMP_RNDN);
  mpfr_gamma (y, x, GMP_RNDN);
  if (mpfr_get_d (y, GMP_RNDN) != CHECK_Y2)
    {
      printf ("mpfr_gamma("CHECK_X2") is wrong: expected %1.20e, got %1.20e\n",
              CHECK_Y2, mpfr_get_d (y, GMP_RNDN));
      exit (1);
    }

  mpfr_set_prec (x, 8);
  mpfr_set_prec (y, 175);
  mpfr_set_ui (x, 33, GMP_RNDN);
  mpfr_gamma (y, x, GMP_RNDU);
  mpfr_set_prec (x, 175);
  mpfr_set_str_binary (x, "0.110010101011010101101000010101010111000110011101001000101011000001100010111001101001011E118");
  if (mpfr_cmp (x, y))
    {
      printf ("Error in mpfr_gamma (1)\n");
      exit (1);
    }

  mpfr_set_prec (x, 21);
  mpfr_set_prec (y, 8);
  mpfr_set_ui (y, 120, GMP_RNDN);
  mpfr_gamma (x, y, GMP_RNDZ);
  mpfr_set_prec (y, 21);
  mpfr_set_str_binary (y, "0.101111101110100110110E654");
  if (mpfr_cmp (x, y))
    {
      printf ("Error in mpfr_gamma (120)\n");
      printf ("Expected "); mpfr_print_binary (y); puts ("");
      printf ("Got      "); mpfr_print_binary (x); puts ("");
      exit (1);
    }

  mpfr_set_prec (x, 3);
  mpfr_set_prec (y, 206);
  mpfr_set_str_binary (x, "0.110e10");
  inex = mpfr_gamma (y, x, GMP_RNDN);
  mpfr_set_prec (x, 206);
  mpfr_set_str_binary (x, "0.110111100001000001101010010001000111000100000100111000010011100011011111001100011110101000111101101100110001001100110100001001111110000101010000100100011100010011101110000001000010001100010000101001111E6250");
  if (mpfr_cmp (x, y))
    {
      printf ("Error in mpfr_gamma (768)\n");
      exit (1);
    }
  if (inex <= 0)
    {
      printf ("Wrong flag for mpfr_gamma (768)\n");
      exit (1);
    }

  /* worst case to exercise retry */
  mpfr_set_prec (x, 1000);
  mpfr_set_prec (y, 869);
  mpfr_const_pi (x, GMP_RNDN);
  mpfr_gamma (y, x, GMP_RNDN);

  mpfr_clear (x);
  mpfr_clear (y);
}

static void
special_overflow (void)
{
  mpfr_t x, y;

  set_emin (-125);
  set_emax (128);

  mpfr_init2 (x, 24);
  mpfr_init2 (y, 24);
  mpfr_set_str_binary (x, "0.101100100000000000110100E7");
  mpfr_gamma (y, x, GMP_RNDN);
  if (!mpfr_inf_p (y))
    {
      printf("Overflow error.\n");
      mpfr_dump (y);
      exit (1);
    }

  mpfr_clear (y);
  mpfr_clear (x);
  set_emin (MPFR_EMIN_MIN);
  set_emax (MPFR_EMAX_MAX);
}

int
main (void)
{
  tests_start_mpfr ();

  special ();
  special_overflow ();
  test_generic (2, 100, 2);

  tests_end_mpfr ();
  return 0;
}
