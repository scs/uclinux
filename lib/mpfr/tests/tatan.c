/* Test file for mpfr_atan.

Copyright 2001, 2002, 2003, 2004, 2005 Free Software Foundation.
Written by Paul Zimmermann, INRIA Lorraine.

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

static void
special (void)
{
  mpfr_t x, y, z;
  int r;

  mpfr_init2 (x, 53);
  mpfr_init2 (y, 53);
  mpfr_init2 (z, 53);

  mpfr_set_str_binary (x, "1.0000100110000001100111100011001110101110100111011101");
  mpfr_set_str_binary (y, "1.1001101101110100101100110011011101101000011010111110e-1");
  mpfr_atan (z, x, GMP_RNDN);
  if (mpfr_cmp (y, z))
    {
      printf ("Error in mpfr_atan for prec=53, rnd=GMP_RNDN\n");
      printf ("x=");
      mpfr_out_str (stdout, 2, 0, x, GMP_RNDN);
      printf ("\nexpected ");
      mpfr_out_str (stdout, 2, 0, y, GMP_RNDN);
      printf ("\ngot      ");
      mpfr_out_str (stdout, 2, 0, z, GMP_RNDN);
      printf ("\n");
      exit (1);
    }

  /* atan(+Inf) = Pi/2 */
  for (r = 0; r < GMP_RND_MAX ; r++)
    {
      mpfr_set_inf (x, 1);
      mpfr_atan (y, x, (mp_rnd_t) r);
      mpfr_const_pi (x, (mp_rnd_t) r);
      mpfr_div_2exp (x, x, 1, (mp_rnd_t) r);
      if (mpfr_cmp (x, y))
        {
          printf ("Error: mpfr_atan(+Inf), rnd=%s\n",
                  mpfr_print_rnd_mode ((mp_rnd_t) r));
          exit (1);
        }
    }

  /* atan(-Inf) = - Pi/2 */
  for (r = 0; r < GMP_RND_MAX ; r++)
    {
      mpfr_set_inf (x, -1);
      mpfr_atan (y, x, (mp_rnd_t) r);
      mpfr_const_pi (x, MPFR_INVERT_RND((mp_rnd_t) r));
      mpfr_neg (x, x, (mp_rnd_t) r);
      mpfr_div_2exp (x, x, 1, (mp_rnd_t) r);
      if (mpfr_cmp (x, y))
        {
          printf ("Error: mpfr_atan(-Inf), rnd=%s\n",
                  mpfr_print_rnd_mode ((mp_rnd_t) r));
          exit (1);
        }
    }

  /* atan(NaN) = NaN */
  mpfr_set_nan (x);
  mpfr_atan (y, x, GMP_RNDN);
  if (!mpfr_nan_p (y))
    {
      printf ("Error: mpfr_atan(NaN) <> NaN\n");
      exit (1);
    }

  /* atan(+/-0) = +/-0 */
  mpfr_set_ui (x, 0, GMP_RNDN);
  MPFR_SET_NEG (y);
  mpfr_atan (y, x, GMP_RNDN);
  if (mpfr_cmp_ui (y, 0) || MPFR_IS_NEG (y))
    {
      printf ("Error: mpfr_atan (+0) <> +0\n");
      exit (1);
    }
  mpfr_atan (x, x, GMP_RNDN);
  if (mpfr_cmp_ui (x, 0) || MPFR_IS_NEG (x))
    {
      printf ("Error: mpfr_atan (+0) <> +0 (in place)\n");
      exit (1);
    }
  mpfr_neg (x, x, GMP_RNDN);
  MPFR_SET_POS (y);
  mpfr_atan (y, x, GMP_RNDN);
  if (mpfr_cmp_ui (y, 0) || MPFR_IS_POS (y))
    {
      printf ("Error: mpfr_atan (-0) <> -0\n");
      exit (1);
    }
  mpfr_atan (x, x, GMP_RNDN);
  if (mpfr_cmp_ui (x, 0) || MPFR_IS_POS (x))
    {
      printf ("Error: mpfr_atan (-0) <> -0 (in place)\n");
      exit (1);
    }

  mpfr_set_prec (x, 32);
  mpfr_set_prec (y, 32);

  /* test one random positive argument */
  mpfr_set_str_binary (x, "0.10000100001100101001001001011001");
  mpfr_atan (x, x, GMP_RNDN);
  mpfr_set_str_binary (y, "0.1111010000001111001111000000011E-1");
  if (mpfr_cmp (x, y))
    {
      printf ("Error in mpfr_atan (1)\n");
      exit (1);
    }

  /* test one random negative argument */
  mpfr_set_str_binary (x, "-0.1100001110110000010101011001011");
  mpfr_atan (x, x, GMP_RNDN);
  mpfr_set_str_binary (y, "-0.101001110001010010110001110001");
  if (mpfr_cmp (x, y))
    {
      printf ("Error in mpfr_atan (2)\n");
      mpfr_print_binary (x); printf ("\n");
      mpfr_print_binary (y); printf ("\n");
      exit (1);
    }

  mpfr_set_prec (x, 3);
  mpfr_set_prec (y, 192);
  mpfr_set_prec (z, 192);
  mpfr_set_str_binary (x, "-0.100e1");
  mpfr_atan (z, x, GMP_RNDD);
  mpfr_set_str_binary (y, "-0.110010010000111111011010101000100010000101101000110000100011010011000100110001100110001010001011100000001101110000011100110100010010100100000010010011100000100010001010011001111100110001110101");
  if (mpfr_cmp (z, y))
    {
      printf ("Error in mpfr_atan (3)\n");
      printf ("Expected "); mpfr_print_binary (y); printf ("\n");
      printf ("Got      "); mpfr_print_binary (z); printf ("\n");
      exit (1);
    }

  mpfr_clear (x);
  mpfr_clear (y);
  mpfr_clear (z);
}

#define TEST_FUNCTION mpfr_atan
#include "tgeneric.c"

static void
special_overflow (void)
{
  mpfr_t x, y;

  set_emin (-125);
  set_emax (128);
  mpfr_init2 (x, 24);
  mpfr_init2 (y, 48);
  mpfr_set_str_binary (x, "0.101101010001001101111010E0");
  mpfr_atan (y, x, GMP_RNDN);
  if (mpfr_cmp_str (y, "0.100111011001100111000010111101000111010101011110E0",
                    2, GMP_RNDN))
    {
      printf("Special Overflow error.\n");
      mpfr_dump (y);
      exit (1);
    }
  mpfr_clear (y);
  mpfr_clear (x);
  set_emin (MPFR_EMIN_MIN);
  set_emax (MPFR_EMAX_MAX);
}

int
main (int argc, char *argv[])
{
  tests_start_mpfr ();

  special_overflow ();
  special ();

  test_generic (2, 100, 7);

  tests_end_mpfr ();
  return 0;
}
