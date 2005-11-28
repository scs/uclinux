/* Test file for mpfr_set_si and mpfr_set_ui.

Copyright 1999, 2001, 2002, 2003, 2004, 2005 Free Software Foundation, Inc.

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
#include <time.h>
#include <limits.h>

#include "mpfr-test.h"

#define ERROR(str) {printf("Error for "str); exit(1);}

static void
test_2exp (void)
{
  mpfr_t x;

  mpfr_init2 (x, 32);
  
  mpfr_set_ui_2exp (x, 1, 0, GMP_RNDN);
  if (mpfr_cmp_ui(x, 1))
    ERROR("(1U,0)");

  mpfr_set_ui_2exp (x, 1024, -10, GMP_RNDN);
  if (mpfr_cmp_ui(x, 1))
    ERROR("(1024U,-10)");

  mpfr_set_ui_2exp (x, 1024, 10, GMP_RNDN);
  if (mpfr_cmp_ui(x, 1024*1024))
    ERROR("(1024U,+10)");

  mpfr_set_si_2exp (x, -1024*1024, -10, GMP_RNDN);
  if (mpfr_cmp_si(x, -1024))
    ERROR("(1M,-10)");

  mpfr_set_ui_2exp (x, 0x92345678, 16, GMP_RNDN);
  if (mpfr_cmp_str (x, "92345678@4", 16, GMP_RNDN))
    ERROR("(x92345678U,+16)");

  mpfr_set_si_2exp (x, -0x1ABCDEF0, -256, GMP_RNDN);
  if (mpfr_cmp_str (x, "-1ABCDEF0@-64", 16, GMP_RNDN))
    ERROR("(-x1ABCDEF0,-256)");

  mpfr_clear (x);
}

/* FIXME: Comparing against mpfr_get_si/ui is not ideal, it'd be better to
   have all tests examine the bits in mpfr_t for what should come out.  */

int
main (int argc, char *argv[])
{
  mpfr_t x;
  long k, z, d, N;
  unsigned long zl, dl;
  int inex;
  int r;
  mp_exp_t emax;

  tests_start_mpfr ();

  mpfr_init2 (x, 100);

  N = (argc==1) ? 100000 : atol (argv[1]);

  for (k = 1; k <= N; k++)
    {
      z = (long) (randlimb () & LONG_MAX) + LONG_MIN / 2;
      inex = mpfr_set_si (x, z, GMP_RNDZ);
      d = mpfr_get_si (x, GMP_RNDZ);
      if (d != z)
        {
          printf ("Error in mpfr_set_si: expected %ld got %ld\n", z, d);
          exit (1);
        }
      if (inex)
        {
          printf ("Error in mpfr_set_si: inex value incorrect for %ld: %d\n",
                  z, inex);
          exit (1);
        }
    }

  for (k = 1; k <= N; k++)
    {
      zl = randlimb ();
      inex = mpfr_set_ui (x, zl, GMP_RNDZ);
      dl = mpfr_get_ui (x, GMP_RNDZ);
      if (dl != zl)
        {
          printf ("Error in mpfr_set_ui: expected %lu got %lu\n", zl, dl);
          exit (1);
        }
      if (inex)
        {
          printf ("Error in mpfr_set_ui: inex value incorrect for %lu: %d\n",
                  zl, inex);
          exit (1);
        }
    }

  mpfr_set_prec (x, 2);
  if (mpfr_set_si (x, 5, GMP_RNDZ) >= 0)
    {
      printf ("Wrong inexact flag for x=5, rnd=GMP_RNDZ\n");
      exit (1);
    }

  mpfr_set_prec (x, 2);
  if (mpfr_set_si (x, -5, GMP_RNDZ) <= 0)
    {
      printf ("Wrong inexact flag for x=-5, rnd=GMP_RNDZ\n");
      exit (1);
    }

  mpfr_set_prec (x, 3);
  inex = mpfr_set_si (x, 77617, GMP_RNDD); /* should be 65536 */
  if (MPFR_MANT(x)[0] != ((mp_limb_t)1 << (mp_bits_per_limb-1))
      || inex >= 0)
    {
      printf ("Error in mpfr_set_si(x:3, 77617, GMP_RNDD)\n");
      mpfr_print_binary (x);
      puts ("");
      exit (1);
    }
  inex = mpfr_set_ui (x, 77617, GMP_RNDD); /* should be 65536 */
  if (MPFR_MANT(x)[0] != ((mp_limb_t)1 << (mp_bits_per_limb-1))
      || inex >= 0)
    {
      printf ("Error in mpfr_set_ui(x:3, 77617, GMP_RNDD)\n");
      mpfr_print_binary (x);
      puts ("");
      exit (1);
    }

  mpfr_set_prec (x, 2);
  inex = mpfr_set_si (x, 33096, GMP_RNDU);
  if (mpfr_get_si (x, GMP_RNDZ) != 49152 || inex <= 0)
    {
      printf ("Error in mpfr_set_si, exp. 49152, got %ld, inex %d\n",
              mpfr_get_si (x, GMP_RNDZ), inex);
      exit (1);
    }
  inex = mpfr_set_ui (x, 33096, GMP_RNDU);
  if (mpfr_get_si (x, GMP_RNDZ) != 49152)
    {
      printf ("Error in mpfr_set_ui, exp. 49152, got %ld, inex %d\n",
              mpfr_get_si (x, GMP_RNDZ), inex);
      exit (1);
    }

  for (r = 0 ; r < GMP_RND_MAX ; r++)
    {
      mpfr_set_si (x, -1, (mp_rnd_t) r);
      mpfr_set_ui (x, 0, (mp_rnd_t) r);
      if (MPFR_IS_NEG (x) )
	{
	  printf ("mpfr_set_ui (x, 0) gives -0 for %s\n", 
		  mpfr_print_rnd_mode ((mp_rnd_t) r));
	  exit (1);
	}

      mpfr_set_si (x, -1, (mp_rnd_t) r);
      mpfr_set_si (x, 0, (mp_rnd_t) r);
      if (MPFR_IS_NEG (x))
	{
	  printf ("mpfr_set_si (x, 0) gives -0 for %s\n",
		  mpfr_print_rnd_mode ((mp_rnd_t) r));
	  exit (1);
	}
    }
  
  /* check potential bug in case mp_limb_t is unsigned */
  emax = mpfr_get_emax ();
  set_emax (0);
  mpfr_set_si (x, -1, GMP_RNDN);
  if (mpfr_sgn (x) >= 0)
    {
      printf ("mpfr_set_si (x, -1) fails\n");
      exit (1);
    }
  set_emax (emax);

  emax = mpfr_get_emax ();
  set_emax (5);
  mpfr_set_prec (x, 2);
  mpfr_set_si (x, -31, GMP_RNDN);
  if (mpfr_sgn (x) >= 0)
    {
      printf ("mpfr_set_si (x, -31) fails\n");
      exit (1);
    }
  set_emax (emax);

  /* test for get_ui */
  mpfr_set_ui (x, 0, GMP_RNDN);
  MPFR_ASSERTN(mpfr_get_ui (x, GMP_RNDN) == 0);
  mpfr_set_ui (x, ULONG_MAX, GMP_RNDU);
  mpfr_nextabove (x);
  mpfr_get_ui (x, GMP_RNDU);

  /* another test for get_ui */
  mpfr_set_prec (x, 10);
  mpfr_set_str_binary (x, "10.101");
  dl = mpfr_get_ui (x, GMP_RNDN);
  MPFR_ASSERTN (dl == 3);

  mpfr_set_str_binary (x, "-1.0");
  mpfr_get_ui (x, GMP_RNDN);

  mpfr_set_str_binary (x, "0.1");
  dl = mpfr_get_ui (x, GMP_RNDN);
  MPFR_ASSERTN (dl == 0);
  dl = mpfr_get_ui (x, GMP_RNDZ);
  MPFR_ASSERTN (dl == 0);
  dl = mpfr_get_ui (x, GMP_RNDD);
  MPFR_ASSERTN (dl == 0);
  dl = mpfr_get_ui (x, GMP_RNDU);
  MPFR_ASSERTN (dl == 1);

  /* coverage tests */
  mpfr_set_prec (x, 2);
  mpfr_set_si (x, -7, GMP_RNDD);
  MPFR_ASSERTN(mpfr_cmp_si (x, -8) == 0);
  mpfr_set_prec (x, 2);
  mpfr_set_ui (x, 7, GMP_RNDU);
  MPFR_ASSERTN(mpfr_cmp_ui (x, 8) == 0);
  emax = mpfr_get_emax ();
  set_emax (3);
  mpfr_set_ui (x, 7, GMP_RNDU);
  MPFR_ASSERTN(mpfr_inf_p (x) && mpfr_sgn (x) > 0);
  set_emax (1);
  MPFR_ASSERTN( mpfr_set_ui (x, 7, GMP_RNDU) );
  MPFR_ASSERTN(mpfr_inf_p (x) && mpfr_sgn (x) > 0);
  set_emax (emax);

  /* Test for ERANGE flag + correct behaviour if overflow */
  mpfr_set_prec (x, 256); 
  mpfr_set_ui (x, ULONG_MAX, GMP_RNDN);
  mpfr_clear_erangeflag ();
  dl = mpfr_get_ui (x, GMP_RNDN);
  if (dl != ULONG_MAX || mpfr_erangeflag_p ())
    {
      printf ("ERROR for get_ui + ERANGE + ULONG_MAX (1)\n");
      exit (1);
    }
  mpfr_add_ui (x, x, 1, GMP_RNDN);
  dl = mpfr_get_ui (x, GMP_RNDN);
  if (dl != ULONG_MAX || !mpfr_erangeflag_p ())
    {
      printf ("ERROR for get_ui + ERANGE + ULONG_MAX (2)\n");
      exit (1);
    }
  mpfr_set_si (x, -1, GMP_RNDN);
  mpfr_clear_erangeflag ();
  dl = mpfr_get_ui (x, GMP_RNDN);
  if (dl != 0 || !mpfr_erangeflag_p ())
    {
      printf ("ERROR for get_ui + ERANGE + -1 \n");
      exit (1);
    }
  mpfr_set_si (x, LONG_MAX, GMP_RNDN);
  mpfr_clear_erangeflag ();
  d = mpfr_get_si (x, GMP_RNDN);
  if (d != LONG_MAX || mpfr_erangeflag_p ())
    {
      printf ("ERROR for get_si + ERANGE + LONG_MAX (1): %ld\n", d);
      exit (1);
    }
  mpfr_add_ui (x, x, 1, GMP_RNDN);
  d = mpfr_get_si (x, GMP_RNDN);
  if (d != LONG_MAX || !mpfr_erangeflag_p ())
    {
      printf ("ERROR for get_si + ERANGE + LONG_MAX (2)\n");
      exit (1);
    }
  mpfr_set_si (x, LONG_MIN, GMP_RNDN);
  mpfr_clear_erangeflag ();
  d = mpfr_get_si (x, GMP_RNDN);
  if (d != LONG_MIN || mpfr_erangeflag_p ())
    {
      printf ("ERROR for get_si + ERANGE + LONG_MIN (1)\n");
      exit (1);
    }
  mpfr_sub_ui (x, x, 1, GMP_RNDN);
  d = mpfr_get_si (x, GMP_RNDN);
  if (d != LONG_MIN || !mpfr_erangeflag_p ())
    {
      printf ("ERROR for get_si + ERANGE + LONG_MIN (2)\n");
      exit (1);
    }
 
  mpfr_clear (x);

  test_2exp ();
  tests_end_mpfr ();
  return 0;
}
