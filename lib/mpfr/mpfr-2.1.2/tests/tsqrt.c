/* Test file for mpfr_sqrt.

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

#include "mpfr-test.h"

static void
check3 (const char *as, mp_rnd_t rnd_mode, const char *qs)
{
  mpfr_t q;

  mpfr_init2 (q, 53);
  mpfr_set_str1 (q, as);
  mpfr_sqrt (q, q, rnd_mode);
  if (mpfr_cmp_str1 (q, qs) )
    {
      printf ("mpfr_sqrt failed for a=%s, rnd_mode=%s\n",
              as, mpfr_print_rnd_mode (rnd_mode));
      printf ("expected sqrt is %s, got ",qs);
      mpfr_out_str(stdout, 10, 0, q, GMP_RNDN);
      putchar('\n');
      exit (1);
    }
  mpfr_clear (q);
}

static void
check4 (const char *as, mp_rnd_t rnd_mode, const char *Qs)
{
  mpfr_t q;

  mpfr_init2(q, 53);
  mpfr_set_str1 (q, as);
  mpfr_sqrt(q, q, rnd_mode);
  if (mpfr_cmp_str (q, Qs, 16, GMP_RNDN))
    {
      printf("mpfr_sqrt failed for a=%s, rnd_mode=%s\n",
	     as, mpfr_print_rnd_mode(rnd_mode));
      printf("expected ");
      mpfr_out_str(stdout, 16, 0, q, GMP_RNDN);
      printf("\ngot      %s\n", Qs);
      mpfr_clear(q);
      exit(1);
  }
  mpfr_clear(q);
}

static void
check24 (const char *as, mp_rnd_t rnd_mode, const char *qs)
{
  mpfr_t q;

  mpfr_init2(q, 24);
  mpfr_set_str1(q, as);
  mpfr_sqrt(q, q, rnd_mode);
  if (mpfr_cmp_str1 (q, qs))
    {
      printf("mpfr_sqrt failed for a=%s, prec=24, rnd_mode=%s\n",
	     as, mpfr_print_rnd_mode(rnd_mode));
      printf("expected sqrt is %s, got ",qs);
      mpfr_out_str(stdout, 10, 0, q, GMP_RNDN);
      exit(1);
    }
  mpfr_clear(q);
}

/* the following examples come from the paper "Number-theoretic Test
   Generation for Directed Rounding" from Michael Parks, Table 3 */
static void
check_float (void)
{
  check24("70368760954880.0", GMP_RNDN, "8.388609e6");
  check24("281474943156224.0", GMP_RNDN, "1.6777215e7");
  check24("70368777732096.0", GMP_RNDN, "8.388610e6");
  check24("281474909601792.0", GMP_RNDN, "1.6777214e7");
  check24("100216216748032.0", GMP_RNDN, "1.0010805e7");
  check24("120137273311232.0", GMP_RNDN, "1.0960715e7");
  check24("229674600890368.0", GMP_RNDN, "1.5155019e7");
  check24("70368794509312.0", GMP_RNDN, "8.388611e6");
  check24("281474876047360.0", GMP_RNDN, "1.6777213e7");
  check24("91214552498176.0", GMP_RNDN, "9.550631e6");

  check24("70368760954880.0", GMP_RNDZ, "8.388608e6");
  check24("281474943156224.0", GMP_RNDZ, "1.6777214e7");
  check24("70368777732096.0", GMP_RNDZ, "8.388609e6");
  check24("281474909601792.0", GMP_RNDZ, "1.6777213e7");
  check24("100216216748032.0", GMP_RNDZ, "1.0010805e7");
  check24("120137273311232.0", GMP_RNDZ, "1.0960715e7");
  check24("229674600890368.0", GMP_RNDZ, "1.5155019e7");
  check24("70368794509312.0", GMP_RNDZ, "8.38861e6");
  check24("281474876047360.0", GMP_RNDZ, "1.6777212e7");
  check24("91214552498176.0", GMP_RNDZ, "9.550631e6");

  check24("70368760954880.0", GMP_RNDU, "8.388609e6");
  check24("281474943156224.0",GMP_RNDU, "1.6777215e7");
  check24("70368777732096.0", GMP_RNDU, "8.388610e6");
  check24("281474909601792.0", GMP_RNDU, "1.6777214e7");
  check24("100216216748032.0", GMP_RNDU, "1.0010806e7");
  check24("120137273311232.0", GMP_RNDU, "1.0960716e7");
  check24("229674600890368.0", GMP_RNDU, "1.515502e7");
  check24("70368794509312.0", GMP_RNDU, "8.388611e6");
  check24("281474876047360.0", GMP_RNDU, "1.6777213e7");
  check24("91214552498176.0", GMP_RNDU, "9.550632e6");

  check24("70368760954880.0", GMP_RNDD, "8.388608e6");
  check24("281474943156224.0", GMP_RNDD, "1.6777214e7");
  check24("70368777732096.0", GMP_RNDD, "8.388609e6");
  check24("281474909601792.0", GMP_RNDD, "1.6777213e7");
  check24("100216216748032.0", GMP_RNDD, "1.0010805e7");
  check24("120137273311232.0", GMP_RNDD, "1.0960715e7");
  check24("229674600890368.0", GMP_RNDD, "1.5155019e7");
  check24("70368794509312.0", GMP_RNDD, "8.38861e6");
  check24("281474876047360.0", GMP_RNDD, "1.6777212e7");
  check24("91214552498176.0", GMP_RNDD, "9.550631e6");
}

static void
special (void)
{
  mpfr_t x, y, z;
  int inexact;
  mp_prec_t p;

  mpfr_init (x);
  mpfr_init (y);
  mpfr_init (z);

  mpfr_set_prec (x, 27);
  mpfr_set_str_binary (x, "0.110100111010101000010001011");
  if ((inexact = mpfr_sqrt (x, x, GMP_RNDZ)) >= 0)
    {
      printf ("Wrong inexact flag: expected -1, got %d\n", inexact);
      exit (1);
    }

  mpfr_set_prec (x, 2);
  for (p=2; p<1000; p++)
    {
      mpfr_set_prec (z, p);
      mpfr_set_ui (z, 1, GMP_RNDN);
      mpfr_add_one_ulp (z, GMP_RNDN);
      mpfr_sqrt (x, z, GMP_RNDU);
      if (mpfr_cmp_ui_2exp(x, 3, -1))
	{
	  printf ("Error: sqrt(1+ulp(1), up) should give 1.5 (prec=%u)\n",
                  (unsigned int) p);
	  printf ("got "); mpfr_print_binary (x); puts ("");
	  exit (1);
	}
    }

  /* check inexact flag */
  mpfr_set_prec (x, 5);
  mpfr_set_str_binary (x, "1.1001E-2");
  if ((inexact = mpfr_sqrt (x, x, GMP_RNDN)))
    {
      printf ("Wrong inexact flag: expected 0, got %d\n", inexact);
      exit (1);
    }

  mpfr_set_prec (x, 2);
  mpfr_set_prec (z, 2);

  /* checks the sign is correctly set */
  mpfr_set_si (x, 1,  GMP_RNDN);
  mpfr_set_si (z, -1, GMP_RNDN);
  mpfr_sqrt (z, x, GMP_RNDN);
  if (mpfr_cmp_ui (z, 0) < 0)
    {
      printf ("Error: square root of 1 gives ");
      mpfr_print_binary(z);
      putchar('\n');
      exit (1);
    }

  mpfr_set_prec (x, 192);
  mpfr_set_prec (z, 160);
  mpfr_set_str_binary (z, "0.1011010100000100100100100110011001011100100100000011000111011001011101101101110000110100001000100001100001011000E1");
  mpfr_set_prec (x, 160);
  mpfr_sqrt(x, z, GMP_RNDN);
  mpfr_sqrt(z, x, GMP_RNDN);

  mpfr_set_prec (x, 53);
  mpfr_set_str (x, "8093416094703476.0", 10, GMP_RNDN);
  mpfr_div_2exp (x, x, 1075, GMP_RNDN);
  mpfr_sqrt (x, x, GMP_RNDN);
  mpfr_set_str (z, "1e55596835b5ef@-141", 16, GMP_RNDN);
  if (mpfr_cmp (x, z))
    {
      printf ("Error: square root of 8093416094703476*2^(-1075)\n");
      exit (1);
    }

  mpfr_set_prec (x, 33);
  mpfr_set_str_binary (x, "0.111011011011110001100111111001000e-10");
  mpfr_set_prec (z, 157);
  inexact = mpfr_sqrt (z, x, GMP_RNDN);
  mpfr_set_prec (x, 157);
  mpfr_set_str_binary (x, "0.11110110101100101111001011100011100011100001101010111011010000100111011000111110100001001011110011111100101110010110010110011001011011010110010000011001101E-5");
  if (mpfr_cmp (x, z))
    {
      printf ("Error: square root (1)\n");
      exit (1);
    }
  if (inexact <= 0)
    {
      printf ("Error: wrong inexact flag (1)\n");
      exit (1);
    }

  /* case prec(result) << prec(input) */
  mpfr_set_prec (z, 2);
  for (p = 2; p < 1000; p++)
    {
      mpfr_set_prec (x, p);
      mpfr_set_ui (x, 1, GMP_RNDN);
      mpfr_nextabove (x);
      /* 1.0 < x <= 1.5 thus 1 < sqrt(x) <= 1.23 */
      inexact = mpfr_sqrt (z, x, GMP_RNDN);
      MPFR_ASSERTN(inexact < 0 && mpfr_cmp_ui (z, 1) == 0);
      inexact = mpfr_sqrt (z, x, GMP_RNDZ);
      MPFR_ASSERTN(inexact < 0 && mpfr_cmp_ui (z, 1) == 0);
      inexact = mpfr_sqrt (z, x, GMP_RNDU);
      MPFR_ASSERTN(inexact > 0 && mpfr_cmp_ui_2exp (z, 3, -1) == 0);
      inexact = mpfr_sqrt (z, x, GMP_RNDD);
      MPFR_ASSERTN(inexact < 0 && mpfr_cmp_ui (z, 1) == 0);
    }

  /* corner case rw = 0 in rounding to nearest */
  mpfr_set_prec (z, mp_bits_per_limb - 1);
  mpfr_set_prec (y, mp_bits_per_limb - 1);
  mpfr_set_ui (y, 1, GMP_RNDN);
  mpfr_mul_2exp (y, y, mp_bits_per_limb - 1, GMP_RNDN);
  mpfr_nextabove (y);
  for (p = 2 * mp_bits_per_limb - 1; p <= 1000; p++)
    {
      mpfr_set_prec (x, p);
      mpfr_set_ui (x, 1, GMP_RNDN);
      mpfr_set_exp (x, mp_bits_per_limb);
      mpfr_add_ui (x, x, 1, GMP_RNDN);
      /* now x = 2^(mp_bits_per_limb - 1) + 1 (mp_bits_per_limb bits) */
      MPFR_ASSERTN(mpfr_mul (x, x, x, GMP_RNDN) == 0); /* exact */
      inexact = mpfr_sqrt (z, x, GMP_RNDN);
      /* even rule: z should be 2^(mp_bits_per_limb - 1) */
      MPFR_ASSERTN(inexact < 0 &&
                   mpfr_cmp_ui_2exp (z, 1, mp_bits_per_limb - 1) == 0);
      mpfr_nextbelow (x);
      /* now x is just below [2^(mp_bits_per_limb - 1) + 1]^2 */
      inexact = mpfr_sqrt (z, x, GMP_RNDN);
      MPFR_ASSERTN(inexact < 0 &&
                   mpfr_cmp_ui_2exp (z, 1, mp_bits_per_limb - 1) == 0);
      mpfr_nextabove (x);
      mpfr_nextabove (x);
      /* now x is just above [2^(mp_bits_per_limb - 1) + 1]^2 */
      inexact = mpfr_sqrt (z, x, GMP_RNDN);
      if (mpfr_cmp (z, y))
        {
          printf ("Error for sqrt(x) in rounding to nearest\n");
          printf ("x="); mpfr_dump (x);
          printf ("Expected "); mpfr_dump (y);
          printf ("Got      "); mpfr_dump (z);
          exit (1);
        }
      if (inexact <= 0)
        {
          printf ("Wrong inexact flag in corner case for p = %lu\n", (unsigned long) p);
          exit (1);
        }
    }

  mpfr_clear (x);
  mpfr_clear (y);
  mpfr_clear (z);
}

static void
check_inexact (mp_prec_t p)
{
  mpfr_t x, y, z;
  mp_rnd_t rnd;
  int inexact, sign;

  mpfr_init2 (x, p);
  mpfr_init2 (y, p);
  mpfr_init2 (z, 2*p);
  mpfr_random (x);
  rnd = (mp_rnd_t) RND_RAND();
  inexact = mpfr_sqrt (y, x, rnd);
  if (mpfr_mul (z, y, y, rnd)) /* exact since prec(z) = 2*prec(y) */
    {
      printf ("Error: multiplication should be exact\n");
      exit (1);
    }
  mpfr_sub (z, z, x, rnd); /* exact also */
  sign = mpfr_cmp_ui (z, 0);
  if (((inexact == 0) && (sign)) ||
      ((inexact > 0) && (sign <= 0)) ||
      ((inexact < 0) && (sign >= 0)))
    {
      printf ("Error: wrong inexact flag, expected %d, got %d\n",
              sign, inexact);
      printf ("x=");
      mpfr_print_binary (x);
      printf (" rnd=%s\n", mpfr_print_rnd_mode (rnd));
      printf ("y="); mpfr_print_binary (y); puts ("");
      exit (1);
    }
  mpfr_clear (x);
  mpfr_clear (y);
  mpfr_clear (z);
}

static void
check_nan (void)
{
  mpfr_t  x, got;

  mpfr_init2 (x, 100L);
  mpfr_init2 (got, 100L);

  /* sqrt(NaN) == NaN */
  MPFR_CLEAR_FLAGS (x);
  MPFR_SET_NAN (x);
  MPFR_ASSERTN (mpfr_sqrt (got, x, GMP_RNDZ) == 0); /* exact */
  MPFR_ASSERTN (mpfr_nan_p (got));

  /* sqrt(-1) == NaN */
  mpfr_set_si (x, -1L, GMP_RNDZ);
  MPFR_ASSERTN (mpfr_sqrt (got, x, GMP_RNDZ) == 0); /* exact */
  MPFR_ASSERTN (mpfr_nan_p (got));

  /* sqrt(+inf) == +inf */
  MPFR_CLEAR_FLAGS (x);
  MPFR_SET_INF (x);
  MPFR_SET_POS (x);
  MPFR_ASSERTN (mpfr_sqrt (got, x, GMP_RNDZ) == 0); /* exact */
  MPFR_ASSERTN (mpfr_inf_p (got));

  /* sqrt(-inf) == NaN */
  MPFR_CLEAR_FLAGS (x);
  MPFR_SET_INF (x);
  MPFR_SET_NEG (x);
  MPFR_ASSERTN (mpfr_sqrt (got, x, GMP_RNDZ) == 0); /* exact */
  MPFR_ASSERTN (mpfr_nan_p (got));

  /* sqrt(-0) == 0 */
  mpfr_set_si (x, 0L, GMP_RNDZ);
  MPFR_SET_NEG (x);
  MPFR_ASSERTN (mpfr_sqrt (got, x, GMP_RNDZ) == 0); /* exact */
  MPFR_ASSERTN (mpfr_number_p (got));
  MPFR_ASSERTN (mpfr_cmp_ui (got, 0L) == 0);

  mpfr_clear (x);
  mpfr_clear (got);
}

int
main (void)
{
  mp_prec_t p;
  int k;

  tests_start_mpfr ();

  check_nan ();

  for (p=2; p<200; p++)
    for (k=0; k<200; k++)
      check_inexact (p);
  special ();
  check_float();

  check3 ("-0.0", GMP_RNDN, "0.0");
  check4 ("6.37983013646045901440e+32", GMP_RNDN, "5.9bc5036d09e0c@13");
  check4 ("1.0", GMP_RNDN, "1");
  check4 ("1.0", GMP_RNDZ, "1");
  check4 ("3.725290298461914062500000e-9", GMP_RNDN, "4@-4");
  check4 ("3.725290298461914062500000e-9", GMP_RNDZ, "4@-4");
  check4 ("1190456976439861.0", GMP_RNDZ, "2.0e7957873529a@6");
  check4 ("1219027943874417664.0", GMP_RNDZ, "4.1cf2af0e6a534@7");
  /* the following examples are bugs in Cygnus compiler/system, found by
     Fabrice Rouillier while porting mpfr to Windows */
  check4 ("9.89438396044940256501e-134", GMP_RNDU, "8.7af7bf0ebbee@-56");
  check4 ("7.86528588050363751914e+31", GMP_RNDZ, "1.f81fc40f32062@13");
  check4 ("0.99999999999999988897", GMP_RNDN, "f.ffffffffffff8@-1");
  check4 ("1.00000000000000022204", GMP_RNDN, "1");
  /* the following examples come from the paper "Number-theoretic Test
   Generation for Directed Rounding" from Michael Parks, Table 4 */

  check4 ("78652858805036375191418371571712.0", GMP_RNDN,
	  "1.f81fc40f32063@13");
  check4 ("38510074998589467860312736661504.0", GMP_RNDN,
	  "1.60c012a92fc65@13");
  check4 ("35318779685413012908190921129984.0", GMP_RNDN,
	  "1.51d17526c7161@13");
  check4 ("26729022595358440976973142425600.0", GMP_RNDN,
	  "1.25e19302f7e51@13");
  check4 ("22696567866564242819241453027328.0", GMP_RNDN,
	  "1.0ecea7dd2ec3d@13");
  check4 ("22696888073761729132924856434688.0", GMP_RNDN,
	  "1.0ecf250e8e921@13");
  check4 ("36055652513981905145251657416704.0", GMP_RNDN,
	  "1.5552f3eedcf33@13");
  check4 ("30189856268896404997497182748672.0", GMP_RNDN,
	  "1.3853ee10c9c99@13");
  check4 ("36075288240584711210898775080960.0", GMP_RNDN,
	  "1.556abe212b56f@13");
  check4 ("72154663483843080704304789585920.0", GMP_RNDN,
	  "1.e2d9a51977e6e@13");

  check4 ("78652858805036375191418371571712.0", GMP_RNDZ,
	  "1.f81fc40f32062@13");
  check4 ("38510074998589467860312736661504.0", GMP_RNDZ,
	  "1.60c012a92fc64@13");
  check4 ("35318779685413012908190921129984.0", GMP_RNDZ, "1.51d17526c716@13");
  check4 ("26729022595358440976973142425600.0", GMP_RNDZ, "1.25e19302f7e5@13");
  check4 ("22696567866564242819241453027328.0", GMP_RNDZ,
	  "1.0ecea7dd2ec3c@13");
  check4 ("22696888073761729132924856434688.0", GMP_RNDZ, "1.0ecf250e8e92@13");
  check4 ("36055652513981905145251657416704.0", GMP_RNDZ,
	  "1.5552f3eedcf32@13");
  check4 ("30189856268896404997497182748672.0", GMP_RNDZ,
	  "1.3853ee10c9c98@13");
  check4 ("36075288240584711210898775080960.0", GMP_RNDZ,
	  "1.556abe212b56e@13");
  check4 ("72154663483843080704304789585920.0", GMP_RNDZ,
	  "1.e2d9a51977e6d@13");

  check4 ("78652858805036375191418371571712.0", GMP_RNDU,
	  "1.f81fc40f32063@13");
  check4 ("38510074998589467860312736661504.0", GMP_RNDU,
	  "1.60c012a92fc65@13");
  check4 ("35318779685413012908190921129984.0", GMP_RNDU,
	  "1.51d17526c7161@13");
  check4 ("26729022595358440976973142425600.0", GMP_RNDU,
	  "1.25e19302f7e51@13");
  check4 ("22696567866564242819241453027328.0", GMP_RNDU,
	  "1.0ecea7dd2ec3d@13");
  check4 ("22696888073761729132924856434688.0", GMP_RNDU,
	  "1.0ecf250e8e921@13");
  check4 ("36055652513981905145251657416704.0", GMP_RNDU,
	  "1.5552f3eedcf33@13");
  check4 ("30189856268896404997497182748672.0", GMP_RNDU,
	  "1.3853ee10c9c99@13");
  check4 ("36075288240584711210898775080960.0", GMP_RNDU,
	  "1.556abe212b56f@13");
  check4 ("72154663483843080704304789585920.0", GMP_RNDU,
	  "1.e2d9a51977e6e@13");

  check4 ("78652858805036375191418371571712.0", GMP_RNDD,
	  "1.f81fc40f32062@13");
  check4 ("38510074998589467860312736661504.0", GMP_RNDD,
	  "1.60c012a92fc64@13");
  check4 ("35318779685413012908190921129984.0", GMP_RNDD, "1.51d17526c716@13");
  check4 ("26729022595358440976973142425600.0", GMP_RNDD, "1.25e19302f7e5@13");
  check4 ("22696567866564242819241453027328.0", GMP_RNDD,
	  "1.0ecea7dd2ec3c@13");
  check4 ("22696888073761729132924856434688.0", GMP_RNDD, "1.0ecf250e8e92@13");
  check4 ("36055652513981905145251657416704.0", GMP_RNDD,
	  "1.5552f3eedcf32@13");
  check4 ("30189856268896404997497182748672.0", GMP_RNDD,
	  "1.3853ee10c9c98@13");
  check4 ("36075288240584711210898775080960.0", GMP_RNDD,
	  "1.556abe212b56e@13");
  check4 ("72154663483843080704304789585920.0", GMP_RNDD,
	  "1.e2d9a51977e6d@13");

  tests_end_mpfr ();
  return 0;
}
