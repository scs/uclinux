/* tsum -- test file for the list summation function

Copyright 2004, 2005 Free Software Foundation.

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

#include <stdlib.h>
#include <stdio.h>
#include "mpfr-test.h"


static int is_sorted(unsigned long n, mpfr_srcptr *perm)
{
  unsigned long i;

  for (i = 0; i < n - 1; i++)
    {
      if (MPFR_GET_EXP(perm[i]) < MPFR_GET_EXP(perm[i+1]))
	return 0;
    }
  return 1;
}

static int mpfr_list_sum (mpfr_ptr ret, mpfr_t *tab, unsigned long n, 
                          mp_rnd_t rnd)
{
    mpfr_ptr *tabtmp;
    unsigned long i;
    int inexact;
    TMP_DECL(marker);
    
    TMP_MARK(marker);
    tabtmp = (mpfr_ptr *) TMP_ALLOC(n * sizeof(mpfr_srcptr));
    for (i = 0; i < n; i++)
        tabtmp[i] = tab[i];
    
    inexact = mpfr_sum (ret, tabtmp, n, rnd);
    TMP_FREE(marker);
    return inexact;
}


static mp_prec_t get_prec_max (mpfr_t *tab, unsigned long n, mp_prec_t f)
{
  mp_prec_t res;
  mp_exp_t min, max;
  unsigned long i;
  min = max = MPFR_GET_EXP(tab[0]);

  for (i = 1; i < n; i++)
  {
      if (MPFR_GET_EXP(tab[i]) > max)
          max = MPFR_GET_EXP(tab[i]);
      if (MPFR_GET_EXP(tab[i]) < min)
          min = MPFR_GET_EXP(tab[i]);
  }
  res = max - min;
  res += f;
  res += __gmpfr_ceil_log2 (n) + 1;
  return res;
}


static void algo_exact(mpfr_t somme, mpfr_t *tab, unsigned long n, mp_prec_t f)
{
  unsigned long i;
  mp_prec_t prec_max;
  prec_max = get_prec_max(tab, n, f);
  mpfr_init2 (somme, prec_max);
  mpfr_set_ui (somme, 0, GMP_RNDN);
  for (i = 0; i < n; i++)
    {
      if (mpfr_add(somme, somme, tab[i], GMP_RNDN))
	{
            printf ("FIXME: algo_exact is buggy.\n");
            exit (1);
	}
    }
}

int
main (void)
{
  mpfr_t *tab;
  mpfr_ptr *tabtmp;
  unsigned long i, n;
  mp_prec_t f;
  int rnd_mode;
  mpfr_srcptr *perm;
  mpfr_t sum, real_sum, real_non_rounded;

  tests_start_mpfr ();
  n = 1026;
  f = 1764;
  tab = (mpfr_t *) malloc (n * sizeof(mpfr_t));
  for (i = 0; i < n; i++)
  {
      mpfr_init2 (tab[i], f);
      mpfr_urandomb (tab[i], RANDS);
  }
  mpfr_init2 (sum, f);
  mpfr_init2 (real_sum, f);
  algo_exact (real_non_rounded, tab, n, f);
  for (rnd_mode = 0; rnd_mode < GMP_RND_MAX; rnd_mode++)
  {
      mpfr_list_sum (sum, tab, n, (mp_rnd_t) rnd_mode);
      mpfr_set (real_sum, real_non_rounded, (mp_rnd_t) rnd_mode);
      if (mpfr_cmp (real_sum, sum) != 0)
      {
          printf ("mpfr_list_sum incorrect.\n");
          mpfr_print_binary (real_sum);
          putchar ('\n');
          mpfr_print_binary (sum);
          putchar ('\n');
          return 1;
      }
  }

  for (i = 0; i < n; i++)
  {
      mpfr_urandomb (tab[i], RANDS);
  }

  mpfr_set_exp (tab[0], 1000);
  mpfr_clear (real_non_rounded);
  algo_exact (real_non_rounded, tab, n, f);
  
  for (rnd_mode = 0; rnd_mode < GMP_RND_MAX; rnd_mode++)
  {
      mpfr_list_sum (sum, tab, n, (mp_rnd_t) rnd_mode);
      mpfr_set (real_sum, real_non_rounded, (mp_rnd_t) rnd_mode);
      if (mpfr_cmp (real_sum, sum) != 0)
      {
          printf ("mpfr_list_sum incorrect.\n");
          mpfr_print_binary (real_sum);
          putchar ('\n');
          mpfr_print_binary (sum);
          putchar ('\n');
          return 1;
      }
  }


  /* list_sum tested, now test the sorting function */

  for (i = 0; i < n; i++)
      mpfr_urandomb (tab[i], RANDS);
  tabtmp = (mpfr_ptr *) malloc (n * sizeof(mpfr_ptr));
  perm = (mpfr_srcptr *) malloc (n * sizeof(mpfr_srcptr));

  for (i = 0; i < n; i++)
       tabtmp[i] = tab[i];

  mpfr_count_sort (tabtmp, n, perm);

  if (is_sorted (n, perm) == 0)
  {
      printf ("mpfr_count_sort incorrect.\n");
      for (i = 0; i < n; i++)
      {
          mpfr_print_binary (perm[i]);
          putchar ('\n');
      }
      return 1;
  }

  for (i = 0; i < n; i++)
      mpfr_clear (tab[i]);

  mpfr_clear (sum);
  mpfr_clear (real_sum);
  mpfr_clear (real_non_rounded);
  free (tab);
  free (perm);
  tests_end_mpfr ();
  return 0;
}

