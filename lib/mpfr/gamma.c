/* mpfr_gamma -- gamma function

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

#ifdef DEBUG
#include <stdio.h>
#include <stdlib.h>
#endif


#include "mpfr-impl.h"

/* We use the reflection formula 
  Gamma(1+t) Gamma(1-t) = - Pi t / sin(Pi (1 + t))
  in order to treat the case x <= 1,
  i.e. if x = 1-t, then Gamma(x) = -Pi*(1-x)/sin(Pi*(2-x))/GAMMA(2-x)
*/

int
mpfr_gamma (mpfr_ptr gamma, mpfr_srcptr x, mp_rnd_t rnd_mode)
{
  mpfr_t xp;
  mpfr_t product;
  mpfr_t the_pi;
  mpfr_t GammaTrial;
  mpfr_t tmp, tmp2;
  mp_prec_t Prec;
  mp_prec_t prec_gamma;
  mp_prec_t prec_nec;
  mp_prec_t A, N, estimated_cancel;
  mp_prec_t realprec;
  int compared;
  unsigned long k;
  int sign;
  int inex;

  /* Trivial cases */
  if (MPFR_UNLIKELY( MPFR_IS_SINGULAR(x) ))
    {
      if (MPFR_IS_NAN(x))
	{
	  MPFR_SET_NAN(gamma);
	  MPFR_RET_NAN;
	}
      else if (MPFR_IS_INF(x))
	{
	  if (MPFR_IS_NEG(x))
	    {
	      MPFR_SET_NAN(gamma);
	      MPFR_RET_NAN;
	    }
	  else
	    {
	      MPFR_SET_INF(gamma);
	      MPFR_SET_POS(gamma);
	      return 0;  /* exact */
	    }
	}
      else
	{
          MPFR_ASSERTD(MPFR_IS_ZERO(x));
	  MPFR_SET_INF(gamma);
	  MPFR_SET_SAME_SIGN(gamma, x);
	  return 0;  /* exact */
	}
    }
  MPFR_CLEAR_FLAGS(gamma);

  /* Set x_p=x if x> 1 else set x_p=2-x */
  prec_gamma = MPFR_PREC (gamma);
  compared = mpfr_cmp_ui (x, 1);
  if (compared == 0)
    return mpfr_set_ui (gamma, 1, rnd_mode);

  /* if x is an integer that fits into an unsigned long, use mpfr_fac_ui */
  if (mpfr_integer_p (x))
    {
      unsigned long int u;
      u = mpfr_get_ui (x, GMP_RNDN);
      /* u = 0 when x is 0 or x does not fit in an unsigned long */
      if (u != 0)
        return mpfr_fac_ui (gamma, u - 1, rnd_mode);
    }

  mpfr_save_emin_emax ();

  realprec = prec_gamma + 10;

  mpfr_init2 (xp, 2);
  /* Initialisation    */
  mpfr_init (tmp);
  mpfr_init (tmp2);
  mpfr_init (the_pi);
  mpfr_init (product);
  mpfr_init (GammaTrial);

  for (;;)
    { 
      /* Precision stuff */
      prec_nec = compared < 0 ?
        2 + realprec  /* We will use the reflexion formula! */
        : realprec;
      /* A   = (prec_nec-0.5)*CST
	 CST = ln(2)/(ln(2*pi))) = 0.38
	 This strange formula is just to avoid any overflow */
      A = (prec_nec/100)*38 + ((prec_nec%100)*38+100-38/2)/100 - 1;
      N = A - 1;
#ifdef DEBUG
      printf("A=%d N=%d\n", (int)A, (int)N);
#endif

      /* Estimated_cancel is the amount of bit that will be flushed */
      /* estimated_cancel = A + ecCST * A;
	 ecCST = {1+sup_{x\in [0,1]} x*ln((1-x)/x)}/ln(2) = 1.84 
	 This strange formula is just to avoid any overflow */
      estimated_cancel = A + (A + (A/100)*84 + ((A%100)*84)/100);
      Prec = prec_nec + estimated_cancel + 16;

      MPFR_ASSERTD (Prec > prec_nec);
      MPFR_ASSERTD (Prec > estimated_cancel);
      MPFR_ASSERTD (estimated_cancel > A);

      mpfr_set_prec (xp, Prec);
      if (compared < 0)
	mpfr_ui_sub (xp, 1, x, GMP_RNDN);
      else
	mpfr_sub_ui (xp, x, 1, GMP_RNDN);

      /* Set prec  */
      mpfr_set_prec (tmp, Prec);
      mpfr_set_prec (tmp2, Prec);
      mpfr_set_prec (the_pi, Prec);
      mpfr_set_prec (product, Prec);
      mpfr_set_prec (GammaTrial, Prec);

      mpfr_set_ui (GammaTrial, 0, GMP_RNDN);
      sign = 1;
      for (k = 1; k <= N; k++)
        {
          mpfr_set_ui (tmp, A - k, GMP_RNDN);
          mpfr_exp (product, tmp, GMP_RNDN);
          mpfr_ui_pow_ui (tmp, A - k, k - 1, GMP_RNDN);
          mpfr_mul (product, product, tmp, GMP_RNDN);
          mpfr_sqrt_ui (tmp, A - k, GMP_RNDN);
          mpfr_mul (product, product, tmp, GMP_RNDN);
          mpfr_fac_ui (tmp, k - 1, GMP_RNDN);
          mpfr_div (product, product, tmp, GMP_RNDN);
          mpfr_add_ui (tmp, xp, k, GMP_RNDN);
          mpfr_div (product, product, tmp, GMP_RNDN);
          sign = -sign;
          if (sign == 1)
            {
              mpfr_neg (product, product, GMP_RNDN);
#ifdef DEBUG
              /*    printf(" k=%u", k);
                    printf("\n");*/
#endif
            }
          mpfr_add(GammaTrial, GammaTrial, product, GMP_RNDN);
        }
#ifdef DEBUG
      printf("GammaTrial =");
      mpfr_out_str (stdout, 10, 0, GammaTrial, GMP_RNDD);
      printf ("\n");
#endif
      mpfr_const_pi(the_pi, GMP_RNDN);
      mpfr_const_pi(tmp, GMP_RNDN);
      mpfr_mul_2ui(tmp, tmp, 1, GMP_RNDN);
      mpfr_sqrt(tmp, tmp, GMP_RNDN);
      mpfr_add(GammaTrial, GammaTrial, tmp, GMP_RNDN);
      mpfr_add_ui(tmp2, xp, A, GMP_RNDN);
      mpfr_set_ui(tmp, 1, GMP_RNDN);
      mpfr_div_2ui(tmp, tmp, 1, GMP_RNDN);
      mpfr_add(tmp, tmp, xp, GMP_RNDN);
      mpfr_pow(tmp, tmp2, tmp, GMP_RNDN);
      mpfr_mul(GammaTrial, GammaTrial, tmp, GMP_RNDN);
      mpfr_neg(tmp, tmp2, GMP_RNDN);
      mpfr_exp(tmp, tmp, GMP_RNDN);
      mpfr_mul(GammaTrial, GammaTrial, tmp, GMP_RNDN);
      if (compared < 0)
        {
          mpfr_sub_ui (tmp, x, 1, GMP_RNDN);
          mpfr_mul (tmp, the_pi, tmp, GMP_RNDN);
          mpfr_div (GammaTrial, tmp, GammaTrial, GMP_RNDN);
          mpfr_sin (tmp, tmp, GMP_RNDN);
          mpfr_div (GammaTrial, GammaTrial, tmp, GMP_RNDN);
        }
#ifdef DEBUG
      printf("GammaTrial =");
      mpfr_out_str (stdout, 10, 0, GammaTrial, GMP_RNDD);
      printf ("\n");
#endif
      if (mpfr_can_round (GammaTrial, realprec, GMP_RNDD, GMP_RNDZ,
                          MPFR_PREC(gamma) + (rnd_mode == GMP_RNDN)))
        break;
      
      realprec += __gmpfr_ceil_log2 ((double) realprec);
    }
  inex = mpfr_set (gamma, GammaTrial, rnd_mode);

  mpfr_clear(tmp);
  mpfr_clear(tmp2);
  mpfr_clear(the_pi);
  mpfr_clear(product);
  mpfr_clear(GammaTrial);

  mpfr_clear (xp);
  mpfr_restore_emin_emax ();

  return mpfr_check_range(gamma, inex, rnd_mode); 
}
