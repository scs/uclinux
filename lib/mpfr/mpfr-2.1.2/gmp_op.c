/* Implementations of operations between mpfr and mpz/mpq data

Copyright 2001, 2003, 2004 Free Software Foundation, Inc.

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

#include <stddef.h>
#include "mpfr-impl.h"
 
int
mpfr_mul_z (mpfr_ptr y, mpfr_srcptr x, mpz_srcptr z,mp_rnd_t rnd_mode)
{
  mpfr_t t;
  int res;
  mpfr_init2(t, mpz_sizeinbase(z, 2) + MPFR_PREC_MIN );
  res = mpfr_set_z(t, z, rnd_mode);
  MPFR_ASSERTD(res == 0);
  res = mpfr_mul(y, x, t, rnd_mode);
  mpfr_clear(t);
  return(res);
}

int
mpfr_div_z (mpfr_ptr y, mpfr_srcptr x, mpz_srcptr z, mp_rnd_t rnd_mode)
{
  mpfr_t t;
  int res;
  mpfr_init2(t, mpz_sizeinbase(z, 2)  + MPFR_PREC_MIN );
  res = mpfr_set_z(t, z, rnd_mode);
  MPFR_ASSERTD(res == 0);
  res = mpfr_div(y, x, t, rnd_mode);
  mpfr_clear(t);
  return res;
}

int
mpfr_add_z (mpfr_ptr y, mpfr_srcptr x, mpz_srcptr z, mp_rnd_t rnd_mode)
{
  mpfr_t t;
  int res;
  
  if (MPFR_UNLIKELY(mpz_sgn(z) == 0))
    return mpfr_set (y, x, rnd_mode);

  mpfr_init2 (t, mpz_sizeinbase(z, 2)  + MPFR_PREC_MIN );
  res = mpfr_set_z (t, z, rnd_mode);
  MPFR_ASSERTD (res == 0);
  res = mpfr_add (y, x, t, rnd_mode);
  mpfr_clear (t);
  return res;
}

int
mpfr_sub_z (mpfr_ptr y, mpfr_srcptr x, mpz_srcptr z,mp_rnd_t rnd_mode)
{
  mpfr_t t;
  int res;

  if (MPFR_UNLIKELY(mpz_sgn(z) == 0))
    return mpfr_set (y, x, rnd_mode);
  mpfr_init2 (t, mpz_sizeinbase(z, 2)  + MPFR_PREC_MIN );
  res = mpfr_set_z (t, z, rnd_mode);
  MPFR_ASSERTD (res == 0);
  res=mpfr_sub (y, x, t, rnd_mode);
  mpfr_clear (t);
  return res;
}

int
mpfr_cmp_z (mpfr_srcptr x, mpz_srcptr z)
{
  mpfr_t t;
  int res;
  mpfr_init2 (t, mpz_sizeinbase(z, 2)  + MPFR_PREC_MIN );
  res = mpfr_set_z (t, z, GMP_RNDN);
  MPFR_ASSERTD(res == 0);
  res = mpfr_cmp (x, t);
  mpfr_clear (t);
  return res;  
}

int
mpfr_mul_q (mpfr_ptr y, mpfr_srcptr x, mpq_srcptr z,mp_rnd_t rnd_mode)
{
  mpfr_t tmp;
  int res;
 
  mpfr_init2 (tmp, MPFR_PREC(x) + mpz_sizeinbase(mpq_numref(z), 2) );
  res = mpfr_mul_z (tmp, x, mpq_numref(z), GMP_RNDN );
  MPFR_ASSERTD( res == 0 );
  res = mpfr_div_z (y, tmp, mpq_denref(z), rnd_mode);
  mpfr_clear(tmp);
  return(res);
}

int
mpfr_div_q (mpfr_ptr y, mpfr_srcptr x, mpq_srcptr z, mp_rnd_t rnd_mode)
{
  mpfr_t tmp;
  int res;

  mpfr_init2 (tmp, MPFR_PREC(x) + mpz_sizeinbase(mpq_denref(z), 2) );
  res = mpfr_mul_z (tmp, x, mpq_denref(z), GMP_RNDN );
  MPFR_ASSERTD( res == 0 );
  res = mpfr_div_z (y, tmp, mpq_numref(z), rnd_mode);
  mpfr_clear(tmp);
  return(res);
}

int
mpfr_add_q (mpfr_ptr y, mpfr_srcptr x, mpq_srcptr z, mp_rnd_t rnd_mode)
{
  mpfr_t    t,q;
  mp_prec_t p = MPFR_PREC(y)+10;
  mp_exp_t  err;
  int res;

  if (MPFR_UNLIKELY(MPFR_IS_SINGULAR(x)))
    {
      if (MPFR_IS_NAN(x))
	{
	  MPFR_SET_NAN(y);
	  MPFR_RET_NAN;
	}
      else if (MPFR_IS_INF(x))
	{
	  MPFR_SET_INF (y);
	  MPFR_SET_SAME_SIGN (y, x);
	  MPFR_RET (0);
	}
      else
	{
	  MPFR_ASSERTD( MPFR_IS_ZERO(x));
	  
	  if (MPFR_UNLIKELY( mpq_sgn(z) == 0))
	    return mpfr_set (y, x, rnd_mode); /* signed 0 - Unsigned 0 */
	  else
	    return mpfr_set_q (y, z, rnd_mode);
	}
    }

  mpfr_inits(t, q, NULL);
  for(;;)
    {
      mpfr_set_prec(t, p);
      mpfr_set_prec(q, p);
      
      res = mpfr_set_q(q, z, GMP_RNDN);  /* Error <= 1/2 ulp(q) */
      /* If z if @INF@ (1/0), res = 0, so it quits immediately */
      if (res == 0) /* Result is exact so we can add it directly!*/
	{
	  res = mpfr_add(y, x, q, rnd_mode);
	  break;
	}
      mpfr_add(t, x, q, GMP_RNDN);       /* Error <= 1/2 ulp(t) */
      /* Error / ulp(t)      <= 1/2 + 1/2 * 2^(EXP(q)-EXP(t))
	 If EXP(q)-EXP(t)>0, <= 2^(EXP(q)-EXP(t)-1)*(1+2^-(EXP(q)-EXP(t)))
	                     <= 2^(EXP(q)-EXP(t))
	 If EXP(q)-EXP(t)<0, <= 2^0 */
      /* We can get 0, but we can't round since q is inexact */
      if (MPFR_LIKELY( !MPFR_IS_ZERO (t)))
	{
	  err = (mp_exp_t) p - 1 - MAX(MPFR_GET_EXP(q)-MPFR_GET_EXP(t), 0);
	  res = mpfr_can_round (t, err, GMP_RNDN, GMP_RNDZ, 
				MPFR_PREC(y) + (rnd_mode == GMP_RNDN) );
	  if (res != 0)  /* We can round! */
	    {
	      res = mpfr_set(y, t, rnd_mode);
	      break;
	    }
	}
      p += BITS_PER_MP_LIMB;             /* Next precision if we continue */
    } 
  mpfr_clears(t, q, NULL);
  return res;
}

int
mpfr_sub_q (mpfr_ptr y, mpfr_srcptr x, mpq_srcptr z,mp_rnd_t rnd_mode)
{
  mpfr_t t,q;
  mp_prec_t p = MPFR_PREC(y)+10;
  int res;
  mp_exp_t err;

  if (MPFR_UNLIKELY(MPFR_IS_SINGULAR(x)))
    {
      if (MPFR_IS_NAN(x))
        {
          MPFR_SET_NAN (y);
          MPFR_RET_NAN;
        }
      else if (MPFR_IS_INF(x))
        {
          MPFR_SET_INF (y);
          MPFR_SET_SAME_SIGN (y, x);
          MPFR_RET (0);
        }
      else
        {
          MPFR_ASSERTD( MPFR_IS_ZERO(x));
	  
          if (MPFR_UNLIKELY( mpq_sgn(z) == 0))
            return mpfr_set (y, x, rnd_mode); /* signed 0 - Unsigned 0 */
          else
	    {
	      if (rnd_mode == GMP_RNDU) 
		rnd_mode = GMP_RNDD;
	      else if (rnd_mode == GMP_RNDD)
		rnd_mode = GMP_RNDU;
	      res =  mpfr_set_q (y, z, rnd_mode);
	      MPFR_CHANGE_SIGN (y);
	      return -res;
	    }
        }
    }

  mpfr_inits(t, q, NULL);
  for(;;)
    {
      mpfr_set_prec(t, p);
      mpfr_set_prec(q, p);

      res = mpfr_set_q(q, z, GMP_RNDN);  /* Error <= 1/2 ulp(q) */
      /* If z if @INF@ (1/0), res = 0, so it quits immediately */
      if (res == 0)            /* Result is exact so we can add it directly!*/
        {
          res = mpfr_sub(y, x, q, rnd_mode);
          break;
        }
      mpfr_sub(t, x, q, GMP_RNDN);       /* Error <= 1/2 ulp(t) */
      /* Error / ulp(t)      <= 1/2 + 1/2 * 2^(EXP(q)-EXP(t))
         If EXP(q)-EXP(t)>0, <= 2^(EXP(q)-EXP(t)-1)*(1+2^-(EXP(q)-EXP(t)))
                             <= 2^(EXP(q)-EXP(t))
			     If EXP(q)-EXP(t)<0, <= 2^0 */
      /* We can get 0, but we can't round since q is inexact */
      if (MPFR_LIKELY( !MPFR_IS_ZERO (t)))
	{
	  err = (mp_exp_t) p - 1 - MAX(MPFR_GET_EXP(q)-MPFR_GET_EXP(t), 0);
	  res = mpfr_can_round (t, err, GMP_RNDN, GMP_RNDZ,
				MPFR_PREC(y) + (rnd_mode == GMP_RNDN) );
	  if (res != 0)  /* We can round! */
	    {
	      res = mpfr_set(y, t, rnd_mode);
	      break;
	    }
	}
      p += BITS_PER_MP_LIMB;             /* Next precision if we continue */
    }
  mpfr_clears(t, q, NULL);
  return res;
}

int
mpfr_cmp_q (mpfr_srcptr x, mpq_srcptr z)
{
  mpfr_t t;
  int res;
  /* x < a/b ? <=> x*b < a */
  mpfr_init2 (t, MPFR_PREC(x) + mpz_sizeinbase (mpq_denref(z), 2) );
  res = mpfr_mul_z (t, x, mpq_denref (z), GMP_RNDN );
  MPFR_ASSERTD( res == 0 );
  res = mpfr_cmp_z (t, mpq_numref (z) );
  mpfr_clear (t);
  return res;
}

int
mpfr_cmp_f (mpfr_srcptr x, mpf_srcptr z)
{
  mpfr_t t;
  int res;

  mpfr_init2 (t, MPFR_PREC_MIN + ABS(SIZ(z)) * BITS_PER_MP_LIMB );
  res = mpfr_set_f (t, z, GMP_RNDN);
  MPFR_ASSERTD( res == 0 );
  res = mpfr_cmp (x, t);
  mpfr_clear (t);
  return res;
}
