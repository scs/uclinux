/* mpfr_div -- divide two floating-point numbers
 
Copyright 1999, 2001, 2002, 2003, 2004 Free Software Foundation.

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

#define MPFR_NEED_LONGLONG_H
#include "mpfr-impl.h"

int
mpfr_div (mpfr_ptr q, mpfr_srcptr u, mpfr_srcptr v, mp_rnd_t rnd_mode)
{
  mp_srcptr up, vp, bp;
  mp_size_t usize, vsize;

  mp_ptr ap, qp, rp;
  mp_size_t asize, bsize, qsize, rsize;
  mp_exp_t qexp;

  mp_size_t err, k;
  mp_limb_t tonearest;
  int inex, sh, can_round = 0, sign_quotient;
  unsigned int cc = 0, rw;

  TMP_DECL (marker);


  /**************************************************************************
   *                                                                        *
   *              This part of the code deals with special cases            *
   *                                                                        *
   **************************************************************************/

  if (MPFR_ARE_SINGULAR(u,v))
    {
      if (MPFR_IS_NAN(u) || MPFR_IS_NAN(v))
	{
	  MPFR_SET_NAN(q);
	  MPFR_RET_NAN;
	}
      sign_quotient = MPFR_MULT_SIGN( MPFR_SIGN(u) , MPFR_SIGN(v) );
      MPFR_SET_SIGN(q, sign_quotient);
      if (MPFR_IS_INF(u))
	{
	  if (MPFR_IS_INF(v))
	    {
	      MPFR_SET_NAN(q);
	      MPFR_RET_NAN;
	    }
	  else
	    {
	      MPFR_SET_INF(q);
	      MPFR_RET(0);
	    }
	}
      else if (MPFR_IS_INF(v))
	{
	  MPFR_SET_ZERO(q);
	  MPFR_RET(0);
	}
      else if (MPFR_IS_ZERO(v))
	{
	  if (MPFR_IS_ZERO(u))
	    {
	      MPFR_SET_NAN(q);
	      MPFR_RET_NAN;
	    }
	  else
	    {
	      MPFR_SET_INF(q);
	      MPFR_RET(0);
	    }
	}
      else
	{
	  MPFR_ASSERTD(MPFR_IS_ZERO(u));
	  MPFR_SET_ZERO(q);
	  MPFR_RET(0);
	}
    }
  MPFR_CLEAR_FLAGS(q);

  /**************************************************************************
   *                                                                        *
   *              End of the part concerning special values.                *
   *                                                                        *
   **************************************************************************/

  sign_quotient = MPFR_MULT_SIGN( MPFR_SIGN(u) , MPFR_SIGN(v) );
  up = MPFR_MANT(u);
  vp = MPFR_MANT(v);
  MPFR_SET_SIGN(q, sign_quotient);

  TMP_MARK (marker);
  usize = MPFR_LIMB_SIZE(u);
  vsize = MPFR_LIMB_SIZE(v);

  /**************************************************************************
   *                                                                        *
   *   First try to use only part of u, v. If this is not sufficient,       *
   *   use the full u and v, to avoid long computations eg. in the case     *
   *   u = v.                                                               *
   *                                                                        *
   **************************************************************************/

  /* The dividend is a, length asize. The divisor is b, length bsize. */

  qsize = (MPFR_PREC(q) + 3) / BITS_PER_MP_LIMB + 1;

  /* in case PREC(q)=PREC(v), then vsize=qsize with probability 1-4/b
     where b is the number of bits per limb */
  if (MPFR_LIKELY(vsize <= qsize))
    {
      bsize = vsize;
      bp = vp;
    }
  else /* qsize < vsize: take only the qsize high limbs of the divisor */
    {
      bsize = qsize;
      bp = (mp_srcptr) vp + (vsize - qsize);
    }

  /* we have {bp, bsize} * (1 + errb) = (true divisor)
     with 0 <= errb < 2^(-qsize*BITS_PER_MP_LIMB+1) */

  asize = bsize + qsize;
  ap = (mp_ptr) TMP_ALLOC (asize * BYTES_PER_MP_LIMB);
  /* if all arguments have same precision, then asize will be about 2*usize */
  if (MPFR_LIKELY(asize > usize))
    {
      /* copy u into the high limbs of {ap, asize}, and pad with zeroes */
      /* FIXME: could we copy only the qsize high limbs of the dividend? */
      MPN_COPY (ap + asize - usize, up, usize);
      MPN_ZERO (ap, asize - usize);
    }
  else /* truncate the high asize limbs of u into {ap, asize} */
    MPN_COPY (ap, up + usize - asize, asize);

  /* we have {ap, asize} = (true dividend) * (1 - erra)
     with 0 <= erra < 2^(-asize*BITS_PER_MP_LIMB).
     This {ap, asize} / {bp, bsize} =
     (true dividend) / (true divisor) * (1 - erra) (1 + errb) */

  /* Allocate limbs for quotient and remainder. */
  qp = (mp_ptr) TMP_ALLOC ((qsize + 1) * BYTES_PER_MP_LIMB);
  rp = (mp_ptr) TMP_ALLOC (bsize * BYTES_PER_MP_LIMB);
  rsize = bsize;

  mpn_tdiv_qr (qp, rp, 0, ap, asize, bp, bsize);
  sh = - (int) qp[qsize];
  /* since u and v are normalized, sh is 0 or -1 */

  /* we have {qp, qsize + 1} = {ap, asize} / {bp, bsize} (1 - errq)
     with 0 <= errq < 2^(-qsize*BITS_PER_MP_LIMB+1+sh)
     thus {qp, qsize + 1} =
     (true dividend) / (true divisor) * (1 - erra) (1 + errb) (1 - errq).
     
     In fact, since the truncated dividend and {rp, bsize} do not overlap,
     we have: {qp, qsize + 1} =
     (true dividend) / (true divisor) * (1 - erra') (1 + errb)
     where 0 <= erra' < 2^(-qsize*BITS_PER_MP_LIMB+sh) */

  /* Estimate number of correct bits. */

  err = qsize * BITS_PER_MP_LIMB;

  /* We want to check if rounding is possible, but without normalizing
     because we might have to divide again if rounding is impossible, or
     if the result might be exact. We have however to mimic normalization */

  /*
     To detect asap if the result is inexact, so as to avoid doing the
     division completely, we perform the following check :

     - if rnd_mode != GMP_RNDN, and the result is exact, we are unable
     to round simultaneously to zero and to infinity ;

     - if rnd_mode == GMP_RNDN, and if we can round to zero with one extra
     bit of precision, we can decide rounding. Hence in that case, check
     as in the case of GMP_RNDN, with one extra bit. Note that in the case
     of close to even rounding we shall do the division completely, but
     this is necessary anyway : we need to know whether this is really
     even rounding or not.
  */

  if (MPFR_UNLIKELY(asize < usize || bsize < vsize))
    {
      {
	mp_rnd_t  rnd_mode1, rnd_mode2;
	mp_exp_t  tmp_exp;
	mp_prec_t tmp_prec;

        if (bsize < vsize)
          err -= 2; /* divisor is truncated */
#if 0 /* commented this out since the truncation of the dividend is already
         taken into account in {rp, bsize}, which does not overlap with the
         neglected part of the dividend */
        else if (asize < usize)
          err --;   /* dividend is truncated */
#endif

	if (MPFR_LIKELY(rnd_mode == GMP_RNDN))
	  {
	    rnd_mode1 = GMP_RNDZ;
	    rnd_mode2 = MPFR_IS_POS_SIGN(sign_quotient) ? GMP_RNDU : GMP_RNDD;
	    sh++;
	  }
	else
	  {
	    rnd_mode1 = rnd_mode;
	    switch (rnd_mode)
	      {
	      case GMP_RNDU:
		rnd_mode2 = GMP_RNDD; break;
	      case GMP_RNDD:
		rnd_mode2 = GMP_RNDU; break;
	      default:
		rnd_mode2 = MPFR_IS_POS_SIGN(sign_quotient) ?
		  GMP_RNDU : GMP_RNDD;
		break;
	      }
	  }

	tmp_exp  = err + sh + BITS_PER_MP_LIMB;
	tmp_prec = MPFR_PREC(q) + sh + BITS_PER_MP_LIMB;
	
	can_round =
	  mpfr_can_round_raw (qp, qsize + 1, sign_quotient, tmp_exp,
                              GMP_RNDN, rnd_mode1, tmp_prec)
	  & mpfr_can_round_raw (qp, qsize + 1, sign_quotient, tmp_exp,
                                GMP_RNDN, rnd_mode2, tmp_prec);

        /* restore original value of sh, i.e. sh = - qp[qsize] */
	sh -= (rnd_mode == GMP_RNDN);
      }

      /* If can_round is 0, either we cannot round or
	 the result might be exact. If asize >= usize and bsize >= vsize, we
	 can just check this by looking at the remainder. Otherwise, we
	 have to correct our first approximation. */

      if (MPFR_UNLIKELY(!can_round))
	{
	  mp_ptr rem, rem2;

  /**************************************************************************
   *                                                                        *
   *   The attempt to use only part of u and v failed. We first compute a   *
   *   correcting term, then perform the full division.                     *
   *   Put u = uhi + ulo, v = vhi + vlo. We have uhi = vhi * qp + rp,       *
   *   thus u - qp * v = rp + ulo - qp * vlo, that we shall divide by v,    *
   *                                                                        *
   *   where ulo = 0 when asize >= usize, vlo = 0 when bsize >= vsize.      *
   *                                                                        *
   **************************************************************************/

	  rsize = qsize + 1 +
	    (usize - asize > vsize - bsize
	     ? usize - asize
	     : vsize - bsize);

      /*
	TODO : One operand is probably enough, but then we have to
	perform one further comparison (compute first vlo * q,
	try to substract r, try to substract ulo. Which is best ?
	NB : ulo and r do not overlap. Draw advantage of this
	[eg. HI(vlo*q) = r => compare LO(vlo*q) with b.]
      */

	  rem = (mp_ptr) TMP_ALLOC(rsize * BYTES_PER_MP_LIMB);
	  rem2 = (mp_ptr) TMP_ALLOC(rsize * BYTES_PER_MP_LIMB);

          /* FIXME: instead of padding with zeroes in {rem, rsize},
             subtract directly in the right place in {rem2, rsize} below */
	  if (bsize < vsize) /* then bsize = qsize */
	    {
	      /* Compute vlo * q */
	      if (qsize + 1 > vsize - bsize)
		mpn_mul (rem + rsize - vsize - 1,
			qp, qsize + 1, vp, vsize - bsize);
	      else
		mpn_mul (rem + rsize - vsize - 1,
			vp, vsize - bsize, qp, qsize + 1);
	      MPN_ZERO (rem, rsize - vsize - 1);
	    }
	  else
            MPN_ZERO (rem, rsize);

	  /* Compute ulo + r. The two of them do not overlap. */
	  MPN_COPY(rem2 + rsize - 1 - qsize, rp, bsize);

          /* since bsize = min(vsize, qsize), we have bsize <= qsize
             and thus bsize < qsize + 1 is always true */
          MPN_ZERO (rem2 + rsize - 1 - qsize + bsize, qsize + 1 - bsize);

	  if (asize < usize)
	    {
	      MPN_COPY (rem2 + rsize - 1 - qsize - usize + asize,
		       up, usize - asize);
	      MPN_ZERO (rem2, rsize - 1 - qsize - usize + asize);
	    }
	  else
	    MPN_ZERO (rem2, rsize - 1 - qsize);

	  /* the remainder is now {rem2, rsize} - {rem, rsize} */
          if (mpn_sub_n (rem, rem2, rem, rsize))
            {
              unsigned long b = 0;
	      /* Negative correction is at most 4, since
                 qp * vlo < 2*B^qsize * B^(vsize-bsize) <= 2*B^(rsize-1)
                 and vp >= 1/2*B^vsize.
                 In that case, necessarily rem[rsize-1] = 111...111.
              */
	      do
		{
		  b++;
                  rem[rsize - 1] += mpn_add_n (rem + rsize - vsize - 1,
                                  rem + rsize - vsize - 1, vp, vsize);
		}
	      while (rem[rsize - 1]);
              MPFR_ASSERTD(b <= 4);

	      qp[qsize] -= mpn_sub_1 (qp, qp, qsize, b);
            }

          sh = - (int) qp[qsize];
          /* since u and v are normalized, sh is 0 or -1 */

	  err = BITS_PER_MP_LIMB * qsize;
	  rp = rem;
	}
    }

  /**************************************************************************
   *                                                                        *
   *                       Final stuff (rounding and so.)                   *
   *  From now on : {qp, qsize+1} is the quotient, {rp, rsize} the remainder*
   *  with qp[qsize] <= 1.                                                  *
   **************************************************************************/

  qexp = MPFR_GET_EXP (u) - MPFR_GET_EXP (v);

  /* FIXME: instead of first shifting {qp, qsize} when qp[qsize]=1,
     then rounding it, first round it (with appropriate err and prec),
     and shift it afterwards, directly in MPFR_MANT(q) */

  if (qp[qsize] != 0)
    /* Hack : qp[qsize] is 0 or 1, hence if not 0, = 2^(qp[qsize] - 1). */
    {
      MPFR_ASSERTD(qp[qsize] == 1);
      tonearest = mpn_rshift (qp, qp, qsize, 1);
      qp[qsize - 1] |= MPFR_LIMB_HIGHBIT;
      qexp ++;
    }
  else
    {
      MPFR_ASSERTD(sh == 0);
      tonearest = 0;
    }

  cc = mpfr_round_raw_3 (qp, qp, err,
                         (MPFR_IS_NEG_SIGN(sign_quotient) ? 1 : 0),
                         MPFR_PREC(q), rnd_mode, &inex);

  /* cc = 0 if one must truncate {qp, qsize},
          1 if one must add one ulp */

  qp += qsize - MPFR_LIMB_SIZE(q); /* 0 or 1 */
  qsize = MPFR_LIMB_SIZE(q);

  /*
     At that point, either we were able to round from the beginning,
     and know thus that the result is inexact.

     Or we have performed a full division. In that case, we might still
     be wrong if both
     - the remainder is nonzero ;
     - we are rounding to infinity or to nearest (the nasty case of even
     rounding).
     - inex = 0, meaning that the non-significant bits of the quotients are 0,
     except when rounding to nearest (the nasty case of even rounding again).
  */

  if (MPFR_LIKELY(can_round == 0)) /* Lazy case. */
    {
      if (MPFR_UNLIKELY(inex == 0))
	{
	  k = rsize - 1;

	  /* If a bit has been shifted out during normalization, then
	     the remainder is nonzero. */
	  if (MPFR_LIKELY(tonearest == 0))
	    while (MPFR_UNLIKELY((k >= 0) && !(rp[k])))
	      k--;

	  if (MPFR_LIKELY(k >= 0)) /* Remainder is nonzero. */
	    {
	      if (MPFR_UNLIKELY(
		  MPFR_IS_RNDUTEST_OR_RNDDNOTTEST(rnd_mode,
				  MPFR_IS_POS_SIGN(sign_quotient))))
		/* Rounding to infinity. */
		{
		  inex = MPFR_FROM_SIGN_TO_INT( sign_quotient );
		  cc = 1;
		}
	      /* rounding to zero. */
	      else
		inex = -MPFR_FROM_SIGN_TO_INT( sign_quotient );
	    }
	}
      else /* We might have to correct an even rounding if remainder
	      is nonzero and if even rounding was towards 0. */
	if (MPFR_LIKELY(rnd_mode == GMP_RNDN) &&
	    MPFR_UNLIKELY(inex == MPFR_EVEN_INEX || inex == -MPFR_EVEN_INEX))
	  {
	    k = rsize - 1;

	  /* If a bit has been shifted out during normalization, hence
	     the remainder is nonzero. */
	    if (MPFR_LIKELY(tonearest == 0))
	      while (MPFR_UNLIKELY(((k >= 0) && !(rp[k]))))
		k--;

	    if (MPFR_LIKELY(k >= 0))
		     /* In fact the quotient is larger than expected */
	      {
		inex = MPFR_FROM_SIGN_TO_INT( sign_quotient );
		/* To infinity, finally. */
		cc = 1;
	      }
	  }
    }
	
  /* Final modification due to rounding */
  if (cc)
    {
      MPFR_UNSIGNED_MINUS_MODULO(sh, MPFR_PREC(q));
      cc = mpn_add_1 (MPFR_MANT(q), qp, qsize, MPFR_LIMB_ONE << sh);
      qp = MPFR_MANT(q);
      if (MPFR_UNLIKELY(cc))
        {
#if 0
          /* no need to shift since {qp, qsize} = 000...000 in that case */
          mpn_rshift (qp, qp, qsize, 1);
#endif
          qp[qsize - 1] = MPFR_LIMB_HIGHBIT;
          qexp++;
        }
    }
  else /* truncate */
    {
      MPN_COPY(MPFR_MANT(q), qp, qsize);
      qp = MPFR_MANT(q);
    }

  TMP_FREE (marker);

  rw = qsize * BITS_PER_MP_LIMB - MPFR_PREC(q);
  qp[0] &= ~((MPFR_LIMB_ONE << rw) - MPFR_LIMB_ONE);
  MPFR_EXP(q) = qexp;

  /* check for underflow/overflow */

  if (MPFR_UNLIKELY(qexp > __gmpfr_emax))
    inex = mpfr_set_overflow (q, rnd_mode, sign_quotient);
  else if (MPFR_UNLIKELY(qexp < __gmpfr_emin))
    {
      if (rnd_mode == GMP_RNDN && ((qexp < __gmpfr_emin - 1) ||
                                   (inex == 0 && mpfr_powerof2_raw (q))))
        rnd_mode = GMP_RNDZ;
      inex = mpfr_set_underflow (q, rnd_mode, sign_quotient);
    }

  MPFR_RET(inex);
}
