/* udivmoddi4.c extracted from gcc-2.95.3/libgcc2.c 
 * and gcc-2.95.3/longlong.h which are:  */
/* Copyright (C) 1989, 92-98, 1999 Free Software Foundation, Inc.

This file is part of GNU CC.

GNU CC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU CC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU CC; see the file COPYING.  If not, write to
the Free Software Foundation, 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#define BITS_PER_UNIT 8

typedef unsigned int UQItype	__attribute__ ((mode (QI)));
typedef 	 int SItype	__attribute__ ((mode (SI)));
typedef unsigned int USItype	__attribute__ ((mode (SI)));
typedef		 int DItype	__attribute__ ((mode (DI)));
typedef unsigned int UDItype	__attribute__ ((mode (DI)));

#define SI_TYPE_SIZE (sizeof (SItype) * BITS_PER_UNIT)

struct DIstruct {SItype high, low;};

typedef union
{
  struct DIstruct s;
  DItype ll;
} DIunion;

#define sub_ddmmss(sh, sl, ah, al, bh, bl) \
  __asm__ ("sub%.l %5,%1		      \n\
	subx%.l %3,%0"                          \
       : "=d" ((USItype) (sh)),                 \
         "=&d" ((USItype) (sl))                 \
       : "0" ((USItype) (ah)),                  \
         "d" ((USItype) (bh)),                  \
         "1" ((USItype) (al)),                  \
         "g" ((USItype) (bl)))

#if !(defined(__mcf5200__) || defined(__mcoldfire__))
/* %/ inserts REGISTER_PREFIX, %# inserts IMMEDIATE_PREFIX.  */
#define umul_ppmm(xh, xl, a, b) \
  __asm__ ("| Inlined umul_ppmm               \n\
    move%.l %2,%/d0                           \n\
    move%.l %3,%/d1                           \n\
    move%.l %/d0,%/d2                         \n\
    swap    %/d0                              \n\
    move%.l %/d1,%/d3                         \n\
    swap    %/d1                              \n\
    move%.w %/d2,%/d4                         \n\
    mulu    %/d3,%/d4                         \n\
    mulu    %/d1,%/d2                         \n\
    mulu    %/d0,%/d3                         \n\
    mulu    %/d0,%/d1                         \n\
    move%.l %/d4,%/d0                         \n\
    eor%.w  %/d0,%/d0                         \n\
    swap    %/d0                              \n\
    add%.l  %/d0,%/d2                         \n\
    add%.l  %/d3,%/d2                         \n\
    jcc 1f                                    \n\
    add%.l  %#65536,%/d1                      \n\
1:  swap    %/d2                              \n\
    moveq   %#0,%/d0                          \n\
    move%.w %/d2,%/d0                         \n\
    move%.w %/d4,%/d2                         \n\
    move%.l %/d2,%1                           \n\
    add%.l  %/d1,%/d0                         \n\
    move%.l %/d0,%0"                            \
       : "=g" ((USItype) (xh)),                 \
         "=g" ((USItype) (xl))                  \
       : "g" ((USItype) (a)),                   \
         "g" ((USItype) (b))                    \
       : "d0", "d1", "d2", "d3", "d4")
#define UMUL_TIME 100
#define UDIV_TIME 400
#endif /* not (mcf5200 || mcoldfire) */

#if !defined (udiv_qrnnd)
#define UDIV_NEEDS_NORMALIZATION 1
#define udiv_qrnnd __udiv_qrnnd_c
#endif

#define __BITS4 (SI_TYPE_SIZE / 4)
#define __ll_B (1L << (SI_TYPE_SIZE / 2))
#define __ll_lowpart(t) ((USItype) (t) % __ll_B)
#define __ll_highpart(t) ((USItype) (t) / __ll_B)

#if !defined (count_leading_zeros)
extern const UQItype __clz_tab[];
#define count_leading_zeros(count, x) \
  do {                                  \
    USItype __xr = (x);                         \
    USItype __a;                            \
                                    \
    if (SI_TYPE_SIZE <= 32)                     \
      {                                 \
    __a = __xr < ((USItype)1<<2*__BITS4)                \
      ? (__xr < ((USItype)1<<__BITS4) ? 0 : __BITS4)        \
      : (__xr < ((USItype)1<<3*__BITS4) ?  2*__BITS4 : 3*__BITS4);  \
      }                                 \
    else                                \
      {                                 \
    for (__a = SI_TYPE_SIZE - 8; __a > 0; __a -= 8)         \
      if (((__xr >> __a) & 0xff) != 0)              \
        break;                          \
      }                                 \
                                    \
    (count) = SI_TYPE_SIZE - (__clz_tab[__xr >> __a] + __a);        \
  } while (0)
#endif

#define __udiv_qrnnd_c(q, r, n1, n0, d) \
  do {                                  \
    USItype __d1, __d0, __q1, __q0;                 \
    USItype __r1, __r0, __m;                        \
    __d1 = __ll_highpart (d);                       \
    __d0 = __ll_lowpart (d);                        \
                                    \
    __r1 = (n1) % __d1;                         \
    __q1 = (n1) / __d1;                         \
    __m = (USItype) __q1 * __d0;                    \
    __r1 = __r1 * __ll_B | __ll_highpart (n0);              \
    if (__r1 < __m)                         \
      {                                 \
    __q1--, __r1 += (d);                        \
    if (__r1 >= (d)) /* i.e. we didn't get carry when adding to __r1 */\
      if (__r1 < __m)                       \
        __q1--, __r1 += (d);                    \
      }                                 \
    __r1 -= __m;                            \
                                    \
    __r0 = __r1 % __d1;                         \
    __q0 = __r1 / __d1;                         \
    __m = (USItype) __q0 * __d0;                    \
    __r0 = __r0 * __ll_B | __ll_lowpart (n0);               \
    if (__r0 < __m)                         \
      {                                 \
    __q0--, __r0 += (d);                        \
    if (__r0 >= (d))                        \
      if (__r0 < __m)                       \
        __q0--, __r0 += (d);                    \
      }                                 \
    __r0 -= __m;                            \
                                    \
    (q) = (USItype) __q1 * __ll_B | __q0;               \
    (r) = __r0;                             \
  } while (0)

#if !defined (umul_ppmm)
#define umul_ppmm(w1, w0, u, v)                     \
  do {                                  \
    USItype __x0, __x1, __x2, __x3;                 \
    USItype __ul, __vl, __uh, __vh;                 \
                                    \
    __ul = __ll_lowpart (u);                        \
    __uh = __ll_highpart (u);                       \
    __vl = __ll_lowpart (v);                        \
    __vh = __ll_highpart (v);                       \
                                    \
    __x0 = (USItype) __ul * __vl;                   \
    __x1 = (USItype) __ul * __vh;                   \
    __x2 = (USItype) __uh * __vl;                   \
    __x3 = (USItype) __uh * __vh;                   \
                                    \
    __x1 += __ll_highpart (__x0);/* this can't give carry */        \
    __x1 += __x2;       /* but this indeed can */       \
    if (__x1 < __x2)        /* did we get it? */            \
      __x3 += __ll_B;       /* yes, add it in the proper pos. */    \
                                    \
    (w1) = __x3 + __ll_highpart (__x1);                 \
    (w0) = __ll_lowpart (__x1) * __ll_B + __ll_lowpart (__x0);      \
  } while (0)
#endif


static const UQItype __clz_tab[] =
{
  0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
  6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
  8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
};

UDItype
__udivmoddi4 (UDItype n, UDItype d, UDItype *rp)
{
  DIunion ww;
  DIunion nn, dd;
  DIunion rr;
  USItype d0, d1, n0, n1, n2;
  USItype q0, q1;
  USItype b, bm;

  nn.ll = n;
  dd.ll = d;

  d0 = dd.s.low;
  d1 = dd.s.high;
  n0 = nn.s.low;
  n1 = nn.s.high;

#if !UDIV_NEEDS_NORMALIZATION
  if (d1 == 0)
    {
      if (d0 > n1)
	{
	  /* 0q = nn / 0D */

	  udiv_qrnnd (q0, n0, n1, n0, d0);
	  q1 = 0;

	  /* Remainder in n0.  */
	}
      else
	{
	  /* qq = NN / 0d */

	  if (d0 == 0)
	    d0 = 1 / d0;	/* Divide intentionally by zero.  */

	  udiv_qrnnd (q1, n1, 0, n1, d0);
	  udiv_qrnnd (q0, n0, n1, n0, d0);

	  /* Remainder in n0.  */
	}

      if (rp != 0)
	{
	  rr.s.low = n0;
	  rr.s.high = 0;
	  *rp = rr.ll;
	}
    }

#else /* UDIV_NEEDS_NORMALIZATION */

  if (d1 == 0)
    {
      if (d0 > n1)
	{
	  /* 0q = nn / 0D */

	  count_leading_zeros (bm, d0);

	  if (bm != 0)
	    {
	      /* Normalize, i.e. make the most significant bit of the
		 denominator set.  */

	      d0 = d0 << bm;
	      n1 = (n1 << bm) | (n0 >> (SI_TYPE_SIZE - bm));
	      n0 = n0 << bm;
	    }

	  udiv_qrnnd (q0, n0, n1, n0, d0);
	  q1 = 0;

	  /* Remainder in n0 >> bm.  */
	}
      else
	{
	  /* qq = NN / 0d */

	  if (d0 == 0)
	    d0 = 1 / d0;	/* Divide intentionally by zero.  */

	  count_leading_zeros (bm, d0);

	  if (bm == 0)
	    {
	      /* From (n1 >= d0) /\ (the most significant bit of d0 is set),
		 conclude (the most significant bit of n1 is set) /\ (the
		 leading quotient digit q1 = 1).

		 This special case is necessary, not an optimization.
		 (Shifts counts of SI_TYPE_SIZE are undefined.)  */

	      n1 -= d0;
	      q1 = 1;
	    }
	  else
	    {
	      /* Normalize.  */

	      b = SI_TYPE_SIZE - bm;

	      d0 = d0 << bm;
	      n2 = n1 >> b;
	      n1 = (n1 << bm) | (n0 >> b);
	      n0 = n0 << bm;

	      udiv_qrnnd (q1, n1, n2, n1, d0);
	    }

	  /* n1 != d0...  */

	  udiv_qrnnd (q0, n0, n1, n0, d0);

	  /* Remainder in n0 >> bm.  */
	}

      if (rp != 0)
	{
	  rr.s.low = n0 >> bm;
	  rr.s.high = 0;
	  *rp = rr.ll;
	}
    }
#endif /* UDIV_NEEDS_NORMALIZATION */

  else
    {
      if (d1 > n1)
	{
	  /* 00 = nn / DD */

	  q0 = 0;
	  q1 = 0;

	  /* Remainder in n1n0.  */
	  if (rp != 0)
	    {
	      rr.s.low = n0;
	      rr.s.high = n1;
	      *rp = rr.ll;
	    }
	}
      else
	{
	  /* 0q = NN / dd */

	  count_leading_zeros (bm, d1);
	  if (bm == 0)
	    {
	      /* From (n1 >= d1) /\ (the most significant bit of d1 is set),
		 conclude (the most significant bit of n1 is set) /\ (the
		 quotient digit q0 = 0 or 1).

		 This special case is necessary, not an optimization.  */

	      /* The condition on the next line takes advantage of that
		 n1 >= d1 (true due to program flow).  */
	      if (n1 > d1 || n0 >= d0)
		{
		  q0 = 1;
		  sub_ddmmss (n1, n0, n1, n0, d1, d0);
		}
	      else
		q0 = 0;

	      q1 = 0;

	      if (rp != 0)
		{
		  rr.s.low = n0;
		  rr.s.high = n1;
		  *rp = rr.ll;
		}
	    }
	  else
	    {
	      USItype m1, m0;
	      /* Normalize.  */

	      b = SI_TYPE_SIZE - bm;

	      d1 = (d1 << bm) | (d0 >> b);
	      d0 = d0 << bm;
	      n2 = n1 >> b;
	      n1 = (n1 << bm) | (n0 >> b);
	      n0 = n0 << bm;

	      udiv_qrnnd (q0, n1, n2, n1, d1);
	      umul_ppmm (m1, m0, q0, d0);

	      if (m1 > n1 || (m1 == n1 && m0 > n0))
		{
		  q0--;
		  sub_ddmmss (m1, m0, m1, m0, d1, d0);
		}

	      q1 = 0;

	      /* Remainder in (n1n0 - m1m0) >> bm.  */
	      if (rp != 0)
		{
		  sub_ddmmss (n1, n0, n1, n0, m1, m0);
		  rr.s.low = (n1 << b) | (n0 >> bm);
		  rr.s.high = n1 >> bm;
		  *rp = rr.ll;
		}
	    }
	}
    }

  ww.s.low = q0;
  ww.s.high = q1;
  return ww.ll;
}
