/************************************************************************
 *
 * float16.h
 *
 * (c) Copyright 1996-2003 Analog Devices, Inc.
 * This file is subject to the terms and conditions of the GNU Library General
 * Public License. See the file "COPYING.LIB" in the main directory of this
 * archive for more details.
 *
 * Non-LGPL License also available as part of VisualDSP++
 * http://www.analog.com/processors/resources/crosscore/visualDspDevSoftware.html
 *
 *
 ************************************************************************/

/*
** C prototype functions for C++ float16 class.
** float16 is a 32-bit type. Exponent is low-half.
** Mantissa is high half:
** s mmm mmmm mmmm mmmm s eee eeee eeee eeee
** Exponent is unbiased, and there is no hidden bit;
** numbers are normalised to 0.x, not 1.x.
*/

#ifndef _FLOAT16_H
#define _FLOAT16_H

#ifdef _FLOAT16_NO_INLINE

typedef long float16;

#else

typedef union {
		long l;			/* for simple initialisations  */
		unsigned long u;	/* for conversions             */
		struct {
			short e;	/* low half                    */     
			short m;	/* high half                   */
		} s;
		float f;		/* for conversions             */       
} float16;

#endif /* _FLOAT16_NO_INLINE */

#include <fract.h>

#define PlusInf_fl16	0x7fffffff
#define NegInf_fl16	0x8000ffff
#define NaN_fl16	0x00008000

#ifdef _FLOAT16_NO_INLINE

#ifdef __cplusplus
extern "C" {
#endif

float16 fr16_to_fl16(fract16);
fract16 fl16_to_fr16(float16);
float16 norm_fl16(float16);
float16 add_fl16(float16, float16);
float16 sub_fl16(float16, float16);
float16 mul_fl16(float16, float16);
float16 div_fl16(float16, float16);
float16 negate_fl16(float16);
float16 abs_fl16(float16);
int cmp_fl16(float16, float16);
float16 fl_to_fl16(float);
int fits_in_fl16(float);
float fl16_to_fl(float16);

#ifdef __cplusplus
}
#endif

#else

__inline float16
fr16_to_fl16(fract16 fr)
{
	float16 fl = { 0 };
	if (fr) {
		short exp = norm_fr1x16(fr);
		fl.s.e = -exp;
		fl.s.m = fr << exp;
	}
	return fl;
}

__inline fract16
fl16_to_fr16(float16 fl)
{
	fract16 fr = fl.s.m;
	short exp = fl.s.e;

	return shl_fr1x16(fr, exp);
}

static __inline float16
norm_fl16(float16 fl)
{
	if (fl.s.m) {
		short exp = norm_fr1x16(fl.s.m);
		fl.s.m <<= exp;
		fl.s.e -= exp;
	} else {
		fl.s.e = 0;
	}
	return fl;
}

__inline float16
add_fl16(float16 x, float16 y)
{
	int d = x.s.e - y.s.e;
	float16 fl = x, a = y;
	int xneg = x.l < 0;
	int yneg = y.l < 0;
	if (d < 0) {
		fl = y;
		a = x;
	}
	d = abs_fr1x32(d);
	fl.s.m += a.s.m >> d;
	/* check for overflow. Isn't a quick way of doing this in C. */
	if (xneg == yneg && xneg != (fl.l < 0)) {
		fl.s.m >>= 1;
		fl.s.m &= 0x7fff;	/* really want to rotate xneg in */
		fl.s.m |= xneg << 15;
		fl.s.e++;
	} else if (fl.s.m) {
		short exp = norm_fr1x16(fl.s.m);
		fl.s.m <<= exp;
		fl.s.e -= exp;
	} else {
		fl.s.e = 0;
	}
	return fl;
}

__inline float16
sub_fl16(float16 x, float16 y)
{
	int d = x.s.e - y.s.e;
	float16 fl = x, a = y;
	int xneg = x.l < 0;
	int yneg = y.l < 0;
	if (d < 0) {
		d = -d;
		fl.s.m >>= d;
		fl.s.e += d;
	} else {
		a.s.m >>= d;
	}
	fl.s.m -= a.s.m;
	/* check for overflow. Isn't a quick way of doing this in C. */
	if (xneg != yneg && yneg == (fl.l < 0)) {
		fl.s.m >>= 1;
		fl.s.m &= 0x7fff;	/* really want to rotate xneg in */
		fl.s.m |= xneg << 15;
		fl.s.e++;
	} else if (fl.s.m) {
		short exp = norm_fr1x16(fl.s.m);
		fl.s.m <<= exp;
		fl.s.e -= exp;
	} else {
		fl.s.e = 0;
	}
	return fl;
}

__inline float16
mul_fl16(float16 x, float16 y)
{
	float16 fl;

	fl.s.e  = x.s.e + y.s.e;
	fl.s.m = mult_fr1x16(x.s.m, y.s.m);
	if (fl.s.m) {
		short exp = norm_fr1x16(fl.s.m);
		fl.s.m <<= exp;
		fl.s.e -= exp;
	} else {
		fl.s.e = 0;
	}
	return fl;
}

__inline float16
div_fl16(float16 x, float16 y)
{
	int i;
	int niters = 15;
	const long one = 0x40000001;
	float16 fl;
	int xneg = x.l < 0;
	int yneg = y.l < 0;
	unsigned short r = 0;
	unsigned short d = x.s.m;
	unsigned short q = y.s.m;
	if (y.l == 0) {
		fl.l=NaN_fl16;
		return fl;
	}
	if (y.l == one)
		return x;
	if (x.l == y.l) {
		fl.l = one;
		return fl;
	}
	fl.s.e = x.s.e - y.s.e;
	if (xneg)
		d = -d;
	if (yneg)
		q = -q;
	for (i = 0; i < niters; i++) {
		if (q <= d) {
			d -= q;
			r |= 1;
		}
		d <<= 1;
		r <<= 1;
	}
	d = r;
	if (d & 0x8000) {
		/* overflow */
		d >>= 1;
		d &= 0x7fff;
		fl.s.e++;
	}
	if (xneg != yneg)
		d = -d;
	fl.s.m = d;	    /* truncation  */
	if (fl.s.m) {
		short exp = norm_fr1x16(fl.s.m);
		fl.s.m <<= exp;
		fl.s.e -= exp;
	} else {
		fl.s.e = 0;
	}
	return fl;
}

__inline float16
negate_fl16(float16 fl)
{
#if 0
	if (fl.s.m) {
		short exp;
		fl.s.m = -fl.s.m;
		exp = norm_fr1x16(fl.s.m);
		fl.s.m <<= exp;
		fl.s.e -= exp;
	} else {
		fl.s.e = 0;
	}
#else
	fl.s.m = -fl.s.m;
#endif
	return fl;
}

__inline float16
abs_fl16(float16 fl)
{
	fl.s.m = abs_fr1x16(fl.s.m);
	return fl;
}

__inline int
cmp_fl16(float16 x, float16 y)
{
	/* x < y  => negative
	** x == y =>  0
	** x > y  => positive
	*/
	int neg = 0;
	int res;
	short resl, resh;
	int xneg = x.l < 0;	/* x.u & 0x80000000 might be faster */
	int yneg = y.l < 0;

	/* If both are negative, compare and negate.
	** If both positive, just compare.
	** If signs differ, return 1, with sign of x.
	*/
	
	if (xneg == yneg)
		neg = xneg;
	else
		return (xneg << 31) | 1;

	resh = sub_fr1x16(x.s.m, y.s.m);
	resl = sub_fr1x16(x.s.e, y.s.e);
	if (resl == 0)
		resl = resh;
	res = resl;
	if (neg)
		res = -res;
	return res;
}

__inline float16
fl_to_fl16(float f)
{
	float16 fl;
	unsigned long sign, uexp;
	long exp;
	fl.f = f;
	if ((fl.u << 1) == 0) {
		/* -0.0 or +0.0 - needs special handling */
		fl.u = 0;
		return fl;
	}
	sign = (fl.u >> 31) << 31;
	uexp = (fl.u << 1) >> 24;
	exp = uexp - 127;
	exp += 1;	/* because we have to include the hidden bit */
	fl. u |= (1<<23);	/* add the hidden bit */
	fl.u <<= 8;	/* move 24-bit mantissa to top, to remove exp & sign */
	fl.u >>= 1;	/* back one space, for sign */
#ifdef DEBUG
	if (fl.s.e)
		printf("Warning: precision lost %08x\n", fl.s.e);
#endif
	fl.s.e = exp;
	if (sign)
		fl.s.m = -fl.s.m;
	return fl;
}

__inline int
fits_in_fl16(float f)
{
	float16 fl;
	fl.f = f;
	return (fl.u & 0xff) == 0;
}

__inline float
fl16_to_fl(float16 fl)
{
	unsigned long exp, sign;
	if (fl.u == 0)
		return fl.f;
	sign = (fl.u >> 31) << 31;
	exp = (fl.s.e + 127 - 1);	/* remove one, for hidden bit */
	if ((fl.s.m & 0xffff) == 0x8000) {
		fl.s.m = 0x4000;
		exp++;
	} else if (sign) {
		fl.s.m = -fl.s.m;
	}
	fl.s.e = 0;
	fl.u <<= 2;	/* remove sign bit and hidden bit*/
	fl.u >>= 9;
	exp <<= 23;
	fl.u = sign | exp | fl.u;
	return fl.f;
}

#endif /*  NO_INLINE */

#endif /* _FLOAT16_H */
