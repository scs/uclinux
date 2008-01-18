/* auxiliary functions for MPFR tests.

Copyright 1999, 2000, 2001, 2002, 2003, 2004 Free Software Foundation, Inc.

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

#ifndef __MPFR_TEST_H__
#define __MPFR_TEST_H__

#include <stdio.h>
#include "mpfr-impl.h"

/* generates a random long int, a random double,
   and corresponding seed initializing */
#define DBL_RAND() ((double) randlimb() / (double) MP_LIMB_T_MAX)

#define MINNORM 2.2250738585072013831e-308 /* 2^(-1022), smallest normalized */
#define MAXNORM 1.7976931348623157081e308 /* 2^(1023)*(2-2^(-52)) */

/* Generates a random rounding mode */
#define RND_RAND() (randlimb() % GMP_RND_MAX)

/* Generates a random sign */
#define SIGN_RAND() ( (randlimb()%2) ? MPFR_SIGN_POS : MPFR_SIGN_NEG)

/* Loop for all rounding modes */
#define RND_LOOP(_r) for((_r) = 0 ; (_r) < GMP_RND_MAX ; (_r)++)
 
/* The MAX, MIN and ABS macros may already be defined if gmp-impl.h has
   been included. They have the same semantics as in gmp-impl.h, but the
   expressions may be slightly different. So, it's better to undefine
   them first, as required by the ISO C standard. */
#undef MAX
#undef MIN
#undef ABS
#define MAX(a, b) (((a) > (b)) ? (a) : (b))
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define ABS(x) (((x)>0) ? (x) : -(x))

#if defined (__cplusplus)
extern "C" {
#endif

void tests_memory_start _MPFR_PROTO ((void));
void tests_memory_end _MPFR_PROTO ((void));

void tests_start_mpfr _MPFR_PROTO ((void));
void tests_end_mpfr _MPFR_PROTO ((void));

void tests_machine_prec_double _MPFR_PROTO ((void));
void tests_machine_prec_long_double _MPFR_PROTO ((void));

unsigned short x86_fstcw _MPFR_PROTO ((void));
void x86_fldcw _MPFR_PROTO ((unsigned short));

int mpfr_set_machine_rnd_mode _MPFR_PROTO ((mp_rnd_t));
void mpfr_test_init _MPFR_PROTO ((void));
mp_limb_t randlimb _MPFR_PROTO ((void));
void randseed _MPFR_PROTO ((unsigned int));
int ulp _MPFR_PROTO ((double, double));
double dbl _MPFR_PROTO ((double, int));
double Ulp _MPFR_PROTO ((double));
int Isnan _MPFR_PROTO ((double));
void d_trace _MPFR_PROTO ((const char *, double));
void ld_trace _MPFR_PROTO ((const char *, long double));

FILE *src_fopen _MPFR_PROTO ((const char *, const char *));
void set_emin _MPFR_PROTO ((mp_exp_t));
void set_emax _MPFR_PROTO ((mp_exp_t));

int mpfr_cmp_str _MPFR_PROTO ((mpfr_srcptr x, const char *, int, mp_rnd_t));
#define mpfr_cmp_str1(x,s) mpfr_cmp_str(x,s,10,GMP_RNDN)
#define mpfr_set_str1(x,s) mpfr_set_str(x,s,10,GMP_RNDN)

#ifndef MPFR_TEST_USE_RANDS
# define MPFR_TEST_USE_RANDS() ((void)0)
#endif

#if defined (__cplusplus)
}
#endif

#endif
