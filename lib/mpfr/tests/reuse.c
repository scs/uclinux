/* Test file for in-place operations.

Copyright 2000, 2001, 2002, 2003, 2004 Free Software Foundation.

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

#define DISP(s, t) {printf(s); mpfr_out_str(stdout, 10, 0, t, GMP_RNDN); }
#define DISP2(s,t) {DISP(s,t); putchar('\n');}

/* same than mpfr_cmp, but returns 0 for both NaN's */
static int
mpfr_compare (mpfr_srcptr a, mpfr_srcptr b)
{
  return (MPFR_IS_NAN(a)) ? !MPFR_IS_NAN(b) :
    (MPFR_IS_NAN(b) || mpfr_cmp(a, b));
}

static void
mpfr_set_pos_zero(mpfr_t a)
{
  MPFR_SET_ZERO(a);
  MPFR_SET_POS(a);
}

static void
mpfr_set_neg_zero(mpfr_t a)
{
  MPFR_SET_ZERO(a);
  MPFR_SET_NEG(a);
}

static void
test3 (int (*testfunc)(mpfr_ptr, mpfr_srcptr, mpfr_srcptr, mp_rnd_t),
       char *foo, mp_prec_t prec, mp_rnd_t rnd)
{
  mpfr_t ref1, ref2, ref3;
  mpfr_t res1;
  int i;

#ifdef DEBUG
  printf("checking %s\n", foo);
#endif
  mpfr_init2 (ref1, prec);
  mpfr_init2 (ref2, prec);
  mpfr_init2 (ref3, prec);
  mpfr_init2 (res1, prec);

  /* for each variable, consider each of the following 6 possibilities:
     NaN, +Infinity, -Infinity, +0, -0 or a random number */
  for (i=0; i<36; i++) {
    if (i%6==0) mpfr_set_nan (ref2);
    if (i%6==1) mpfr_set_inf (ref2, 1);
    if (i%6==2) mpfr_set_inf (ref2, -1);
    if (i%6==3) mpfr_set_pos_zero (ref2);
    if (i%6==4) mpfr_set_neg_zero (ref2);
    if (i%6==5) mpfr_random (ref2);

    if (i/6==0) mpfr_set_nan (ref3);
    if (i/6==1) mpfr_set_inf (ref3, 1);
    if (i/6==2) mpfr_set_inf (ref3, -1);
    if (i/6==3) mpfr_set_pos_zero (ref3);
    if (i/6==4) mpfr_set_neg_zero (ref3);
    if (i/6==5) mpfr_random (ref3);

    /* reference call: foo(a, b, c) */
    testfunc (ref1, ref2, ref3, rnd);

    /* foo(a, a, c) */
    mpfr_set (res1, ref2, rnd); /* exact operation */
    testfunc (res1, res1, ref3, rnd);

    if (mpfr_compare (res1, ref1))
      {
        printf ("Error for %s(a, a, c) for ", foo);
	DISP("a=",ref2); DISP2(", c=",ref3);
        printf ("expected "); mpfr_print_binary (ref1); puts ("");
        printf ("got      "); mpfr_print_binary (res1); puts ("");
        exit (1);
      }

    /* foo(a, b, a) */
    mpfr_set (res1, ref3, rnd);
    testfunc (res1, ref2, res1, rnd);
    if (mpfr_compare (res1, ref1))
      {
        printf ("Error for %s(a, b, a) for ", foo);
	DISP("b=",ref2); DISP2(", a=", ref3);
	DISP("expected ", ref1); DISP2(", got ",res1);
        exit (1);
      }

    /* foo(a, a, a) */
    mpfr_set (ref3, ref2, rnd);
    testfunc (ref1, ref2, ref3, rnd);
    mpfr_set (res1, ref2, rnd);
    testfunc (res1, res1, res1, rnd);

    if (mpfr_compare (res1, ref1))
      {
        printf ("Error for %s(a, a, a) for ", foo);
	DISP2("a=",ref2);
	DISP("expected ", ref1); DISP2(", got", res1);
        exit (1);
      }
  }

  mpfr_clear (ref1);
  mpfr_clear (ref2);
  mpfr_clear (ref3);
  mpfr_clear (res1);
}

static void
test4 (int (*testfunc)(mpfr_ptr, mpfr_srcptr, mpfr_srcptr, mpfr_srcptr,
                       mp_rnd_t),
       char *foo, mp_prec_t prec, mp_rnd_t rnd)
{
  mpfr_t ref, op1, op2, op3;
  mpfr_t res;
  int i, j, k;

#ifdef DEBUG
  printf("checking %s\n", foo);
#endif
  mpfr_init2 (ref, prec);
  mpfr_init2 (op1, prec);
  mpfr_init2 (op2, prec);
  mpfr_init2 (op3, prec);
  mpfr_init2 (res, prec);

  /* for each variable, consider each of the following 6 possibilities:
     NaN, +Infinity, -Infinity, +0, -0 or a random number */

  for (i=0; i<6; i++)
    {
      MPFR_CLEAR_FLAGS(op1);
      if (i==0) mpfr_set_nan (op1);
      if (i==1) mpfr_set_inf (op1, 1);
      if (i==2) mpfr_set_inf (op1, -1);
      if (i==3) mpfr_set_pos_zero (op1);
      if (i==4) mpfr_set_neg_zero (op1);
      if (i==5) mpfr_random (op1);

      for (j=0; j<6; j++)
        {
          MPFR_CLEAR_FLAGS(op2);
          if (j==0) mpfr_set_nan (op2);
          if (j==1) mpfr_set_inf (op2, 1);
          if (j==2) mpfr_set_inf (op2, -1);
          if (j==3) mpfr_set_pos_zero (op2);
          if (j==4) mpfr_set_neg_zero (op2);
          if (j==5) mpfr_random (op2);

          for (k=0; k<6; k++)
            {
              MPFR_CLEAR_FLAGS(op3);
              if (k==0) mpfr_set_nan (op3);
              if (k==1) mpfr_set_inf (op3, 1);
              if (k==2) mpfr_set_inf (op3, -1);
              if (k==3) mpfr_set_pos_zero (op3);
              if (k==4) mpfr_set_neg_zero (op3);
              if (k==5) mpfr_random (op3);

              /* reference call: foo(s, a, b, c) */
              testfunc (ref, op1, op2, op3, rnd);

              /* foo(a, a, b, c) */
              mpfr_set (res, op1, rnd); /* exact operation */
              testfunc (res, res, op2, op3, rnd);

              if (mpfr_compare (res, ref))
                {
                  printf ("Error for %s(a, a, b, c) for ", foo);
		  DISP("a=", op1); DISP(", b=", op2); DISP2(", c=", op3);
		  DISP("expected ", ref); DISP2(", got", res);
                  exit (1);
                }

              /* foo(b, a, b, c) */
              mpfr_set (res, op2, rnd);
              testfunc (res, op1, res, op3, rnd);

              if (mpfr_compare (res, ref))
                {
                  printf ("Error for %s(a, a, b, c) for ", foo);
                  DISP("a=", op1); DISP(", b=", op2); DISP2(", c=", op3);
                  DISP("expected ", ref); DISP2(", got", res);
                  exit (1);
                }

              /* foo(c, a, b, c) */
              mpfr_set (res, op3, rnd);
              testfunc (res, op1, op2, res, rnd);

              if (mpfr_compare (res, ref))
                {
                  printf ("Error for %s(a, a, b, c) for ", foo);
                  DISP("a=", op1); DISP(", b=", op2); DISP2(", c=", op3);
                  DISP("expected ", ref); DISP2(", got", res);
                  exit (1);
                }

              /* foo(a, a, a,c) */
              testfunc (ref, op1, op1, op3, rnd);
              mpfr_set (res, op1, rnd);
              testfunc (res, res, res, op3, rnd);
              if (mpfr_compare (res, ref))
                {
                  printf ("Error for %s(a, a, b, c) for ", foo);
                  DISP("a=", op1); DISP(", a=", op2); DISP2(", c=", op3);
                  DISP("expected ", ref); DISP2(", got", res);
                  exit (1);
                }

              /* foo(a, a, b,a) */
              testfunc (ref, op1, op2, op1, rnd);
              mpfr_set (res, op1, rnd);
              testfunc (res, res, op2, res, rnd);
              if (mpfr_compare (res, ref))
                {
                  printf ("Error for %s(a, a, b, c) for ", foo);
                  DISP("a=", op1); DISP(", a=", op2); DISP2(", c=", op3);
                  DISP("expected ", ref); DISP2(", got", res);
                  exit (1);
                }

              /* foo(b, a, b, b) */
              testfunc (ref, op1, op2, op2, rnd);
              mpfr_set (res, op2, rnd);
              testfunc (res, op1, res, res, rnd);
              if (mpfr_compare (res, ref))
                {
                  printf ("Error for %s(a, a, b, c) for ", foo);
                  DISP("a=", op1); DISP(", a=", op2); DISP2(", c=", op3);
                  DISP("expected ", ref); DISP2(", got", res);
                  exit (1);
                }

              /* foo (a, a, a, a) */
              testfunc (ref, op1, op1, op1 ,rnd);
              mpfr_set (res, op1, rnd);
              testfunc (res, res, res, res, rnd);
              if (mpfr_compare (res, ref))
                {
                  printf ("Error for %s(a, a, a, a) for ", foo);
		  DISP2("a=", op1);
                  DISP("expected ", ref); DISP2(", got", res);
                  exit (1);
                }
            }
        }
    }

  mpfr_clear (ref);
  mpfr_clear (op1);
  mpfr_clear (op2);
  mpfr_clear (op3);
  mpfr_clear (res);

}

static void
test2ui (int (*testfunc)(mpfr_ptr, mpfr_srcptr, unsigned long int, mp_rnd_t),
         char *foo, mp_prec_t prec, mp_rnd_t rnd)
{
  mpfr_t ref1, ref2;
  unsigned int ref3;
  mp_limb_t c[1];
  mpfr_t res1;
  int i;

#ifdef DEBUG
  printf("checking %s\n", foo);
#endif
  mpfr_init2 (ref1, prec);
  mpfr_init2 (ref2, prec);
  mpfr_init2 (res1, prec);



  /* ref2 can be NaN, +Inf, -Inf, +0, -0 or any number
     ref3 can be 0 or any number */
  for (i=0; i<12; i++)
    {
      if (i%6==0) mpfr_set_nan (ref2);
      if (i%6==1) mpfr_set_inf (ref2, 1);
      if (i%6==2) mpfr_set_inf (ref2, -1);
      if (i%6==3) mpfr_set_pos_zero (ref2);
      if (i%6==4) mpfr_set_neg_zero (ref2);
      if (i%6==5) mpfr_random (ref2);

      if (i/6==0)
	ref3=0;
      else
	{
	  mpn_random (c, 1);
	  ref3 = (unsigned int) c[0];
	}

      /* reference call: foo(a, b, c) */
      testfunc (ref1, ref2, ref3, rnd);

      /* foo(a, a, c) */
      mpfr_set (res1, ref2, rnd); /* exact operation */
      testfunc (res1, res1, ref3, rnd);

      if (mpfr_compare (res1, ref1))
	{
	  printf ("Error for %s(a, a, c) for c=%u\n", foo, ref3);
	  DISP2("a=",ref2); 
          printf ("expected "); mpfr_print_binary (ref1); puts ("");
          printf ("got      "); mpfr_print_binary (res1); puts ("");
	  exit (1);
	}
    }

  mpfr_clear (ref1);
  mpfr_clear (ref2);
  mpfr_clear (res1);
}

static void
testui2 (int (*testfunc)(mpfr_ptr, unsigned long int, mpfr_srcptr, mp_rnd_t),
         char *foo, mp_prec_t prec, mp_rnd_t rnd)
{
  mpfr_t ref1, ref3;
  unsigned int ref2;
  mp_limb_t c[1];
  mpfr_t res1;
  int i;

#ifdef DEBUG
  printf("checking %s\n", foo);
#endif
  mpfr_init2 (ref1, prec);
  mpfr_init2 (ref3, prec);
  mpfr_init2 (res1, prec);
  mpfr_random (ref3);
  mpn_random (c, 1);
  ref2 = (unsigned int) c[0];

  for (i=0; i<12; i++) {
    if (i%6==0) mpfr_set_nan (ref3);
    if (i%6==1) mpfr_set_inf (ref3, 1);
    if (i%6==2) mpfr_set_inf (ref3, -1);
    if (i%6==3) mpfr_set_pos_zero (ref3);
    if (i%6==4) mpfr_set_neg_zero (ref3);
    if (i%6==5) mpfr_random (ref3);

    if (i/6==0) ref2=0;
    else {
      mpn_random (c, 1);
      ref2 = (unsigned int) c[0];
    }

    /* reference call: foo(a, b, c) */
    testfunc (ref1, ref2, ref3, rnd);

    /* foo(a, b, a) */
    mpfr_set (res1, ref3, rnd); /* exact operation */
    testfunc (res1, ref2, res1, rnd);
    if (mpfr_compare (res1, ref1))
      {
        printf ("Error for %s(a, b, a) for b=%u \n", foo, ref2);
	DISP2("a=", ref3);
	DISP("expected", ref1); DISP2(", got ", res1);
        exit (1);
      }
  }

  mpfr_clear (ref1);
  mpfr_clear (ref3);
  mpfr_clear (res1);
}

/* foo(mpfr_ptr, mpfr_srcptr, mp_rndt) */
static void
test2 (int (*testfunc)(mpfr_ptr, mpfr_srcptr, mp_rnd_t),
       char *foo, mp_prec_t prec, mp_rnd_t rnd)
{
  mpfr_t ref1, ref2;
  mpfr_t res1;
  int i;

#ifdef DEBUG
  printf("checking %s\n", foo);
#endif
  mpfr_init2 (ref1, prec);
  mpfr_init2 (ref2, prec);
  mpfr_init2 (res1, prec);
  mpfr_random (ref2);

  for (i=0; i<6; i++)
    {
      if (i==0) mpfr_set_nan (ref2);
      if (i==1) mpfr_set_inf (ref2, 1);
      if (i==2) mpfr_set_inf (ref2, -1);
      if (i==3) mpfr_set_pos_zero (ref2);
      if (i==4) mpfr_set_neg_zero (ref2);
      if (i==5) mpfr_random (ref2);

      /* reference call: foo(a, b) */
      testfunc (ref1, ref2, rnd);

      /* foo(a, a) */
      mpfr_set (res1, ref2, rnd); /* exact operation */
      testfunc (res1, res1, rnd);
      if (mpfr_compare (res1, ref1))
        {
          printf ("Error for %s(a, a) for ", foo);
	  DISP2("a=", ref2);
	  DISP("expected", ref1); DISP2(", got ", res1);
          exit (1);
        }
    }

  mpfr_clear (ref1);
  mpfr_clear (ref2);
  mpfr_clear (res1);
}

/* foo(mpfr_ptr, mpfr_srcptr) */
static void
test2a (int (*testfunc)(mpfr_ptr, mpfr_srcptr),
        char *foo, mp_prec_t prec)
{
  mpfr_t ref1, ref2;
  mpfr_t res1;
  int i;

#ifdef DEBUG
  printf ("checking %s\n", foo);
#endif
  mpfr_init2 (ref1, prec);
  mpfr_init2 (ref2, prec);
  mpfr_init2 (res1, prec);
  mpfr_random (ref2);

  for (i=0; i<6; i++)
    {
      if (i==0) mpfr_set_nan (ref2);
      if (i==1) mpfr_set_inf (ref2, 1);
      if (i==2) mpfr_set_inf (ref2, -1);
      if (i==3) mpfr_set_pos_zero (ref2);
      if (i==4) mpfr_set_neg_zero (ref2);
      if (i==5) mpfr_random (ref2);

      /* reference call: foo(a, b) */
      testfunc (ref1, ref2);

      /* foo(a, a) */
      mpfr_set (res1, ref2, GMP_RNDN); /* exact operation */
      testfunc (res1, res1);
      if (mpfr_compare (res1, ref1))
        {
          printf ("Error for %s(a, a) for ", foo);
	  DISP2("a=",ref2);
	  DISP("expected", ref1); DISP2(", got ", res1);
          exit (1);
        }
    }

  mpfr_clear (ref1);
  mpfr_clear (ref2);
  mpfr_clear (res1);
}

#if 0

/* one operand, two results */
static void
test3a (char *foo, mp_prec_t prec, mp_rnd_t rnd)
{
  mpfr_t ref1, ref2, ref3;
  mpfr_t res1, res2;
  int i;

#ifdef DEBUG
  printf ("checking %s\n", foo);
#endif
  mpfr_init2 (ref1, prec);
  mpfr_init2 (ref2, prec);
  mpfr_init2 (ref3, prec);
  mpfr_init2 (res1, prec);
  mpfr_init2 (res2, prec);
  mpfr_random (ref3);

  for (i=0; i<6; i++)
    {
      if (i==0) mpfr_set_nan (ref3);
      if (i==1) mpfr_set_inf (ref3, 1);
      if (i==2) mpfr_set_inf (ref3, -1);
      if (i==3) mpfr_set_pos_zero (ref3);
      if (i==4) mpfr_set_neg_zero (ref3);
      if (i==5) mpfr_random (ref3);

      /* reference call: foo(a, b, c) */
      testfunc (ref1, ref2, ref3, rnd);

      /* foo(a, b, a) */
      mpfr_set (res1, ref3, rnd); /* exact operation */
      testfunc (res1, res2, res1, rnd);
      if (mpfr_compare (res1, ref1) || mpfr_compare (res2, ref2))
        {
          printf ("Error for %s(a, b, a) for ", foo);
	  DISP2("a=",ref3);
	  DISP("expected (", ref1); DISP(",",ref2);
	  DISP("), got (", res1); DISP(",", res2); printf(")\n");
          exit (1);
        }

      /* foo(a, b, b) */
      mpfr_set (res2, ref3, rnd); /* exact operation */
      testfunc (res1, res2, res2, rnd);
      if (mpfr_compare (res1, ref1) || mpfr_compare (res2, ref2))
        {
          printf ("Error for %s(a, b, b) for ", foo);
          DISP2("b=",ref3);
          DISP("expected (", ref1); DISP(",",ref2);
          DISP("), got (", res1); DISP(",", res2); printf(")\n");
          exit (1);
        }
    }

  mpfr_clear (ref1);
  mpfr_clear (ref2);
  mpfr_clear (ref3);
  mpfr_clear (res1);
  mpfr_clear (res2);
}

#endif

static int
reldiff_wrapper (mpfr_ptr a, mpfr_srcptr b, mpfr_srcptr c, mp_rnd_t rnd_mode)
{
  mpfr_reldiff (a, b, c, rnd_mode);
  return 0;
}

int
main (void)
{
  MPFR_TEST_USE_RANDS ();
  tests_start_mpfr ();

  test3 (mpfr_add, "mpfr_add", 53, GMP_RNDN);
  test2ui (mpfr_add_ui, "mpfr_add_ui", 53, GMP_RNDN);
  test3 (mpfr_agm, "mpfr_agm", 53, GMP_RNDN);
  test2a (mpfr_ceil, "mpfr_ceil", 53);
  test3 (mpfr_div, "mpfr_div", 53, GMP_RNDN);
  test2ui (mpfr_div_2exp, "mpfr_div_2exp", 53, GMP_RNDN);
  test2ui (mpfr_div_ui, "mpfr_div_ui", 53, GMP_RNDN);
  test2 (mpfr_exp, "mpfr_exp", 53, GMP_RNDN);
  test2a (mpfr_floor, "mpfr_floor", 53);
  test2 (mpfr_log, "mpfr_log", 53, GMP_RNDN);
  test3 (mpfr_mul, "mpfr_mul", 53, GMP_RNDN);
  test2ui (mpfr_mul_2exp, "mpfr_mul_2exp", 53, GMP_RNDN);
  test2ui (mpfr_mul_ui, "mpfr_mul_ui", 53, GMP_RNDN);
  test2 (mpfr_neg, "mpfr_neg", 53, GMP_RNDN);
  test2ui (mpfr_pow_ui, "mpfr_pow_ui", 53, GMP_RNDN);
  test3 (reldiff_wrapper, "mpfr_reldiff", 53, GMP_RNDN);
  test3 (mpfr_sub, "mpfr_sub", 53, GMP_RNDN);
  test2ui (mpfr_sub_ui, "mpfr_sub_ui", 53, GMP_RNDN);
  test2 (mpfr_sqrt, "mpfr_sqrt", 53, GMP_RNDN);
  testui2 (mpfr_ui_div, "mpfr_ui_div", 53, GMP_RNDN);
  testui2 (mpfr_ui_sub, "mpfr_ui_sub", 53, GMP_RNDN);
  test2a (mpfr_trunc, "mpfr_trunc", 53);
  test2 (mpfr_asin, "mpfr_asin", 53, GMP_RNDN);
  test2 (mpfr_acos, "mpfr_acos", 53, GMP_RNDN);
  test2 (mpfr_atan, "mpfr_atan", 53, GMP_RNDN);
  test2 (mpfr_sinh, "mpfr_sinh", 53, GMP_RNDN);
  test2 (mpfr_cosh, "mpfr_cosh", 53, GMP_RNDN);
  test2 (mpfr_tanh, "mpfr_tanh", 53, GMP_RNDN);
  test2 (mpfr_asinh, "mpfr_asinh", 53, GMP_RNDN);
  test2 (mpfr_acosh, "mpfr_acosh", 53, GMP_RNDN);
  test2 (mpfr_atanh, "mpfr_atanh", 53, GMP_RNDN);
  test2 (mpfr_exp2, "mpfr_exp2", 53, GMP_RNDN);
  test2 (mpfr_cos, "mpfr_cos", 53, GMP_RNDN);
  test2 (mpfr_sin, "mpfr_sin", 53, GMP_RNDN);
  test2 (mpfr_tan, "mpfr_tan", 53, GMP_RNDN);
  test2 (mpfr_log10, "mpfr_log10", 53, GMP_RNDN);
  test2 (mpfr_log2, "mpfr_log2", 53, GMP_RNDN);
  test2 (mpfr_zeta, "mpfr_zeta", 53, GMP_RNDN);
  test3 (mpfr_pow, "mpfr_pow", 53, GMP_RNDN);
  test4 (mpfr_fma, "mpfr_fma", 53, GMP_RNDN);

  tests_end_mpfr ();
  return 0;
}
