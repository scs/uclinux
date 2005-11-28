/* Test file for mpfr_set_exp.

Copyright 2004 Free Software Foundation.

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

int
main (int argc, char *argv[])
{
  mpfr_t x;
  int ret;

  tests_start_mpfr ();

  mpfr_init (x);

  mpfr_set_ui (x, 1, GMP_RNDN);
  ret = mpfr_set_exp (x, 2);
  MPFR_ASSERTN(ret == 0 && mpfr_cmp_ui (x, 2) == 0);

  set_emin (-1);
  ret = mpfr_set_exp (x, -1);
  MPFR_ASSERTN(ret == 0 && mpfr_cmp_ui_2exp (x, 1, -2) == 0);

  set_emax (1);
  ret = mpfr_set_exp (x, 1);
  MPFR_ASSERTN(ret == 0 && mpfr_cmp_ui (x, 1) == 0);

  ret = mpfr_set_exp (x, -2);
  MPFR_ASSERTN(ret != 0 && mpfr_cmp_ui (x, 1) == 0);

  ret = mpfr_set_exp (x, 2);
  MPFR_ASSERTN(ret != 0 && mpfr_cmp_ui (x, 1) == 0);

  mpfr_clear (x);

  tests_end_mpfr ();
  return 0;
}
