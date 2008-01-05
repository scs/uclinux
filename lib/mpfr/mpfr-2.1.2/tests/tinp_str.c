/* Test file for mpfr_inp_str.

Copyright 2004 Free Software Foundation, Inc.

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
  FILE *f;
  int i;
  tests_start_mpfr ();

  mpfr_init (x);

  mpfr_set_prec (x, 15);
  f = src_fopen ("inp_str.data", "r");
  if (f == NULL)
    {
      printf ("Error, can't open inp_str.data\n");
      exit (1);
    }
  i = mpfr_inp_str (x, f, 10, GMP_RNDN);
  if (i == 0 || mpfr_cmp_ui (x, 31415))
    {
      printf ("Error in reading 1st line from file inp_str.data\n");
      exit (1);
    }
  getc (f);
  i = mpfr_inp_str (x, f, 10, GMP_RNDN);
  if ((i == 0) || mpfr_cmp_ui (x, 31416))
    {
      printf ("Error in reading 2nd line from file inp_str.data\n");
      exit (1);
    }
  getc (f);
  i = mpfr_inp_str (x, f, 10, GMP_RNDN);
  if (i != 0)
    {
      printf ("Error in reading 3rd line from file inp_str.data\n");
      exit (1);
    }
  fclose (f);
  
  mpfr_clear (x);

  tests_end_mpfr ();
  return 0;
}
