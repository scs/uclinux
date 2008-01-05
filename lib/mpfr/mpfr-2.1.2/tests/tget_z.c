/* Test file for mpz_set_fr / mpfr_get_z.

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

static void
check_one (mpz_ptr z)
{
  int    sh, neg;
  mpfr_t f;
  mpz_t  got;

  mpfr_init2 (f, MAX( mpz_sizeinbase (z, 2), MPFR_PREC_MIN) );
  mpz_init (got);

  for (sh = -2*BITS_PER_MP_LIMB ; sh < 2*BITS_PER_MP_LIMB ; sh++)
    {
      for (neg = 0; neg <= 1; neg++)
	{
	  mpz_neg (z, z);
	  mpfr_set_z (f, z, GMP_RNDN);  
	  
	  if (sh < 0)
	    {
	      mpz_tdiv_q_2exp (z, z, -sh);
	      mpfr_div_2exp (f, f, -sh, GMP_RNDN);
	    }
	  else
	    {
	      mpz_mul_2exp (z, z, sh);
	      mpfr_mul_2exp (f, f, sh, GMP_RNDN);
	    }

	  mpfr_get_z (got, f, GMP_RNDZ); 

	  if (mpz_cmp (got, z) != 0)
	    {
	      printf ("Wrong result for shift=%d\n", sh);
	      printf ("     f "); mpfr_dump (f);
	      printf ("   got "); mpz_dump (got);
	      printf ("  want "); mpz_dump (z);
	      exit (1);
	    }
	}
    }

  mpfr_clear (f);
  mpz_clear (got);
}

static void
check (void)
{
  mpz_t  z;

  mpz_init (z);

  mpz_set_ui (z, 0L);
  check_one (z);

  mpz_set_si (z, 123L);
  check_one (z);

  mpz_rrandomb (z, RANDS, 2*BITS_PER_MP_LIMB);
  check_one (z);

  mpz_rrandomb (z, RANDS, 5*BITS_PER_MP_LIMB);
  check_one (z);

  mpz_clear (z);
}

int
main (void)
{
  tests_start_mpfr ();

  check ();

  tests_end_mpfr ();
  return 0;
}
