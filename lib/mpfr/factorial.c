/* mpfr_fac_ui -- factorial of a non-negative integer

Copyright 2001, 2004 Free Software Foundation, Inc.

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


#include "mpfr-impl.h"

 /* The computation of n! is done by

    n!=prod^{n}_{i=1}i
 */

int
mpfr_fac_ui (mpfr_ptr y, unsigned long int x, mp_rnd_t rnd_mode) 
{

  /****** Declaration ******/

    mpfr_t t;       /* Variable of Intermediary Calculation*/
    unsigned long i;
    int round, inexact = 0;
    int loop = 1;

    mp_prec_t Ny;   /* Precision of output variable */
    mp_prec_t Nt;   /* Precision of Intermediary Calculation variable */
    mp_prec_t err;  /* Precision of error */

    mp_rnd_t rnd;

  /***** test x = 0  ******/
  	  
    if (x == 0)
      {
	return mpfr_set_ui (y, 1, GMP_RNDN); /* 0! = 1 */
      }
    else
      {
        /* Initialisation of the Precision */
	Ny = MPFR_PREC(y);
        
        /* compute the size of intermediary variable */
	Nt = Ny + 2 * (int) __gmpfr_ceil_log2 ((double) x) + 7;
	
        mpfr_init2 (t, Nt); /* initialise of intermediary variable */
        
        rnd = GMP_RNDZ;
        while (loop)
          {
            inexact = mpfr_set_ui (t, 1, rnd);
            
            for (i=2; i<=x; i++)              /* compute factorial */
              {
                round = mpfr_mul_ui (t, t, i, rnd);
                /* assume the first inexact product gives the sign
                   of difference: is that always correct? */
                if (inexact == 0)
                  inexact = round;
              }
	    
            err = Nt - 1 - (int) __gmpfr_ceil_log2 ((double) Nt);

            round = !inexact || mpfr_can_round (t, err, rnd, GMP_RNDZ,
                                                Ny + (rnd_mode == GMP_RNDN));
            
            if (round)
              {
                /* If inexact = 0, then t is exactly x!, so round is the
                   correct inexact flag.
                   Otherwise, t != x! since we rounded to zero or away. */
                round = mpfr_set (y, t, rnd_mode);
                if (inexact == 0)
                  {
                    inexact = round;
                    loop = 0;
                  }
                else if ((inexact < 0 && round <= 0) ||
                         (inexact > 0 && round >= 0))
                  {
                    loop = 0;
                  }
                else /* inexact and round have opposite signs: we cannot
                        compute the inexact flag. Restart using the 
                        symmetric rounding. */
                  {
                    rnd = (rnd == GMP_RNDZ) ? GMP_RNDU : GMP_RNDZ;
                    Nt = Nt + 10;
                    /*initialise of intermediary variable */
                    mpfr_set_prec (t, Nt);
                  }
              }
            else
              {
                Nt = Nt + 10;
                /*initialise of intermediary variable */
                mpfr_set_prec (t, Nt);
              }
	  }
   
	  mpfr_clear (t);
          return inexact;
    }
}




