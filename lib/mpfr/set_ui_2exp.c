/* mpfr_set_ui_2exp -- set a MPFR number from a machine unsigned integer with 
   a shift

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

#include "mpfr-impl.h"

int
mpfr_set_ui_2exp (mpfr_ptr x, unsigned long i, mp_exp_t e, mp_rnd_t rnd_mode)
{
  int res;

  mpfr_save_emin_emax ();
  res = mpfr_set_ui (x, i, rnd_mode);
  MPFR_ASSERTD ( res == 0);
  MPFR_ASSERTD (e == (mp_exp_t)(long) e);
  res = mpfr_mul_2si (x, x, e, rnd_mode);
  mpfr_restore_emin_emax ();
  if (res)
    return res;
  res = mpfr_check_range(x, 0, rnd_mode);
  return res;
}
