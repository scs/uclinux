/* mechname.c --- Get name of SASL mechanism used in a session.
 * Copyright (C) 2008, 2009  Simon Josefsson
 *
 * This file is part of GNU SASL Library.
 *
 * GNU SASL Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * GNU SASL Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"

/**
 * gsasl_mechanism_name:
 * @sctx: libgsasl session handle.
 *
 * This function returns the name of the SASL mechanism used in the
 * session.
 *
 * Return value: Returns a zero terminated character array with the
 *   name of the SASL mechanism, or %NULL if not known.
 *
 * Since: 0.2.28
 **/
const char *
gsasl_mechanism_name (Gsasl_session * sctx)
{
  if (!sctx || !sctx->mech)
    return NULL;
  return sctx->mech->name;
}
