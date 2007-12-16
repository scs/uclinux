/* supportp.c --- Tell if a specific mechanism is supported.
 * Copyright (C) 2002, 2003, 2004, 2005  Simon Josefsson
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

static int
_gsasl_support_p (Gsasl_mechanism * mechs, size_t n_mechs, const char *name)
{
  size_t i;

  for (i = 0; i < n_mechs; i++)
    if (name && strcmp (name, mechs[i].name) == 0)
      return 1;

  return 0;
}

/**
 * gsasl_client_support_p:
 * @ctx: libgsasl handle.
 * @name: name of SASL mechanism.
 *
 * Decide whether there is client-side support for a specified
 * mechanism.
 *
 * Return value: Returns 1 if the libgsasl client supports the named
 * mechanism, otherwise 0.
 **/
int
gsasl_client_support_p (Gsasl * ctx, const char *name)
{
  return _gsasl_support_p (ctx->client_mechs, ctx->n_client_mechs, name);
}

/**
 * gsasl_server_support_p:
 * @ctx: libgsasl handle.
 * @name: name of SASL mechanism.
 *
 * Decide whether there is server-side support for a specified
 * mechanism.
 *
 * Return value: Returns 1 if the libgsasl server supports the named
 * mechanism, otherwise 0.
 **/
int
gsasl_server_support_p (Gsasl * ctx, const char *name)
{
  return _gsasl_support_p (ctx->server_mechs, ctx->n_server_mechs, name);
}
