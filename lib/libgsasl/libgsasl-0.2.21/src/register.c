/* register.c --- Initialize and register SASL plugin in global context.
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

/**
 * gsasl_register:
 * @ctx: pointer to libgsasl handle.
 * @mech: plugin structure with information about plugin.
 *
 * This function initialize given mechanism, and if successful, add it
 * to the list of plugins that is used by the library.
 *
 * Return value: GSASL_OK iff successful, otherwise GSASL_MALLOC_ERROR.
 *
 * Since: 0.2.0
 **/
int
gsasl_register (Gsasl * ctx, const Gsasl_mechanism * mech)
{
  Gsasl_mechanism *tmp;

#ifdef USE_CLIENT
  if (mech->client.init == NULL || mech->client.init (ctx) == GSASL_OK)
    {
      tmp = realloc (ctx->client_mechs,
		     sizeof (*ctx->client_mechs) * (ctx->n_client_mechs + 1));
      if (tmp == NULL)
	return GSASL_MALLOC_ERROR;

      memcpy (&tmp[ctx->n_client_mechs], mech, sizeof (*mech));

      ctx->client_mechs = tmp;
      ctx->n_client_mechs++;
    }
#endif

#ifdef USE_SERVER
  if (mech->server.init == NULL || mech->server.init (ctx) == GSASL_OK)
    {
      tmp = realloc (ctx->server_mechs,
		     sizeof (*ctx->server_mechs) * (ctx->n_server_mechs + 1));
      if (tmp == NULL)
	return GSASL_MALLOC_ERROR;

      memcpy (&tmp[ctx->n_server_mechs], mech, sizeof (*mech));

      ctx->server_mechs = tmp;
      ctx->n_server_mechs++;
    }
#endif

  return GSASL_OK;
}
