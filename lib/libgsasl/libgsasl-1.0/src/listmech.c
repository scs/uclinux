/* listmech.c --- List active client and server mechanisms.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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
_gsasl_listmech (Gsasl * ctx,
		 Gsasl_mechanism * mechs,
		 size_t n_mechs, char **out, int clientp)
{
  Gsasl_session *sctx;
  char *list;
  size_t i;
  int rc;

  list = calloc (n_mechs, GSASL_MAX_MECHANISM_SIZE + 1);
  if (!list)
    return GSASL_MALLOC_ERROR;

  for (i = 0; i < n_mechs; i++)
    {
      if (clientp)
	rc = gsasl_client_start (ctx, mechs[i].name, &sctx);
      else
	rc = gsasl_server_start (ctx, mechs[i].name, &sctx);

      if (rc == GSASL_OK)
	{
	  gsasl_finish (sctx);

	  strcat (list, mechs[i].name);
	  if (i < n_mechs - 1)
	    strcat (list, " ");
	}
    }

  *out = list;

  return GSASL_OK;
}

/**
 * gsasl_client_mechlist:
 * @ctx: libgsasl handle.
 * @out: newly allocated output character array.
 *
 * Return a newly allocated string containing SASL names, separated by
 * space, of mechanisms supported by the libgsasl client.  @out is
 * allocated by this function, and it is the responsibility of caller
 * to deallocate it.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 **/
int
gsasl_client_mechlist (Gsasl * ctx, char **out)
{
  return _gsasl_listmech (ctx, ctx->client_mechs, ctx->n_client_mechs,
			  out, 1);
}

/**
 * gsasl_server_mechlist:
 * @ctx: libgsasl handle.
 * @out: newly allocated output character array.
 *
 * Return a newly allocated string containing SASL names, separated by
 * space, of mechanisms supported by the libgsasl server.  @out is
 * allocated by this function, and it is the responsibility of caller
 * to deallocate it.
 *
 * Return value: Returns %GSASL_OK if successful, or error code.
 **/
int
gsasl_server_mechlist (Gsasl * ctx, char **out)
{
  return _gsasl_listmech (ctx, ctx->server_mechs, ctx->n_server_mechs,
			  out, 0);
}
