/* xstart.c --- Start libgsasl session.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006  Simon Josefsson
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

static Gsasl_mechanism *
find_mechanism (const char *mech, size_t n_mechs, Gsasl_mechanism * mechs)
{
  size_t i;

  if (mech == NULL)
    return NULL;

  for (i = 0; i < n_mechs; i++)
    if (strcmp (mech, mechs[i].name) == 0)
      return &mechs[i];

  return NULL;
}

static int
setup (Gsasl * ctx,
       const char *mech,
       Gsasl_session * sctx,
       size_t n_mechs, Gsasl_mechanism * mechs, int clientp)
{
  Gsasl_mechanism *mechptr = NULL;
  int res;

  mechptr = find_mechanism (mech, n_mechs, mechs);
  if (mechptr == NULL)
    return GSASL_UNKNOWN_MECHANISM;

  sctx->ctx = ctx;
  sctx->mech = mechptr;
  sctx->clientp = clientp;

  if (clientp)
    {
      if (sctx->mech->client.start)
	res = sctx->mech->client.start (sctx, &sctx->mech_data);
      else if (!sctx->mech->client.step)
	res = GSASL_NO_CLIENT_CODE;
      else
	res = GSASL_OK;
    }
  else
    {
      if (sctx->mech->server.start)
	res = sctx->mech->server.start (sctx, &sctx->mech_data);
      else if (!sctx->mech->server.step)
	res = GSASL_NO_SERVER_CODE;
      else
	res = GSASL_OK;
    }
  if (res != GSASL_OK)
    return res;

  return GSASL_OK;
}

static int
start (Gsasl * ctx,
       const char *mech,
       Gsasl_session ** sctx,
       size_t n_mechs, Gsasl_mechanism * mechs, int clientp)
{
  Gsasl_session *out;
  int res;

  out = calloc (1, sizeof (*out));
  if (out == NULL)
    return GSASL_MALLOC_ERROR;

  res = setup (ctx, mech, out, n_mechs, mechs, clientp);
  if (res != GSASL_OK)
    {
      gsasl_finish (out);
      return res;
    }

  *sctx = out;

  return GSASL_OK;
}

/**
 * gsasl_client_start:
 * @ctx: libgsasl handle.
 * @mech: name of SASL mechanism.
 * @sctx: pointer to client handle.
 *
 * This functions initiates a client SASL authentication.  This
 * function must be called before any other gsasl_client_*() function
 * is called.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_client_start (Gsasl * ctx, const char *mech, Gsasl_session ** sctx)
{
  return start (ctx, mech, sctx, ctx->n_client_mechs, ctx->client_mechs, 1);
}

/**
 * gsasl_server_start:
 * @ctx: libgsasl handle.
 * @mech: name of SASL mechanism.
 * @sctx: pointer to server handle.
 *
 * This functions initiates a server SASL authentication.  This
 * function must be called before any other gsasl_server_*() function
 * is called.
 *
 * Return value: Returns GSASL_OK if successful, or error code.
 **/
int
gsasl_server_start (Gsasl * ctx, const char *mech, Gsasl_session ** sctx)
{
  return start (ctx, mech, sctx, ctx->n_server_mechs, ctx->server_mechs, 0);
}
