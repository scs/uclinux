/* xfinish.c --- Finish libgsasl session.
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

#define free_if_nonnull(p) if ((p)) free ((p))

/**
 * gsasl_finish:
 * @sctx: libgsasl session handle.
 *
 * Destroy a libgsasl client or server handle.  The handle must not be
 * used with other libgsasl functions after this call.
 **/
void
gsasl_finish (Gsasl_session * sctx)
{
  if (sctx->clientp)
    {
      if (sctx->mech && sctx->mech->client.finish)
	sctx->mech->client.finish (sctx, sctx->mech_data);
    }
  else
    {
      if (sctx->mech && sctx->mech->server.finish)
	sctx->mech->server.finish (sctx, sctx->mech_data);
    }

  free_if_nonnull (sctx->anonymous_token);
  free_if_nonnull (sctx->authid);
  free_if_nonnull (sctx->authzid);
  free_if_nonnull (sctx->password);
  free_if_nonnull (sctx->passcode);
  free_if_nonnull (sctx->pin);
  free_if_nonnull (sctx->suggestedpin);
  free_if_nonnull (sctx->service);
  free_if_nonnull (sctx->hostname);
  free_if_nonnull (sctx->gssapi_display_name);
  free_if_nonnull (sctx->realm);
  free_if_nonnull (sctx->digest_md5_hashed_password);

  free_if_nonnull (sctx);
}
