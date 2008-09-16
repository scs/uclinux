/* xfinish.c --- Finish libgsasl session.
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

  if (sctx->anonymous_token)
    free (sctx->anonymous_token);

  if (sctx->authid)
    free (sctx->authid);

  if (sctx->authzid)
    free (sctx->authzid);

  if (sctx->password)
    free (sctx->password);

  if (sctx->passcode)
    free (sctx->passcode);

  if (sctx->pin)
    free (sctx->pin);

  if (sctx->suggestedpin)
    free (sctx->suggestedpin);

  if (sctx->service)
    free (sctx->service);

  if (sctx->hostname)
    free (sctx->hostname);

  if (sctx->gssapi_display_name)
    free (sctx->gssapi_display_name);

  if (sctx->realm)
    free (sctx->realm);

  free (sctx);
}
