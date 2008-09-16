/* validate.c --- Validate consistency of DIGEST-MD5 tokens.
 * Copyright (C) 2004, 2006  Simon Josefsson
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
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get prototypes. */
#include "validate.h"

/* Get strcmp, strlen. */
#include <string.h>

int
digest_md5_validate_challenge (digest_md5_challenge * c)
{
  /* This directive is required and MUST appear exactly once; if
     not present, or if multiple instances are present, the
     client should abort the authentication exchange. */
  if (!c->nonce)
    return -1;

  /* This directive must be present exactly once if "auth-conf" is
     offered in the "qop-options" directive */
  if (c->ciphers && !(c->qops & DIGEST_MD5_QOP_AUTH_CONF))
    return -1;
  if (!c->ciphers && (c->qops & DIGEST_MD5_QOP_AUTH_CONF))
    return -1;

  return 0;
}

int
digest_md5_validate_response (digest_md5_response * r)
{
  /* This directive is required and MUST be present exactly
     once; otherwise, authentication fails. */
  if (!r->username)
    return -1;

  /* This directive is required and MUST be present exactly
     once; otherwise, authentication fails. */
  if (!r->nonce)
    return -1;

  /* This directive is required and MUST be present exactly once;
     otherwise, authentication fails. */
  if (!r->cnonce)
    return -1;

  /* This directive is required and MUST be present exactly once;
     otherwise, or if the value is 0, authentication fails. */
  if (!r->nc)
    return -1;

  /* This directive is required and MUST be present exactly
     once; if multiple instances are present, the client MUST
     abort the authentication exchange. */
  if (!r->digesturi)
    return -1;

  /* This directive is required and MUST be present exactly
     once; otherwise, authentication fails. */
  if (!*r->response)
    return -1;

  if (strlen (r->response) != DIGEST_MD5_RESPONSE_LENGTH)
    return -1;

  /* This directive MUST appear exactly once if "auth-conf" is
     negotiated; if required and not present, authentication fails.
     If the client recognizes no cipher and the server only advertised
     "auth-conf" in the qop option, the client MUST abort the
     authentication exchange.  */
  if (r->qop == DIGEST_MD5_QOP_AUTH_CONF && !r->cipher)
    return -1;
  if (r->qop != DIGEST_MD5_QOP_AUTH_CONF && r->cipher)
    return -1;

  return 0;
}

int
digest_md5_validate_finish (digest_md5_finish * f)
{
  if (!f->rspauth)
    return -1;

  /* A string of 32 hex digits */
  if (strlen (f->rspauth) != DIGEST_MD5_RESPONSE_LENGTH)
    return -1;

  return 0;
}

int
digest_md5_validate (digest_md5_challenge * c, digest_md5_response * r)
{
  if (!c->nonce || !r->nonce)
    return -1;

  if (strcmp (c->nonce, r->nonce) != 0)
    return -1;

  if (r->nc != 1)
    return -1;

  if (c->utf8 != r->utf8)
    return -1;

  if (!((c->qops ? c->qops : DIGEST_MD5_QOP_AUTH) &
	(r->qop ? r->qop : DIGEST_MD5_QOP_AUTH)))
    return -1;

  if ((r->qop & DIGEST_MD5_QOP_AUTH_CONF) && !(c->ciphers & r->cipher))
    return -1;

  /* FIXME: Check more? */

  return 0;
}
