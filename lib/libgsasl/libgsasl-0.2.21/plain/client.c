/* client.c --- SASL mechanism PLAIN as defined in RFC 2595, client side.
 * Copyright (C) 2002, 2003, 2004  Simon Josefsson
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

/* Get specification. */
#include "plain.h"

/* Get memcpy, strdup, strlen. */
#include <string.h>

/* Get malloc, free. */
#include <stdlib.h>

int
_gsasl_plain_client_step (Gsasl_session * sctx,
			  void *mech_data,
			  const char *input, size_t input_len,
			  char **output, size_t * output_len)
{
  const char *authzid = gsasl_property_get (sctx, GSASL_AUTHZID);
  const char *authid = gsasl_property_get (sctx, GSASL_AUTHID);
  const char *password = gsasl_property_get (sctx, GSASL_PASSWORD);
  size_t authzidlen = 0, authidlen = 0, passwordlen = 0;
  char *out;

  if (authzid)
    authzidlen = strlen (authzid);

  if (authid)
    authidlen = strlen (authid);
  else
    return GSASL_NO_AUTHID;

  if (password)
    passwordlen = strlen (password);
  else
    return GSASL_NO_PASSWORD;

  *output_len = authzidlen + 1 + authidlen + 1 + passwordlen;
  *output = out = malloc (*output_len);
  if (!out)
    return GSASL_MALLOC_ERROR;

  if (authzid)
    {
      memcpy (out, authzid, authzidlen);
      out += authzidlen;
    }

  *out++ = '\0';

  memcpy (out, authid, authidlen);
  out += authidlen;

  *out++ = '\0';

  memcpy (out, password, passwordlen);

  return GSASL_OK;
}
