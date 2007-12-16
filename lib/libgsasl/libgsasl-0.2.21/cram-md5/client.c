/* client.c --- SASL CRAM-MD5 client side functions.
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
#include "cram-md5.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

/* Get cram_md5_digest. */
#include "digest.h"

int
_gsasl_cram_md5_client_step (Gsasl_session * sctx,
			     void *mech_data,
			     const char *input, size_t input_len,
			     char **output, size_t * output_len)
{
  char response[CRAM_MD5_DIGEST_LEN];
  const char *p;
  size_t len;
  char *tmp;
  char *authid;
  int rc;

  if (input_len == 0)
    {
      *output_len = 0;
      *output = NULL;
      return GSASL_NEEDS_MORE;
    }

  p = gsasl_property_get (sctx, GSASL_AUTHID);
  if (!p)
    return GSASL_NO_AUTHID;

  /* XXX Use query strings here?  Specification is unclear. */
  rc = gsasl_saslprep (p, GSASL_ALLOW_UNASSIGNED, &authid, NULL);
  if (rc != GSASL_OK)
    return rc;

  p = gsasl_property_get (sctx, GSASL_PASSWORD);
  if (!p)
    {
      free (authid);
      return GSASL_NO_PASSWORD;
    }

  /* XXX Use query strings here?  Specification is unclear. */
  rc = gsasl_saslprep (p, GSASL_ALLOW_UNASSIGNED, &tmp, NULL);
  if (rc != GSASL_OK)
    {
      free (authid);
      return rc;
    }

  cram_md5_digest (input, input_len, tmp, strlen (tmp), response);

  free (tmp);

  len = strlen (authid);

  *output_len = len + strlen (" ") + CRAM_MD5_DIGEST_LEN;
  *output = malloc (*output_len);
  if (!*output)
    {
      free (authid);
      return GSASL_MALLOC_ERROR;
    }

  memcpy (*output, authid, len);
  (*output)[len++] = ' ';
  memcpy (*output + len, response, CRAM_MD5_DIGEST_LEN);

  free (authid);

  return GSASL_OK;
}
