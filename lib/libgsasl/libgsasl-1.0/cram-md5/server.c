/* server.c --- SASL CRAM-MD5 server side functions.
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
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "cram-md5.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strdup, strlen. */
#include <string.h>

/* Get cram_md5_challenge. */
#include "challenge.h"

/* Get cram_md5_digest. */
#include "digest.h"

#define MD5LEN 16

int
_gsasl_cram_md5_server_start (Gsasl_session * sctx, void **mech_data)
{
  char *challenge;
  int rc;

  challenge = malloc (CRAM_MD5_CHALLENGE_LEN);
  if (challenge == NULL)
    return GSASL_MALLOC_ERROR;

  rc = cram_md5_challenge (challenge);
  if (rc)
    return GSASL_CRYPTO_ERROR;

  *mech_data = challenge;

  return GSASL_OK;
}

int
_gsasl_cram_md5_server_step (Gsasl_session * sctx,
			     void *mech_data,
			     const char *input, size_t input_len,
			     char **output, size_t * output_len)
{
  char *challenge = mech_data;
  char hash[CRAM_MD5_DIGEST_LEN];
  const char *password;
  char *username = NULL;
  int res = GSASL_OK;
  char *normkey;

  if (input_len == 0)
    {
      *output_len = strlen (challenge);
      *output = strdup (challenge);

      return GSASL_NEEDS_MORE;
    }

  if (input_len <= MD5LEN * 2)
    return GSASL_MECHANISM_PARSE_ERROR;

  if (input[input_len - MD5LEN * 2 - 1] != ' ')
    return GSASL_MECHANISM_PARSE_ERROR;

  username = calloc (1, input_len - MD5LEN * 2);
  if (username == NULL)
    return GSASL_MALLOC_ERROR;

  memcpy (username, input, input_len - MD5LEN * 2 - 1);

  gsasl_property_set (sctx, GSASL_AUTHID, username);

  free (username);

  password = gsasl_property_get (sctx, GSASL_PASSWORD);
  if (!password)
    return GSASL_NO_PASSWORD;

  /* FIXME: Use SASLprep here?  Treat string as storage string?
     Specification is unclear. */
  res = gsasl_saslprep (password, 0, &normkey, NULL);
  if (res != GSASL_OK)
    return res;

  cram_md5_digest (challenge, strlen (challenge),
		   normkey, strlen (normkey), hash);

  free (normkey);

  if (memcmp (&input[input_len - MD5LEN * 2], hash, 2 * MD5LEN) == 0)
    res = GSASL_OK;
  else
    res = GSASL_AUTHENTICATION_ERROR;

  *output_len = 0;
  *output = NULL;

  return res;
}

void
_gsasl_cram_md5_server_finish (Gsasl_session * sctx, void *mech_data)
{
  char *challenge = mech_data;

  if (challenge)
    free (challenge);
}
