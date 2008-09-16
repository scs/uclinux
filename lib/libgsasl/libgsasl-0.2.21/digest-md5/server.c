/* server.c --- DIGEST-MD5 mechanism from RFC 2831, server side.
 * Copyright (C) 2002, 2003, 2004, 2006  Simon Josefsson
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
#include "digest-md5.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strdup, strlen. */
#include <string.h>

/* Get tools. */
#include "tokens.h"
#include "parser.h"
#include "printer.h"
#include "free.h"
#include "session.h"
#include "digesthmac.h"
#include "validate.h"

#define NONCE_ENTROPY_BYTES 16

struct _Gsasl_digest_md5_server_state
{
  int step;
  unsigned long readseqnum, sendseqnum;
  char secret[DIGEST_MD5_LENGTH];
  char kic[DIGEST_MD5_LENGTH];
  char kcc[DIGEST_MD5_LENGTH];
  char kis[DIGEST_MD5_LENGTH];
  char kcs[DIGEST_MD5_LENGTH];
  digest_md5_challenge challenge;
  digest_md5_response response;
  digest_md5_finish finish;
};
typedef struct _Gsasl_digest_md5_server_state _Gsasl_digest_md5_server_state;

int
_gsasl_digest_md5_server_start (Gsasl_session * sctx, void **mech_data)
{
  _Gsasl_digest_md5_server_state *state;
  char nonce[NONCE_ENTROPY_BYTES];
  char *p;
  int rc;

  rc = gsasl_nonce (nonce, NONCE_ENTROPY_BYTES);
  if (rc != GSASL_OK)
    return rc;

  rc = gsasl_base64_to (nonce, NONCE_ENTROPY_BYTES, &p, NULL);
  if (rc != GSASL_OK)
    return rc;

  state = calloc (1, sizeof (*state));
  if (state == NULL)
    {
      free (p);
      return GSASL_MALLOC_ERROR;
    }

  state->challenge.qops = DIGEST_MD5_QOP_AUTH | DIGEST_MD5_QOP_AUTH_INT;
  state->challenge.ciphers = 0;

  state->challenge.nonce = p;
  state->challenge.utf8 = 1;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_digest_md5_server_step (Gsasl_session * sctx,
			       void *mech_data,
			       const char *input,
			       size_t input_len,
			       char **output, size_t * output_len)
{
  _Gsasl_digest_md5_server_state *state = mech_data;
  int rc, res;

  *output = NULL;
  *output_len = 0;

  switch (state->step)
    {
    case 0:
      /* Set realm. */
      {
	const char *c;
	c = gsasl_property_get (sctx, GSASL_REALM);
	if (c)
	  {
	    state->challenge.nrealms = 1;

	    state->challenge.realms =
	      malloc (sizeof (*state->challenge.realms));
	    if (!state->challenge.realms)
	      return GSASL_MALLOC_ERROR;

	    state->challenge.realms[0] = strdup (c);
	    if (!state->challenge.realms[0])
	      return GSASL_MALLOC_ERROR;
	  }
      }

      /* FIXME: qop, cipher, maxbuf, more realms. */

      /* Create challenge. */
      *output = digest_md5_print_challenge (&state->challenge);
      if (!*output)
	return GSASL_AUTHENTICATION_ERROR;

      *output_len = strlen (*output);
      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 1:
      if (digest_md5_parse_response (input, input_len, &state->response) < 0)
	return GSASL_MECHANISM_PARSE_ERROR;

      /* Make sure response is consistent with challenge. */
      if (digest_md5_validate (&state->challenge, &state->response) < 0)
	return GSASL_MECHANISM_PARSE_ERROR;

      /* Store properties, from the client response. */
      gsasl_property_set (sctx, GSASL_AUTHID, state->response.username);
      gsasl_property_set (sctx, GSASL_AUTHZID, state->response.authzid);
      gsasl_property_set (sctx, GSASL_REALM, state->response.realm);

      /* FIXME: qop, cipher, maxbuf. */

      /* Compute secret.  TODO: Add callback to retrieve hashed
         secret. */
      {
	const char *c;
	char *tmp, *tmp2;

	c = gsasl_property_get (sctx, GSASL_PASSWORD);
	if (!c)
	  return GSASL_NO_PASSWORD;

	if (asprintf (&tmp, "%s:%s:%s", state->response.username,
		      state->response.realm ?
		      state->response.realm : "", c) < 0)
	  return GSASL_MALLOC_ERROR;

	rc = gsasl_md5 (tmp, strlen (tmp), &tmp2);
	free (tmp);
	if (rc != GSASL_OK)
	  return rc;
	memcpy (state->secret, tmp2, DIGEST_MD5_LENGTH);
	free (tmp2);
      }

      /* Check client response. */
      {
	char check[DIGEST_MD5_RESPONSE_LENGTH + 1];

	rc = digest_md5_hmac (check, state->secret,
			      state->response.nonce, state->response.nc,
			      state->response.cnonce, state->response.qop,
			      state->response.authzid,
			      state->response.digesturi, 0,
			      state->response.cipher, NULL, NULL, NULL, NULL);
	if (rc)
	  return GSASL_AUTHENTICATION_ERROR;

	if (strcmp (state->response.response, check) != 0)
	  return GSASL_AUTHENTICATION_ERROR;
      }

      /* Create finish token. */
      rc = digest_md5_hmac (state->finish.rspauth, state->secret,
			    state->response.nonce, state->response.nc,
			    state->response.cnonce, state->response.qop,
			    state->response.authzid,
			    state->response.digesturi, 1,
			    state->response.cipher, NULL, NULL, NULL, NULL);
      if (rc)
	return GSASL_AUTHENTICATION_ERROR;

      *output = digest_md5_print_finish (&state->finish);
      if (!*output)
	return GSASL_MALLOC_ERROR;

      *output_len = strlen (*output);

      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 2:
      *output_len = 0;
      state->step++;
      res = GSASL_OK;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

void
_gsasl_digest_md5_server_finish (Gsasl_session * sctx, void *mech_data)
{
  _Gsasl_digest_md5_server_state *state = mech_data;

  if (!state)
    return;

  digest_md5_free_challenge (&state->challenge);
  digest_md5_free_response (&state->response);
  digest_md5_free_finish (&state->finish);

  free (state);
}

int
_gsasl_digest_md5_server_encode (Gsasl_session * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char **output, size_t * output_len)
{
  _Gsasl_digest_md5_server_state *state = mech_data;
  int res;

  res = digest_md5_encode (input, input_len, output, output_len,
			   state->response.qop, state->sendseqnum,
			   state->kis);
  if (res)
    return res == -2 ? GSASL_NEEDS_MORE : GSASL_INTEGRITY_ERROR;

  if (state->sendseqnum == 4294967295UL)
    state->sendseqnum = 0;
  else
    state->sendseqnum++;

  return GSASL_OK;
}

int
_gsasl_digest_md5_server_decode (Gsasl_session * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char **output, size_t * output_len)
{
  _Gsasl_digest_md5_server_state *state = mech_data;
  int res;

  res = digest_md5_decode (input, input_len, output, output_len,
			   state->response.qop, state->readseqnum,
			   state->kic);
  if (res)
    return res == -2 ? GSASL_NEEDS_MORE : GSASL_INTEGRITY_ERROR;

  if (state->readseqnum == 4294967295UL)
    state->readseqnum = 0;
  else
    state->readseqnum++;

  return GSASL_OK;
}
