/* client.c --- DIGEST-MD5 mechanism from RFC 2831, client side.
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
#include "digest-md5.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

/* Get tools. */
#include "nonascii.h"
#include "tokens.h"
#include "parser.h"
#include "printer.h"
#include "free.h"
#include "session.h"
#include "digesthmac.h"

#define CNONCE_ENTROPY_BYTES 16

struct _Gsasl_digest_md5_client_state
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
typedef struct _Gsasl_digest_md5_client_state _Gsasl_digest_md5_client_state;

int
_gsasl_digest_md5_client_start (Gsasl_session * sctx, void **mech_data)
{
  _Gsasl_digest_md5_client_state *state;
  char nonce[CNONCE_ENTROPY_BYTES];
  char *p;
  int rc;

  rc = gsasl_nonce (nonce, CNONCE_ENTROPY_BYTES);
  if (rc != GSASL_OK)
    return rc;

  rc = gsasl_base64_to (nonce, CNONCE_ENTROPY_BYTES, &p, NULL);
  if (rc != GSASL_OK)
    return rc;

  state = calloc (1, sizeof (*state));
  if (state == NULL)
    {
      free (p);
      return GSASL_MALLOC_ERROR;
    }

  state->response.cnonce = p;
  state->response.nc = 1;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_digest_md5_client_step (Gsasl_session * sctx,
			       void *mech_data,
			       const char *input,
			       size_t input_len,
			       char **output, size_t * output_len)
{
  _Gsasl_digest_md5_client_state *state = mech_data;
  int rc, res;

  *output = NULL;
  *output_len = 0;

  switch (state->step)
    {
    case 0:
      state->step++;
      if (input_len == 0)
	return GSASL_NEEDS_MORE;
      /* fall through */

    case 1:
      {
	if (digest_md5_parse_challenge (input, input_len,
					&state->challenge) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	/* FIXME: How to let application know of remaining realms?
	   One idea, add a GSASL_REALM_COUNT property, and have the
	   GSASL_REALM be that many concatenated zero terminated realm
	   strings.  Slightly hackish, though.  Another cleaner
	   approach would be to add gsasl_property_set_array and
	   gsasl_property_get_array APIs, for those properties that
	   may be used multiple times. */
	if (state->challenge.nrealms > 0)
	  gsasl_property_set (sctx, GSASL_REALM, state->challenge.realms[0]);
	else
	  gsasl_property_set (sctx, GSASL_REALM, NULL);

	/* FIXME: qop, cipher, maxbuf. */

	/* Create response token. */
	state->response.utf8 = 1;
	state->response.qop = 1;

	state->response.nonce = strdup (state->challenge.nonce);
	if (!state->response.nonce)
	  return GSASL_MALLOC_ERROR;

	{
	  const char *service = gsasl_property_get (sctx, GSASL_SERVICE);
	  const char *hostname = gsasl_property_get (sctx, GSASL_HOSTNAME);
	  if (!service)
	    return GSASL_NO_SERVICE;
	  if (!hostname)
	    return GSASL_NO_HOSTNAME;
	  if (asprintf (&state->response.digesturi, "%s/%s",
			service, hostname) < 0)
	    return GSASL_MALLOC_ERROR;
	}

	{
	  const char *c;
	  char *tmp, *tmp2;

	  c = gsasl_property_get (sctx, GSASL_AUTHID);
	  if (!c)
	    return GSASL_NO_AUTHID;

	  state->response.username = strdup (c);
	  if (!state->response.username)
	    return GSASL_MALLOC_ERROR;

	  c = gsasl_property_get (sctx, GSASL_AUTHZID);
	  if (c)
	    {
	      state->response.authzid = strdup (c);
	      if (!state->response.authzid)
		return GSASL_MALLOC_ERROR;
	    }

	  gsasl_callback (NULL, sctx, GSASL_REALM);
	  c = gsasl_property_fast (sctx, GSASL_REALM);
	  if (c)
	    {
	      state->response.realm = strdup (c);
	      if (!state->response.realm)
		return GSASL_MALLOC_ERROR;
	    }

	  c = gsasl_property_get (sctx, GSASL_PASSWORD);
	  if (!c)
	    return GSASL_NO_PASSWORD;

	  tmp2 = utf8tolatin1ifpossible (c);

	  rc = asprintf (&tmp, "%s:%s:%s", state->response.username,
			 state->response.realm ?
			 state->response.realm : "", tmp2);
	  free (tmp2);
	  if (rc < 0)
	    return GSASL_MALLOC_ERROR;

	  rc = gsasl_md5 (tmp, strlen (tmp), &tmp2);
	  free (tmp);
	  if (rc != GSASL_OK)
	    return rc;
	  memcpy (state->secret, tmp2, DIGEST_MD5_LENGTH);
	  free (tmp2);
	}

	rc = digest_md5_hmac (state->response.response,
			      state->secret,
			      state->response.nonce,
			      state->response.nc,
			      state->response.cnonce,
			      state->response.qop,
			      state->response.authzid,
			      state->response.digesturi,
			      0,
			      state->response.cipher,
			      state->kic, state->kis, state->kcc, state->kcs);
	if (rc)
	  return GSASL_CRYPTO_ERROR;

	*output = digest_md5_print_response (&state->response);
	if (!*output)
	  return GSASL_AUTHENTICATION_ERROR;

	*output_len = strlen (*output);

	state->step++;
	res = GSASL_NEEDS_MORE;
      }
      break;

    case 2:
      {
	char check[DIGEST_MD5_RESPONSE_LENGTH + 1];

	if (digest_md5_parse_finish (input, input_len, &state->finish) < 0)
	  return GSASL_MECHANISM_PARSE_ERROR;

	res = digest_md5_hmac (check, state->secret,
			       state->response.nonce, state->response.nc,
			       state->response.cnonce, state->response.qop,
			       state->response.authzid,
			       state->response.digesturi, 1,
			       state->response.cipher, NULL, NULL, NULL,
			       NULL);
	if (res != GSASL_OK)
	  break;

	if (strcmp (state->finish.rspauth, check) == 0)
	  res = GSASL_OK;
	else
	  res = GSASL_AUTHENTICATION_ERROR;
	state->step++;
      }
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

void
_gsasl_digest_md5_client_finish (Gsasl_session * sctx, void *mech_data)
{
  _Gsasl_digest_md5_client_state *state = mech_data;

  if (!state)
    return;

  digest_md5_free_challenge (&state->challenge);
  digest_md5_free_response (&state->response);
  digest_md5_free_finish (&state->finish);

  free (state);
}

int
_gsasl_digest_md5_client_encode (Gsasl_session * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char **output, size_t * output_len)
{
  _Gsasl_digest_md5_client_state *state = mech_data;
  int res;

  res = digest_md5_encode (input, input_len, output, output_len,
			   state->response.qop,
			   state->sendseqnum, state->kic);
  if (res)
    return res == -2 ? GSASL_NEEDS_MORE : GSASL_INTEGRITY_ERROR;

  if (state->sendseqnum == 4294967295UL)
    state->sendseqnum = 0;
  else
    state->sendseqnum++;

  return GSASL_OK;
}

int
_gsasl_digest_md5_client_decode (Gsasl_session * sctx,
				 void *mech_data,
				 const char *input,
				 size_t input_len,
				 char **output, size_t * output_len)
{
  _Gsasl_digest_md5_client_state *state = mech_data;
  int res;

  res = digest_md5_decode (input, input_len, output, output_len,
			   state->response.qop,
			   state->readseqnum, state->kis);
  if (res)
    return res == -2 ? GSASL_NEEDS_MORE : GSASL_INTEGRITY_ERROR;

  if (state->readseqnum == 4294967295UL)
    state->readseqnum = 0;
  else
    state->readseqnum++;

  return GSASL_OK;
}
