/* client.c --- Experimental SASL mechanism KERBEROS_V5, client side.
 * Copyright (C) 2003, 2004  Simon Josefsson
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
 * NB!  Shishi is licensed under GPL, so linking GSASL with it require
 * that you follow the GPL for GSASL as well.
 *
 */

#include "kerberos_v5.h"

#include "shared.h"

struct _Gsasl_kerberos_v5_client_state
{
  int step;
  char serverhello[BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN];
  int serverqops;
  int clientqop;
  int servermutual;
  uint32_t servermaxbuf;
  uint32_t clientmaxbuf;
  Shishi *sh;
  Shishi_tkt *tkt;
  Shishi_as *as;
  Shishi_ap *ap;
  Shishi_key *sessionkey;
  Shishi_safe *safe;
};

int
_gsasl_kerberos_v5_client_init (Gsasl_ctx * ctx)
{
  if (!shishi_check_version (SHISHI_VERSION))
    return GSASL_UNKNOWN_MECHANISM;

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_client_start (Gsasl_session * sctx, void **mech_data)
{
  struct _Gsasl_kerberos_v5_client_state *state;
  Gsasl_ctx *ctx;
  int err;

  state = malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  memset (state, 0, sizeof (*state));

  err = shishi_init (&state->sh);
  if (err)
    return GSASL_KERBEROS_V5_INIT_ERROR;

  state->step = 0;
  state->clientqop = GSASL_QOP_AUTH_INT;

  *mech_data = state;

  return GSASL_OK;
}

#define STEP_FIRST 0
#define STEP_NONINFRA_SEND_ASREQ 1
#define STEP_NONINFRA_WAIT_ASREP 2
#define STEP_NONINFRA_SEND_APREQ 3
#define STEP_NONINFRA_WAIT_APREP 4
#define STEP_SUCCESS 5

int
_gsasl_kerberos_v5_client_step (Gsasl_session * sctx,
				void *mech_data,
				const char *input,
				size_t input_len,
				char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;
  Gsasl_client_callback_authentication_id cb_authentication_id;
  Gsasl_client_callback_authorization_id cb_authorization_id;
  Gsasl_client_callback_qop cb_qop;
  Gsasl_client_callback_realm cb_realm;
  Gsasl_client_callback_password cb_password;
  Gsasl_client_callback_service cb_service;
  Gsasl_client_callback_maxbuf cb_maxbuf;
  Gsasl_ctx *ctx;
  int res;
  int len;

  ctx = gsasl_client_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  /* These are optional */
  cb_realm = gsasl_client_callback_realm_get (ctx);
  cb_service = gsasl_client_callback_service_get (ctx);
  cb_authentication_id = gsasl_client_callback_authentication_id_get (ctx);
  cb_authorization_id = gsasl_client_callback_authorization_id_get (ctx);
  cb_qop = gsasl_client_callback_qop_get (ctx);
  cb_maxbuf = gsasl_client_callback_maxbuf_get (ctx);

  /* Only optionally needed in infrastructure mode */
  cb_password = gsasl_client_callback_password_get (ctx);
  if (cb_password == NULL)
    return GSASL_NEED_CLIENT_PASSWORD_CALLBACK;

  /* I think we really need this one */
  cb_service = gsasl_client_callback_service_get (ctx);
  if (cb_service == NULL)
    return GSASL_NEED_CLIENT_SERVICE_CALLBACK;

  switch (state->step)
    {
    case STEP_FIRST:
      if (input == NULL)
	{
	  *output_len = 0;
	  return GSASL_NEEDS_MORE;
	}

      if (input_len != SERVER_HELLO_LEN)
	return GSASL_MECHANISM_PARSE_ERROR;

      memcpy (state->serverhello, input, input_len);

      {
	unsigned char serverbitmap;

	memcpy (&serverbitmap, input, BITMAP_LEN);
	state->serverqops = 0;
	if (serverbitmap & GSASL_QOP_AUTH)
	  state->serverqops |= GSASL_QOP_AUTH;
	if (serverbitmap & GSASL_QOP_AUTH_INT)
	  state->serverqops |= GSASL_QOP_AUTH_INT;
	if (serverbitmap & GSASL_QOP_AUTH_CONF)
	  state->serverqops |= GSASL_QOP_AUTH_CONF;
	if (serverbitmap & MUTUAL)
	  state->servermutual = 1;
      }
      memcpy (&state->servermaxbuf, &input[BITMAP_LEN], MAXBUF_LEN);
      state->servermaxbuf = ntohl (state->servermaxbuf);

      if (cb_qop)
	state->clientqop = cb_qop (sctx, state->serverqops);

      if (!(state->serverqops & state->clientqop &
	    (GSASL_QOP_AUTH | GSASL_QOP_AUTH_INT | GSASL_QOP_AUTH_CONF)))
	return GSASL_AUTHENTICATION_ERROR;

      /* XXX for now we require server authentication */
      if (!state->servermutual)
	return GSASL_AUTHENTICATION_ERROR;

      /* Decide policy here: non-infrastructure, infrastructure or proxy.
       *
       * A callback to decide should be added, but without the default
       * should be:
       *
       * IF shishi_tktset_get_for_server() THEN
       *    INFRASTRUCTURE MODE
       * ELSE IF shishi_realm_for_server(server) THEN
       *    PROXY INFRASTRUCTURE (then fallback to NIM?)
       * ELSE
       *    NON-INFRASTRUCTURE MODE
       */
      state->step = STEP_NONINFRA_SEND_APREQ;	/* only NIM for now.. */
      /* fall through */

    case STEP_NONINFRA_SEND_ASREQ:
      res = shishi_as (state->sh, &state->as);
      if (res)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      if (cb_authentication_id)	/* Shishi defaults to one otherwise */
	{
	  len = *output_len - 1;
	  res = cb_authentication_id (sctx, output, &len);
	  if (res != GSASL_OK)
	    return res;
	  output[len] = '\0';

	  res = shishi_kdcreq_set_cname (state->sh, shishi_as_req (state->as),
					 SHISHI_NT_UNKNOWN, output);
	  if (res != GSASL_OK)
	    return res;
	}

      if (cb_realm)
	{
	  len = *output_len - 1;
	  res = cb_realm (sctx, output, &len);
	  if (res != GSASL_OK)
	    return res;
	}
      else
	len = 0;

      output[len] = '\0';
      res = shishi_kdcreq_set_realm (state->sh, shishi_as_req (state->as),
				     output);
      if (res != GSASL_OK)
	return res;

      if (cb_service)
	{
	  char *sname[3];
	  size_t servicelen = 0;
	  size_t hostnamelen = 0;

	  res = cb_service (sctx, NULL, &servicelen, NULL, &hostnamelen,
			    /* XXX support servicename a'la DIGEST-MD5 too? */
			    NULL, NULL);
	  if (res != GSASL_OK)
	    return res;

	  if (*output_len < servicelen + 1 + hostnamelen + 1)
	    return GSASL_TOO_SMALL_BUFFER;

	  sname[0] = &output[0];
	  sname[1] = &output[servicelen + 2];
	  sname[2] = NULL;

	  res = cb_service (sctx, sname[0], &servicelen,
			    sname[1], &hostnamelen, NULL, NULL);
	  if (res != GSASL_OK)
	    return res;

	  sname[0][servicelen] = '\0';
	  sname[1][hostnamelen] = '\0';

	  res = shishi_kdcreq_set_sname (state->sh, shishi_as_req (state->as),
					 SHISHI_NT_UNKNOWN, sname);
	  if (res != GSASL_OK)
	    return res;
	}

      /* XXX query application for encryption types and set the etype
         field?  Already configured by shishi though... */

      res = shishi_a2d (state->sh, shishi_as_req (state->as),
			output, output_len);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      state->step = STEP_NONINFRA_WAIT_ASREP;

      res = GSASL_NEEDS_MORE;
      break;

    case STEP_NONINFRA_WAIT_ASREP:
      if (shishi_as_rep_der_set (state->as, input, input_len) != SHISHI_OK)
	return GSASL_MECHANISM_PARSE_ERROR;

      /* XXX? password stored in callee's output buffer */
      len = *output_len - 1;
      res = cb_password (sctx, output, &len);
      if (res != GSASL_OK && res != GSASL_NEEDS_MORE)
	return res;
      output[len] = '\0';

      res = shishi_as_rep_process (state->as, NULL, output);
      if (res != SHISHI_OK)
	return GSASL_AUTHENTICATION_ERROR;

      state->step = STEP_NONINFRA_SEND_APREQ;
      /* fall through */

    case STEP_NONINFRA_SEND_APREQ:
      if (*output_len <= CLIENT_HELLO_LEN + SERVER_HELLO_LEN)
	return GSASL_TOO_SMALL_BUFFER;

      if (!(state->clientqop & ~GSASL_QOP_AUTH))
	state->clientmaxbuf = 0;
      else if (cb_maxbuf)
	state->clientmaxbuf = cb_maxbuf (sctx, state->servermaxbuf);
      else
	state->clientmaxbuf = MAXBUF_DEFAULT;

      /* XXX for now we require server authentication */
      output[0] = state->clientqop | MUTUAL;
      {
	uint32_t tmp;

	tmp = ntohl (state->clientmaxbuf);
	memcpy (&output[BITMAP_LEN], &tmp, MAXBUF_LEN);
      }
      memcpy (&output[CLIENT_HELLO_LEN], state->serverhello,
	      SERVER_HELLO_LEN);

      if (cb_authorization_id)
	{
	  len = *output_len - CLIENT_HELLO_LEN + SERVER_HELLO_LEN;
	  res = cb_authorization_id (sctx, &output[CLIENT_HELLO_LEN +
						   SERVER_HELLO_LEN], &len);
	}
      else
	len = 0;

      len += CLIENT_HELLO_LEN + SERVER_HELLO_LEN;
      res = shishi_ap_tktoptionsdata (state->sh,
				      &state->ap,
				      shishi_as_tkt (state->as),
				      SHISHI_APOPTIONS_MUTUAL_REQUIRED,
				      output, len);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      res = shishi_authenticator_add_authorizationdata
	(state->sh, shishi_ap_authenticator (state->ap), -1, output, len);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      /* XXX set realm in AP-REQ and Authenticator */

      res = shishi_ap_req_der (state->ap, output, output_len);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      state->step = STEP_NONINFRA_WAIT_APREP;

      res = GSASL_NEEDS_MORE;
      break;

    case STEP_NONINFRA_WAIT_APREP:
      if (shishi_ap_rep_der_set (state->ap, input, input_len) != SHISHI_OK)
	return GSASL_MECHANISM_PARSE_ERROR;

      res = shishi_ap_rep_verify (state->ap);
      if (res != SHISHI_OK)
	return GSASL_AUTHENTICATION_ERROR;

      state->step = STEP_SUCCESS;

      /* XXX support AP session keys */
      state->sessionkey = shishi_tkt_key (shishi_as_tkt (state->as));

      *output_len = 0;
      res = GSASL_OK;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

int
_gsasl_kerberos_v5_client_encode (Gsasl_session * sctx,
				  void *mech_data,
				  const char *input,
				  size_t input_len,
				  char **output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;
  int res;

  if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_CONF)
    {
      return GSASL_INTEGRITY_ERROR;
    }
  else if (state && state->sessionkey
	   && state->clientqop & GSASL_QOP_AUTH_INT)
    {
      res = shishi_safe (state->sh, &state->safe);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      res = shishi_safe_set_user_data (state->sh,
				       shishi_safe_safe (state->safe),
				       input, input_len);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      res = shishi_safe_build (state->safe, state->sessionkey);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      res = shishi_safe_safe_der (state->safe, output, output_len);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;
    }
  else
    {
      *output_len = input_len;
      *output = malloc (input_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, input, input_len);
    }

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_client_decode (Gsasl_session * sctx,
				  void *mech_data,
				  const char *input,
				  size_t input_len,
				  char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;

  if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_CONF)
    {
      return GSASL_INTEGRITY_ERROR;
    }
  else if (state && state->sessionkey
	   && state->clientqop & GSASL_QOP_AUTH_INT)
    {
      return GSASL_INTEGRITY_ERROR;
    }
  else
    {
      *output_len = input_len;
      *output = malloc (input_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, input, input_len);
    }

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_client_finish (Gsasl_session * sctx, void *mech_data)
{
  struct _Gsasl_kerberos_v5_client_state *state = mech_data;

  shishi_done (state->sh);
  free (state);

  return GSASL_OK;
}
