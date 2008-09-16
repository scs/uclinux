/* server.c --- Experimental SASL mechanism KERBEROS_V5, server side.
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

struct _Gsasl_kerberos_v5_server_state
{
  int firststep;
  Shishi *sh;
  char serverhello[BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN];
  char *random;
  int serverqops;
  uint32_t servermaxbuf;
  int clientqop;
  int clientmutual;
  uint32_t clientmaxbuf;
  char *username;
  char *userrealm;
  char *serverrealm;
  char *serverservice;
  char *serverhostname;
  char *password;
  Shishi_key *userkey;		/* user's key derived with string2key */
  Shishi_key *sessionkey;	/* shared between client and server */
  Shishi_key *sessiontktkey;	/* known only by server */
  Shishi_ap *ap;
  Shishi_as *as;
  Shishi_safe *safe;
};

int
_gsasl_kerberos_v5_server_init (Gsasl_ctx * ctx)
{
  if (!shishi_check_version (SHISHI_VERSION))
    return GSASL_UNKNOWN_MECHANISM;

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_server_start (Gsasl_session * sctx, void **mech_data)
{
  struct _Gsasl_kerberos_v5_server_state *state;
  int err;

  state = malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;
  memset (state, 0, sizeof (*state));

  state->random = (char *) malloc (RANDOM_LEN);
  if (state->random == NULL)
    return GSASL_MALLOC_ERROR;

  err = shishi_init_server (&state->sh);
  if (err)
    return GSASL_KERBEROS_V5_INIT_ERROR;

  err = shishi_randomize (state->sh, state->random, RANDOM_LEN);
  if (err)
    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

  /* This can be pretty much anything, the client will never have it. */
  err = shishi_key_random (state->sh, SHISHI_AES256_CTS_HMAC_SHA1_96,
			   &state->sessiontktkey);
  if (err)
    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

  err = shishi_as (state->sh, &state->as);
  if (err)
    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

  state->firststep = 1;
  state->serverqops = GSASL_QOP_AUTH | GSASL_QOP_AUTH_INT;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_kerberos_v5_server_step (Gsasl_session * sctx,
				void *mech_data,
				const char *input,
				size_t input_len,
				char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;
  Gsasl_server_callback_realm cb_realm;
  Gsasl_server_callback_qop cb_qop;
  Gsasl_server_callback_maxbuf cb_maxbuf;
  Gsasl_server_callback_cipher cb_cipher;
  Gsasl_server_callback_retrieve cb_retrieve;
  Gsasl_server_callback_service cb_service;
  unsigned char buf[BUFSIZ];
  size_t buflen;
  Gsasl_ctx *ctx;
  ASN1_TYPE asn1;
  int err;

  ctx = gsasl_server_ctx_get (sctx);
  if (ctx == NULL)
    return GSASL_CANNOT_GET_CTX;

  cb_realm = gsasl_server_callback_realm_get (ctx);
  cb_qop = gsasl_server_callback_qop_get (ctx);
  cb_maxbuf = gsasl_server_callback_maxbuf_get (ctx);
  cb_retrieve = gsasl_server_callback_retrieve_get (ctx);
  cb_service = gsasl_server_callback_service_get (ctx);
  if (cb_service == NULL)
    return GSASL_NEED_SERVER_SERVICE_CALLBACK;

  if (state->firststep)
    {
      uint32_t tmp;
      unsigned char *p;

      /*
       * The initial server packet should contain one octet containing
       * a bit mask of supported security layers, four octets
       * indicating the maximum cipher-text buffer size the server is
       * able to receive (or 0 if no security layers are supported) in
       * network byte order, and then 16 octets containing random data
       * (see [4] on how random data might be generated).
       *
       * The security layers and their corresponding bit-masks are as
       * follows:
       *
       *       Bit 0 No security layer
       *       Bit 1 Integrity (KRB-SAFE) protection
       *       Bit 2 Privacy (KRB-PRIV) protection
       *       Bit 3 Mutual authentication is required (AP option MUTUAL-
       *             REQUIRED must also be present).
       *
       * Other bit-masks may be defined in the future; bits which are
       * not understood must be negotiated off.
       *
       */
      if (output && *output_len < BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN)
	return GSASL_TOO_SMALL_BUFFER;

      p = &state->serverhello[0];

      if (cb_qop)
	state->serverqops = cb_qop (sctx);
      *p = 0;
      if (state->serverqops & GSASL_QOP_AUTH)
	*p |= GSASL_QOP_AUTH;
      if (state->serverqops & GSASL_QOP_AUTH_INT)
	*p |= GSASL_QOP_AUTH_INT;
      if (state->serverqops & GSASL_QOP_AUTH_CONF)
	*p |= GSASL_QOP_AUTH_CONF;
      /* XXX we always require mutual authentication for now */
      *p |= MUTUAL;

      if (!(state->serverqops & ~GSASL_QOP_AUTH))
	state->servermaxbuf = 0;
      else if (cb_maxbuf)
	state->servermaxbuf = cb_maxbuf (sctx);
      else
	state->servermaxbuf = MAXBUF_DEFAULT;

      tmp = htonl (state->servermaxbuf);
      memcpy (&state->serverhello[BITMAP_LEN], &tmp, MAXBUF_LEN);
      memcpy (&state->serverhello[BITMAP_LEN + MAXBUF_LEN],
	      state->random, RANDOM_LEN);

      if (output)
	memcpy (output, state->serverhello, SERVER_HELLO_LEN);
      *output_len = BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN;

      state->firststep = 0;

      return GSASL_NEEDS_MORE;
    }

  if (cb_retrieve)
    {
      /* Non-infrastructure mode */

      if (*output_len < 2048)
	return GSASL_TOO_SMALL_BUFFER;

      if (shishi_as_req_der_set (state->as, input, input_len) == SHISHI_OK)
	{
	  Shishi_tkt *tkt;
	  int etype, i;

	  tkt = shishi_as_tkt (state->as);
	  if (!tkt)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	  i = 1;
	  do
	    {
	      err = shishi_kdcreq_etype (state->sh,
					 shishi_as_req (state->as),
					 &etype, i);
	      if (err == SHISHI_OK && shishi_cipher_supported_p (etype))
		break;
	    }
	  while (err == SHISHI_OK);
	  if (err != SHISHI_OK)
	    return err;

	  /* XXX use a "preferred server kdc etype" from shishi instead? */
	  err = shishi_key_random (state->sh, etype, &state->sessionkey);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	  err = shishi_tkt_key_set (tkt, state->sessionkey);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	  buflen = sizeof (buf) - 1;
	  err = shishi_kdcreq_cname_get (state->sh,
					 shishi_as_req (state->as),
					 buf, &buflen);
	  if (err != SHISHI_OK)
	    return err;
	  buf[buflen] = '\0';
	  state->username = strdup (buf);

	  buflen = sizeof (buf) - 1;
	  err = shishi_kdcreq_realm_get (state->sh,
					 shishi_as_req (state->as),
					 buf, &buflen);
	  if (err != SHISHI_OK)
	    return err;
	  buf[buflen] = '\0';
	  state->userrealm = strdup (buf);

	  buflen = sizeof (buf) - 1;
	  err = cb_retrieve (sctx, state->username, NULL, state->userrealm,
			     NULL, &buflen);
	  if (err != GSASL_OK)
	    return err;

	  state->password = malloc (buflen + 1);
	  if (state->password == NULL)
	    return GSASL_MALLOC_ERROR;

	  err = cb_retrieve (sctx, state->username, NULL, state->userrealm,
			     state->password, &buflen);
	  if (err != GSASL_OK)
	    return err;
	  state->password[buflen] = '\0';

	  buflen = sizeof (buf) - 1;
	  if (cb_realm)
	    {
	      err = cb_realm (sctx, buf, &buflen, 0);
	      if (err != GSASL_OK)
		return err;
	    }
	  else
	    buflen = 0;
	  buf[buflen] = '\0';
	  state->serverrealm = strdup (buf);

	  buflen = sizeof (buf) - 1;
	  err = cb_service (sctx, buf, &buflen, NULL, NULL);
	  if (err != GSASL_OK)
	    return err;
	  buf[buflen] = '\0';
	  state->serverservice = strdup (buf);

	  buflen = sizeof (buf) - 1;
	  err = cb_service (sctx, NULL, NULL, buf, &buflen);
	  if (err != GSASL_OK)
	    return err;
	  buf[buflen] = '\0';
	  state->serverhostname = strdup (buf);

	  /* XXX do some checking on realm and server name?  Right now
	     we simply doesn't care about what client requested and
	     return a ticket for this server.  This is bad. */

	  err = shishi_tkt_clientrealm_set (tkt, state->userrealm,
					    state->username);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	  {
	    char *p;
	    p = malloc (strlen (state->serverservice) + strlen ("/") +
			strlen (state->serverhostname) + 1);
	    if (p == NULL)
	      return GSASL_MALLOC_ERROR;
	    sprintf (p, "%s/%s", state->serverservice, state->serverhostname);
	    err = shishi_tkt_serverrealm_set (tkt, state->serverrealm, p);
	    free (p);
	    if (err)
	      return GSASL_KERBEROS_V5_INTERNAL_ERROR;
	  }

	  buflen = sizeof (buf);
	  err = shishi_as_derive_salt (state->sh,
				       shishi_as_req (state->as),
				       shishi_as_rep (state->as),
				       buf, &buflen);
	  if (err != SHISHI_OK)
	    return err;

	  err = shishi_key_from_string (state->sh,
					etype,
					state->password,
					strlen (state->password),
					buf, buflen, NULL, &state->userkey);
	  if (err != SHISHI_OK)
	    return err;

	  err = shishi_tkt_build (tkt, state->sessiontktkey);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	  err = shishi_as_rep_build (state->as, state->userkey);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

#if DEBUG
	  shishi_kdcreq_print (state->sh, stderr, shishi_as_req (state->as));
	  shishi_encticketpart_print (state->sh, stderr,
				      shishi_tkt_encticketpart (tkt));
	  shishi_ticket_print (state->sh, stderr, shishi_tkt_ticket (tkt));
	  shishi_enckdcreppart_print (state->sh, stderr,
				      shishi_tkt_enckdcreppart (state->as));
	  shishi_kdcrep_print (state->sh, stderr, shishi_as_rep (state->as));
#endif

	  err = shishi_as_rep_der (state->as, output, output_len);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	  return GSASL_NEEDS_MORE;
	}
      else if ((asn1 = shishi_der2asn1_apreq (state->sh, input, input_len)))
	{
	  int adtype;

	  err = shishi_ap (state->sh, &state->ap);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	  shishi_ap_req_set (state->ap, asn1);

	  err = shishi_ap_req_process (state->ap, state->sessiontktkey);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

#if DEBUG
	  shishi_apreq_print (state->sh, stderr, shishi_ap_req (state->ap));
	  shishi_ticket_print (state->sh, stderr,
			       shishi_tkt_ticket (shishi_ap_tkt (state->ap)));
	  shishi_authenticator_print (state->sh, stderr,
				      shishi_ap_authenticator (state->ap));
#endif

	  buflen = sizeof (buf);
	  err = shishi_authenticator_authorizationdata
	    (state->sh, shishi_ap_authenticator (state->ap),
	     &adtype, buf, &buflen, 1);
	  if (err)
	    return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	  if (adtype != 0xFF /* -1 in one-complements form */  ||
	      buflen < CLIENT_HELLO_LEN + SERVER_HELLO_LEN)
	    return GSASL_AUTHENTICATION_ERROR;

	  {
	    unsigned char clientbitmap;

	    memcpy (&clientbitmap, &buf[0], BITMAP_LEN);
	    state->clientqop = 0;
	    if (clientbitmap & GSASL_QOP_AUTH)
	      state->clientqop |= GSASL_QOP_AUTH;
	    if (clientbitmap & GSASL_QOP_AUTH_INT)
	      state->clientqop |= GSASL_QOP_AUTH_INT;
	    if (clientbitmap & GSASL_QOP_AUTH_CONF)
	      state->clientqop |= GSASL_QOP_AUTH_CONF;
	    if (clientbitmap & MUTUAL)
	      state->clientmutual = 1;
	  }
	  memcpy (&state->clientmaxbuf, &input[BITMAP_LEN], MAXBUF_LEN);
	  state->clientmaxbuf = ntohl (state->clientmaxbuf);

	  if (!(state->clientqop & state->serverqops))
	    return GSASL_AUTHENTICATION_ERROR;

	  /* XXX check clientmaxbuf too */

	  if (memcmp (&buf[CLIENT_HELLO_LEN],
		      state->serverhello, SERVER_HELLO_LEN) != 0)
	    return GSASL_AUTHENTICATION_ERROR;

	  {
	    char cksum[BUFSIZ];
	    int cksumlen;
	    int cksumtype;
	    Shishi_key *key;

	    key = shishi_tkt_key (shishi_as_tkt (state->as));
	    cksumtype =
	      shishi_cipher_defaultcksumtype (shishi_key_type (key));
	    cksumlen = sizeof (cksum);
	    err = shishi_checksum (state->sh, key,
				   SHISHI_KEYUSAGE_APREQ_AUTHENTICATOR_CKSUM,
				   cksumtype, buf, buflen, cksum, &cksumlen);
	    if (err != SHISHI_OK)
	      return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	    buflen = sizeof (buf);
	    err = shishi_authenticator_cksum
	      (state->sh,
	       shishi_ap_authenticator (state->ap), &cksumtype, buf, &buflen);
	    if (err != SHISHI_OK)
	      return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	    if (buflen != cksumlen || memcmp (buf, cksum, buflen) != 0)
	      return GSASL_AUTHENTICATION_ERROR;
	  }

	  /* XXX use authorization_id */

	  if (state->clientmutual)
	    {
	      err = shishi_ap_rep_build (state->ap);
	      if (err)
		return GSASL_KERBEROS_V5_INTERNAL_ERROR;

	      err = shishi_ap_rep_der (state->ap, output, output_len);
	      if (err)
		return GSASL_KERBEROS_V5_INTERNAL_ERROR;
	    }
	  else
	    *output_len = 0;

	  return GSASL_OK;
	}
    }
  else
    {
      /* XXX Currently we only handle AS-REQ and AP-REQ in
         non-infrastructure mode.  Supporting infrastructure mode is
         simple, just send the AS-REQ to the KDC and wait for AS-REP
         instead of creating AS-REP locally.

         We should probably have a callback to decide policy:
         1) non-infrastructure mode (NIM) only
         2) infrastructure mode (IM) only
         3) proxied infrastructure mode (PIM) only
         4) NIM with fallback to IM (useful for local server overrides)
         5) IM with fallback to NIM (useful for admins if KDC is offline)
         6) ...etc with PIM too
       */
      return GSASL_NEED_SERVER_RETRIEVE_CALLBACK;
    }

  *output_len = 0;
  return GSASL_NEEDS_MORE;
}

int
_gsasl_kerberos_v5_server_encode (Gsasl_session * sctx,
				  void *mech_data,
				  const char *input,
				  size_t input_len,
				  char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;
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
_gsasl_kerberos_v5_server_decode (Gsasl_session * sctx,
				  void *mech_data,
				  const char *input,
				  size_t input_len,
				  char *output, size_t * output_len)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;
  int res;

  if (state && state->sessionkey && state->clientqop & GSASL_QOP_AUTH_CONF)
    {
      return GSASL_INTEGRITY_ERROR;
    }
  else if (state && state->sessionkey
	   && state->clientqop & GSASL_QOP_AUTH_INT)
    {
      Shishi_asn1 asn1safe;

      res = shishi_safe (state->sh, &state->safe);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      res = shishi_safe_safe_der_set (state->safe, input, input_len);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      res = shishi_safe_verify (state->safe, state->sessionkey);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      res = shishi_safe_user_data (state->sh, shishi_safe_safe (state->safe),
				   output, output_len);
      if (res != SHISHI_OK)
	return GSASL_KERBEROS_V5_INTERNAL_ERROR;

      return GSASL_OK;
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
_gsasl_kerberos_v5_server_finish (Gsasl_session * sctx, void *mech_data)
{
  struct _Gsasl_kerberos_v5_server_state *state = mech_data;

  shishi_done (state->sh);
  if (state->username)
    free (state->username);
  if (state->password)
    free (state->password);
  if (state->random)
    free (state->random);
  free (state);

  return GSASL_OK;
}
