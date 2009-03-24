/* server.c --- SASL mechanism GS2, server side.
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
 * License along with GNU SASL Library; if not, write to the Free
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "gs2.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

#ifdef HAVE_LIBGSS
# include <gss.h>
#elif HAVE_GSSAPI_H		/* Heimdal GSSAPI */
# include <gssapi.h>
#else /* MIT GSSAPI */
# ifdef HAVE_GSSAPI_GSSAPI_H
#  include <gssapi/gssapi.h>
# endif
# ifdef HAVE_GSSAPI_GSSAPI_GENERIC_H
#  include <gssapi/gssapi_generic.h>
# endif
#endif

#include "gs2parser.h"

struct _Gsasl_gs2_server_state
{
  int step;
  gss_name_t client;
  gss_cred_id_t cred;
  gss_ctx_id_t context;
};
typedef struct _Gsasl_gs2_server_state _Gsasl_gs2_server_state;

int
_gsasl_gs2_server_start (Gsasl_session * sctx, void **mech_data)
{
  _Gsasl_gs2_server_state *state;
  OM_uint32 maj_stat, min_stat;
  gss_name_t server;
  gss_buffer_desc bufdesc;
  const char *service;
  const char *hostname;

  service = gsasl_property_get (sctx, GSASL_SERVICE);
  if (!service)
    return GSASL_NO_SERVICE;

  hostname = gsasl_property_get (sctx, GSASL_HOSTNAME);
  if (!hostname)
    return GSASL_NO_HOSTNAME;

  /* FIXME: Use asprintf. */

  bufdesc.length = strlen (service) + strlen ("@") + strlen (hostname) + 1;
  bufdesc.value = malloc (bufdesc.length);
  if (bufdesc.value == NULL)
    return GSASL_MALLOC_ERROR;

  sprintf (bufdesc.value, "%s@%s", service, hostname);

  state = (_Gsasl_gs2_server_state *) malloc (sizeof (*state));
  if (state == NULL)
    {
      free (bufdesc.value);
      return GSASL_MALLOC_ERROR;
    }

  maj_stat = gss_import_name (&min_stat, &bufdesc, GSS_C_NT_HOSTBASED_SERVICE,
			      &server);
  free (bufdesc.value);
  if (GSS_ERROR (maj_stat))
    {
      free (state);
      return GSASL_GSSAPI_IMPORT_NAME_ERROR;
    }

  maj_stat = gss_acquire_cred (&min_stat, server, 0,
			       GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
			       &state->cred, NULL, NULL);
  gss_release_name (&min_stat, &server);

  if (GSS_ERROR (maj_stat))
    {
      free (state);
      return GSASL_GSSAPI_ACQUIRE_CRED_ERROR;
    }

  state->step = 0;
  state->context = GSS_C_NO_CONTEXT;
  state->client = NULL;
  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_gs2_server_step (Gsasl_session * sctx,
			void *mech_data,
			const char *input, size_t input_len,
			char **output, size_t * output_len)
{
  _Gsasl_gs2_server_state *state = mech_data;
  gss_buffer_desc bufdesc1, bufdesc2;
  OM_uint32 maj_stat, min_stat;
  gss_buffer_desc client_name;
  gss_OID mech_type;
  char tmp[4];
  int res;
  OM_uint32 ret_flags;
  struct gs2_token tok;

  *output = NULL;
  *output_len = 0;

  switch (state->step)
    {
    case 0:
      if (input_len == 0)
	{
	  res = GSASL_NEEDS_MORE;
	  break;
	}
      state->step++;
      /* fall through */

    case 1:
      res = gs2_parser (input, input_len, &tok);
      if (res < 0)
	return GSASL_MECHANISM_PARSE_ERROR;

      bufdesc1.value = tok.context_token;
      bufdesc1.length = tok.context_length;
      if (state->client)
	{
	  gss_release_name (&min_stat, &state->client);
	  state->client = GSS_C_NO_NAME;
	}

      maj_stat = gss_accept_sec_context (&min_stat,
					 &state->context,
					 state->cred,
					 &bufdesc1,
					 GSS_C_NO_CHANNEL_BINDINGS,
					 &state->client,
					 &mech_type,
					 &bufdesc2, &ret_flags, NULL, NULL);
      if (maj_stat != GSS_S_COMPLETE && maj_stat != GSS_S_CONTINUE_NEEDED)
	return GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR;

      /* XXX check wrap token */

      if (ret_flags & GSS_C_PROT_READY_FLAG)
	{
	  puts ("prot_ready");
	  /* XXX gss_wrap token */
	}

      res = gs2_encode (bufdesc2.value, bufdesc2.length,
			NULL, 0, output, output_len);
      if (res < 0)
	return GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR;

      maj_stat = gss_release_buffer (&min_stat, &bufdesc2);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_RELEASE_BUFFER_ERROR;

      if (maj_stat == GSS_S_COMPLETE)
	state->step++;

      res = GSASL_NEEDS_MORE;
      break;

    case 2:
      memset (tmp, 0xFF, 4);
      tmp[0] = GSASL_QOP_AUTH;
      bufdesc1.length = 4;
      bufdesc1.value = tmp;
      maj_stat = gss_wrap (&min_stat, state->context, 0, GSS_C_QOP_DEFAULT,
			   &bufdesc1, NULL, &bufdesc2);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_WRAP_ERROR;

      *output = malloc (bufdesc2.length);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, bufdesc2.value, bufdesc2.length);
      *output_len = bufdesc2.length;

      maj_stat = gss_release_buffer (&min_stat, &bufdesc2);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_RELEASE_BUFFER_ERROR;

      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 3:
      bufdesc1.value = (void *) input;
      bufdesc1.length = input_len;
      maj_stat = gss_unwrap (&min_stat, state->context, &bufdesc1,
			     &bufdesc2, NULL, NULL);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_UNWRAP_ERROR;

      /* [RFC 2222 section 7.2.1]:
         The client passes this token to GSS_Unwrap and interprets the
         first octet of resulting cleartext as a bit-mask specifying
         the security layers supported by the server and the second
         through fourth octets as the maximum size output_message to
         send to the server.  The client then constructs data, with
         the first octet containing the bit-mask specifying the
         selected security layer, the second through fourth octets
         containing in network byte order the maximum size
         output_message the client is able to receive, and the
         remaining octets containing the authorization identity.  The
         client passes the data to GSS_Wrap with conf_flag set to
         FALSE, and responds with the generated output_message.  The
         client can then consider the server authenticated. */

      if ((((char *) bufdesc2.value)[0] & GSASL_QOP_AUTH) == 0)
	{
	  /* Integrity or privacy unsupported */
	  maj_stat = gss_release_buffer (&min_stat, &bufdesc2);
	  return GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR;
	}

      gsasl_property_set_raw (sctx, GSASL_AUTHZID,
			      (char *) bufdesc2.value + 4,
			      bufdesc2.length - 4);

      maj_stat = gss_display_name (&min_stat, state->client,
				   &client_name, &mech_type);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_DISPLAY_NAME_ERROR;

      gsasl_property_set_raw (sctx, GSASL_GSSAPI_DISPLAY_NAME,
			      client_name.value, client_name.length);

      maj_stat = gss_release_buffer (&min_stat, &bufdesc2);
      if (GSS_ERROR (maj_stat))
	return GSASL_GSSAPI_RELEASE_BUFFER_ERROR;

      res = gsasl_callback (NULL, sctx, GSASL_VALIDATE_GSSAPI);

      state->step++;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

void
_gsasl_gs2_server_finish (Gsasl_session * sctx, void *mech_data)
{
  _Gsasl_gs2_server_state *state = mech_data;
  OM_uint32 min_stat;

  if (!state)
    return;

  if (state->context != GSS_C_NO_CONTEXT)
    gss_delete_sec_context (&min_stat, &state->context, GSS_C_NO_BUFFER);

  if (state->cred != GSS_C_NO_CREDENTIAL)
    gss_release_cred (&min_stat, &state->cred);

  if (state->client != GSS_C_NO_NAME)
    gss_release_name (&min_stat, &state->client);

  free (state);
}
