/* ntlm.c --- Implementation of non-standard SASL mechanism NTLM, client side.
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

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy. */
#include <string.h>

/* Get specification. */
#include "x-ntlm.h"

#include <ntlm.h>

struct _Gsasl_ntlm_state
{
  int step;
};
typedef struct _Gsasl_ntlm_state _Gsasl_ntlm_state;

int
_gsasl_ntlm_client_start (Gsasl_session * sctx, void **mech_data)
{
  _Gsasl_ntlm_state *state;

  state = (_Gsasl_ntlm_state *) malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_ntlm_client_step (Gsasl_session * sctx,
			 void *mech_data,
			 const char *input, size_t input_len,
			 char **output, size_t * output_len)
{
  _Gsasl_ntlm_state *state = mech_data;
  tSmbNtlmAuthRequest request;
  tSmbNtlmAuthChallenge challenge;
  tSmbNtlmAuthResponse response;
  const char *domain = gsasl_property_get (sctx, GSASL_REALM);
  const char *authid = gsasl_property_get (sctx, GSASL_AUTHID);
  const char *password;
  int res;

  if (!authid)
    return GSASL_NO_AUTHID;

  switch (state->step)
    {
    case 0:
      /* Isn't this just the IMAP continuation char?  Not part of SASL mech.
         if (input_len != 1 && *input != '+')
         return GSASL_MECHANISM_PARSE_ERROR; */

      buildSmbNtlmAuthRequest (&request, authid, domain);

      *output_len = SmbLength (&request);
      *output = malloc (*output_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, &request, *output_len);

      /* dumpSmbNtlmAuthRequest(stdout, &request); */

      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 1:
      if (input_len > sizeof (challenge))
	return GSASL_MECHANISM_PARSE_ERROR;

      /* Hand crafted challenge for parser testing:
         TlRMTVNTUAAAAAAAAAAAAAAAAAAAAGFiY2RlZmdoMDEyMzQ1Njc4ODY2NDQwMTIz */

      memcpy (&challenge, input, input_len);

      password = gsasl_property_get (sctx, GSASL_PASSWORD);
      if (!password)
	return GSASL_NO_PASSWORD;

      buildSmbNtlmAuthResponse (&challenge, &response, authid, password);

      *output_len = SmbLength (&response);
      *output = malloc (*output_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, &response, *output_len);

      /* dumpSmbNtlmAuthResponse(stdout, &response); */

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
_gsasl_ntlm_client_finish (Gsasl_session * sctx, void *mech_data)
{
  _Gsasl_ntlm_state *state = mech_data;

  if (state)
    free (state);
}
