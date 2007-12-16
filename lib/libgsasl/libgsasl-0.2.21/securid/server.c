/* server.c --- SASL mechanism SECURID from RFC 2808, server side.
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
#include "securid.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memchr, strdup, strlen. */
#include <string.h>

#define PASSCODE "passcode"
#define PIN "pin"

int
_gsasl_securid_server_step (Gsasl_session * sctx,
			    void *mech_data,
			    const char *input, size_t input_len,
			    char **output, size_t * output_len)
{
  const char *authorization_id = NULL;
  const char *authentication_id = NULL;
  const char *passcode = NULL;
  const char *suggestedpin;
  char *pin = NULL;
  int res;
  size_t len;

  if (input_len == 0)
    {
      *output_len = 0;
      *output = NULL;
      return GSASL_NEEDS_MORE;
    }

  authorization_id = input;
  authentication_id = memchr (input, '\0', input_len - 1);
  if (authentication_id)
    {
      authentication_id++;
      passcode = memchr (authentication_id, '\0',
			 input_len - strlen (authorization_id) - 1 - 1);
      if (passcode)
	{
	  passcode++;
	  pin = memchr (passcode, '\0', input_len -
			strlen (authorization_id) - 1 -
			strlen (authentication_id) - 1 - 1);
	  if (pin)
	    {
	      pin++;
	      if (pin && !*pin)
		pin = NULL;
	    }
	}
    }

  if (passcode == NULL)
    return GSASL_MECHANISM_PARSE_ERROR;

  gsasl_property_set (sctx, GSASL_AUTHID, authentication_id);
  gsasl_property_set (sctx, GSASL_AUTHZID, authorization_id);
  gsasl_property_set (sctx, GSASL_PASSCODE, passcode);
  if (pin)
    gsasl_property_set (sctx, GSASL_PIN, pin);
  else
    gsasl_property_set (sctx, GSASL_PIN, NULL);

  res = gsasl_callback (NULL, sctx, GSASL_VALIDATE_SECURID);
  switch (res)
    {
    case GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE:
      *output = strdup (PASSCODE);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      *output_len = strlen (PASSCODE);
      res = GSASL_NEEDS_MORE;
      break;

    case GSASL_SECURID_SERVER_NEED_NEW_PIN:
      suggestedpin = gsasl_property_get (sctx, GSASL_SUGGESTED_PIN);
      if (suggestedpin)
	len = strlen (suggestedpin);
      else
	len = 0;
      *output_len = strlen (PIN) + len;
      *output = malloc (*output_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;
      memcpy (*output, PIN, strlen (PIN));
      if (suggestedpin)
	memcpy (*output + strlen (PIN), suggestedpin, len);
      res = GSASL_NEEDS_MORE;
      break;

    default:
      *output_len = 0;
      *output = NULL;
      break;
    }

  return res;
}
