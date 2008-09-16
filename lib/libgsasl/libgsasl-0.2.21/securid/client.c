/* client.c --- SASL mechanism SECURID from RFC 2808, client side.
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
#include "securid.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get strdup, strlen. */
#include <string.h>

#define PASSCODE "passcode"
#define PIN "pin"

int
_gsasl_securid_client_start (Gsasl_session * sctx, void **mech_data)
{
  int *step;

  step = (int *) malloc (sizeof (*step));
  if (step == NULL)
    return GSASL_MALLOC_ERROR;

  *step = 0;

  *mech_data = step;

  return GSASL_OK;
}

int
_gsasl_securid_client_step (Gsasl_session * sctx,
			    void *mech_data,
			    const char *input,
			    size_t input_len,
			    char **output, size_t * output_len)
{
  int *step = mech_data;
  const char *authzid = NULL, *authid = NULL, *passcode = NULL, *pin = NULL;
  size_t authzidlen, authidlen, passcodelen, pinlen;
  int do_pin = 0;
  int res;

  switch (*step)
    {
    case 1:
      if (input_len == strlen (PASSCODE) &&
	  memcmp (input, PASSCODE, strlen (PASSCODE)) == 0)
	{
	  *step = 0;
	}
      else if (input_len >= strlen (PIN) &&
	       memcmp (input, PIN, strlen (PIN)) == 0)
	{
	  do_pin = 1;
	  *step = 0;
	}
      else
	{
	  *output_len = 0;
	  res = GSASL_OK;
	  break;
	}
      /* fall through */

    case 0:
      authzid = gsasl_property_get (sctx, GSASL_AUTHZID);
      if (authzid)
	authzidlen = strlen (authzid);
      else
	authzidlen = 0;

      authid = gsasl_property_get (sctx, GSASL_AUTHID);
      if (!authid)
	return GSASL_NO_AUTHID;
      authidlen = strlen (authid);

      passcode = gsasl_property_get (sctx, GSASL_PASSCODE);
      if (!passcode)
	return GSASL_NO_PASSCODE;
      passcodelen = strlen (passcode);

      if (do_pin)
	{
	  if (input_len > strlen (PIN))
	    gsasl_property_set_raw (sctx, GSASL_SUGGESTED_PIN,
				    &input[strlen (PIN)],
				    input_len - strlen (PIN));

	  pin = gsasl_property_get (sctx, GSASL_PIN);
	  if (!pin)
	    return GSASL_NO_PIN;
	  pinlen = strlen (pin);
	}

      *output_len = authzidlen + 1 + authidlen + 1 + passcodelen + 1;
      if (do_pin)
	*output_len += pinlen + 1;
      *output = malloc (*output_len);
      if (*output == NULL)
	return GSASL_MALLOC_ERROR;

      if (authzid)
	memcpy (*output, authzid, authzidlen);
      (*output)[authzidlen] = '\0';
      memcpy (*output + authzidlen + 1, authid, authidlen);
      (*output)[authzidlen + 1 + authidlen] = '\0';
      memcpy (*output + authzidlen + 1 + authidlen + 1, passcode,
	      passcodelen);
      (*output)[authzidlen + 1 + authidlen + 1 + passcodelen] = '\0';
      if (do_pin)
	{
	  memcpy (*output + authzidlen + 1 + authidlen + 1 + passcodelen + 1,
		  pin, pinlen);
	  (*output)[authzidlen + 1 + authidlen + 1 + passcodelen + 1 +
		    pinlen] = '\0';
	}

      (*step)++;
      res = GSASL_OK;
      break;

    case 2:
      *output_len = 0;
      *output = NULL;
      (*step)++;
      res = GSASL_OK;
      break;

    default:
      res = GSASL_MECHANISM_CALLED_TOO_MANY_TIMES;
      break;
    }

  return res;
}

void
_gsasl_securid_client_finish (Gsasl_session * sctx, void *mech_data)
{
  int *step = mech_data;

  if (step)
    free (step);
}
