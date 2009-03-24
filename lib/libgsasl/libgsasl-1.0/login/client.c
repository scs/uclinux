/* client.c --- Non-standard SASL mechanism LOGIN, client side.
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

/* Get malloc, free. */
#include <stdlib.h>

/* Get strlen. */
#include <string.h>

/* Get specification. */
#include "login.h"

struct _Gsasl_login_client_state
{
  int step;
};

int
_gsasl_login_client_start (Gsasl_session * sctx, void **mech_data)
{
  struct _Gsasl_login_client_state *state;

  state = malloc (sizeof (*state));
  if (state == NULL)
    return GSASL_MALLOC_ERROR;

  state->step = 0;

  *mech_data = state;

  return GSASL_OK;
}

int
_gsasl_login_client_step (Gsasl_session * sctx,
			  void *mech_data,
			  const char *input, size_t input_len,
			  char **output, size_t * output_len)
{
  struct _Gsasl_login_client_state *state = mech_data;
  const char *p;
  int res;

  switch (state->step)
    {
    case 0:
      p = gsasl_property_get (sctx, GSASL_AUTHID);
      if (!p)
	return GSASL_NO_AUTHID;

      *output = strdup (p);
      *output_len = strlen (p);

      state->step++;
      res = GSASL_NEEDS_MORE;
      break;

    case 1:
      p = gsasl_property_get (sctx, GSASL_PASSWORD);
      if (!p)
	return GSASL_NO_PASSWORD;

      *output = strdup (p);
      *output_len = strlen (*output);

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
_gsasl_login_client_finish (Gsasl_session * sctx, void *mech_data)
{
  struct _Gsasl_login_client_state *state = mech_data;

  if (!state)
    return;

  free (state);
}
