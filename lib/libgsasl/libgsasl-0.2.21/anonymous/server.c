/* server.c --- ANONYMOUS mechanism as defined in RFC 2245, server side.
 * Copyright (C) 2002, 2003, 2004, 2005  Simon Josefsson
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
#include "anonymous.h"

int
_gsasl_anonymous_server_step (Gsasl_session * sctx,
			      void *mech_data,
			      const char *input, size_t input_len,
			      char **output, size_t * output_len)
{
  *output = NULL;
  *output_len = 0;

  if (!input)
    return GSASL_NEEDS_MORE;

  /* token       = 1*255TCHAR
     The <token> production is restricted to 255 UTF-8 encoded Unicode
     characters.   As the encoding of a characters uses a sequence of 1
     to 4 octets, a token may be long as 1020 octets. */
  if (input_len == 0 || input_len > 1020)
    return GSASL_MECHANISM_PARSE_ERROR;

  /* FIXME: Validate that input is UTF-8. */

  gsasl_property_set_raw (sctx, GSASL_ANONYMOUS_TOKEN, input, input_len);

  return gsasl_callback (NULL, sctx, GSASL_VALIDATE_ANONYMOUS);
}
