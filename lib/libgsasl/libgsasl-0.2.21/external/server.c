/* server.c --- EXTERNAL mechanism as defined in RFC 2222, server side.
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
#include "external.h"

/* Get memchr. */
#include <string.h>

int
_gsasl_external_server_step (Gsasl_session * sctx,
			     void *mech_data,
			     const char *input, size_t input_len,
			     char **output, size_t * output_len)
{
  *output_len = 0;
  *output = NULL;

  if (!input)
    return GSASL_NEEDS_MORE;

  /* Quoting rfc2222bis-09:
   * extern-resp       = *( UTF8-char-no-nul )
   * UTF8-char-no-nul  = UTF8-1-no-nul / UTF8-2 / UTF8-3 / UTF8-4
   * UTF8-1-no-nul     = %x01-7F */
  if (memchr (input, '\0', input_len))
    return GSASL_MECHANISM_PARSE_ERROR;

  /* FIXME: Validate that input is UTF-8. */

  if (input_len > 0)
    gsasl_property_set_raw (sctx, GSASL_AUTHZID, input, input_len);
  else
    gsasl_property_set (sctx, GSASL_AUTHZID, NULL);

  return gsasl_callback (NULL, sctx, GSASL_VALIDATE_EXTERNAL);
}
