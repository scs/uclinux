/* gs2parser.h --- GS2 parser.
 * Copyright (C) 2006, 2007  Simon Josefsson
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

#include "gs2parser.h"

#include <stdint.h>

/* Parse a GS2 token in TOKEN of TOKLEN length, check the length
   field, and set the appropriate values in OUT, if OUT is non-NULL.
   The values in OUT that are set points into the TOKEN buffer, so
   they must not be deallocated.  On success, the function sets all
   values in OUT.  Returns 0 on success, or negative on failures
   (i.e., the input is invalid).  */
int
gs2_parser (const char *token, size_t toklen, struct gs2_token *out)
{
  uint32_t context_length, wrap_length;

  if (!out)
    return -1;

  /* Messages shorter than or equal to 8 octets are invalid. */
  if (toklen <= 8)
    return -1;

  context_length =
    (token[0] << 24) & 0xFF000000 |
    (token[1] << 16) & 0xFF0000 |
    (token[2] << 8) & 0xFF00 | (token[3]) & 0xFF;

  wrap_length =
    (token[4] << 24) & 0xFF000000 |
    (token[5] << 16) & 0xFF0000 |
    (token[6] << 8) & 0xFF00 | (token[7]) & 0xFF;

  /* Check that lengths are not out of bounds. */
  if (context_length > toklen || wrap_length > toklen ||
      context_length + wrap_length + 8 != toklen)
    return -1;

  out->context_length = context_length;
  if (context_length > 0)
    out->context_token = token + 8;
  else
    out->context_token = NULL;

  out->wrap_length = wrap_length;
  if (wrap_length > 0)
    out->wrap_token = token + 8 + context_length;
  else
    out->wrap_token = NULL;

  return 0;
}

/* Encode a GS2 token into newly allocated OUT buffer.  CONTEXT is the
   context token, of length CONTEXT_LENGTH.  WRAP is the wrap token,
   of length WRAP_LENGTH.  If OUTLEN is non-NULL, the length of the
   output token is written to it on successful exit.  If OUT is NULL,
   no data is written, but the input lengths are verified, and the
   OUTLEN variable is written (if applicable).  This can be used to
   determine how large the output will be.  Returns 0 on success, or
   negative on failures (i.e., the input is invalid). */
int
gs2_encode (const char *context, size_t context_length,
	    const char *wrap, size_t wrap_length, char **out, size_t * outlen)
{
  size_t totlen = 4 + context_length + wrap_length;
  uint32_t ctxlen;

  /* Reject out of bounds conditions. */
  if (totlen > UINT32_MAX || totlen < context_length || totlen < wrap_length)
    return -1;

  /* Only time we accept NULL inputs is for zero-length inputs. */
  if (context == NULL && context_length != 0)
    return -2;
  if (wrap == NULL && wrap_length != 0)
    return -3;

  if (outlen)
    *outlen = totlen;

  if (!out)
    return 0;

  *out = malloc (*outlen);
  if (!*out)
    return -4;

  (*out)[0] = (context_length >> 24) & 0xFF;
  (*out)[1] = (context_length >> 16) & 0xFF;
  (*out)[2] = (context_length >> 8) & 0xFF;
  (*out)[3] = context_length & 0xFF;

  if (context)
    memcpy (*out + 4, context, context_length);
  if (wrap)
    memcpy (*out + 4 + context_length, wrap, wrap_length);

  return 0;
}
