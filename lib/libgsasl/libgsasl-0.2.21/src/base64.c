/* base64.c --- Base64 encoding/decoding functions.
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
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#include "internal.h"

#include "base64.h"

/**
 * gsasl_base64_to:
 * @in: input byte array
 * @inlen: size of input byte array
 * @out: pointer to newly allocated output byte array
 * @outlen: pointer to size of newly allocated output byte array
 *
 * Encode data as base64.  The string is zero terminated, and OUTLEN
 * holds the length excluding the terminating zero.  The OUT buffer
 * must be deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK on success, or %GSASL_MALLOC_ERROR
 *   if input was too large or memory allocation fail.
 *
 * Since: 0.2.2
 **/
int
gsasl_base64_to (const char *in, size_t inlen, char **out, size_t * outlen)
{
  size_t len = base64_encode_alloc (in, inlen, out);

  if (outlen)
    *outlen = len;

  if (*out == NULL)
    return GSASL_MALLOC_ERROR;

  return GSASL_OK;
}

/**
 * gsasl_base64_from:
 * @in: input byte array
 * @inlen: size of input byte array
 * @out: pointer to newly allocated output byte array
 * @outlen: pointer to size of newly allocated output byte array
 *
 * Decode Base64 data.  The OUT buffer must be deallocated by the
 * caller.
 *
 * Return value: Returns %GSASL_OK on success, %GSASL_BASE64_ERROR if
 *   input was invalid, and %GSASL_MALLOC_ERROR on memory allocation
 *   errors.
 *
 * Since: 0.2.2
 **/
int
gsasl_base64_from (const char *in, size_t inlen, char **out, size_t * outlen)
{
  int ok = base64_decode_alloc (in, inlen, out, outlen);

  if (!ok)
    return GSASL_BASE64_ERROR;

  if (*out == NULL)
    return GSASL_MALLOC_ERROR;

  return GSASL_OK;
}
