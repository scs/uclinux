/* xcode.c --- Encode and decode application payload in libgsasl session.
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

static int
_gsasl_code (Gsasl_session * sctx,
	     Gsasl_code_function code,
	     const char *input, size_t input_len,
	     char **output, size_t * output_len)
{

  if (code == NULL)
    {
      *output_len = input_len;
      *output = malloc (*output_len);
      if (!*output)
	return GSASL_MALLOC_ERROR;

      memcpy (*output, input, input_len);
      return GSASL_OK;
    }

  return code (sctx, sctx->mech_data, input, input_len, output, output_len);
}

/**
 * gsasl_encode:
 * @sctx: libgsasl session handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: newly allocated output byte array.
 * @output_len: size of output byte array.
 *
 * Encode data according to negotiated SASL mechanism.  This might mean
 * that data is integrity or privacy protected.
 *
 * The @output buffer is allocated by this function, and it is the
 * responsibility of caller to deallocate it by calling free(@output).
 *
 * Return value: Returns GSASL_OK if encoding was successful, otherwise
 * an error code.
 **/
int
gsasl_encode (Gsasl_session * sctx,
	      const char *input, size_t input_len,
	      char **output, size_t * output_len)
{
  Gsasl_code_function code;

  if (sctx->clientp)
    code = sctx->mech->client.encode;
  else
    code = sctx->mech->server.encode;

  return _gsasl_code (sctx, code, input, input_len, output, output_len);
}

/**
 * gsasl_decode:
 * @sctx: libgsasl session handle.
 * @input: input byte array.
 * @input_len: size of input byte array.
 * @output: newly allocated output byte array.
 * @output_len: size of output byte array.
 *
 * Decode data according to negotiated SASL mechanism.  This might mean
 * that data is integrity or privacy protected.
 *
 * The @output buffer is allocated by this function, and it is the
 * responsibility of caller to deallocate it by calling free(@output).
 *
 * Return value: Returns GSASL_OK if encoding was successful, otherwise
 * an error code.
 **/
int
gsasl_decode (Gsasl_session * sctx,
	      const char *input, size_t input_len,
	      char **output, size_t * output_len)
{
  Gsasl_code_function code;

  if (sctx->clientp)
    code = sctx->mech->client.decode;
  else
    code = sctx->mech->server.decode;

  return _gsasl_code (sctx, code, input, input_len, output, output_len);
}
