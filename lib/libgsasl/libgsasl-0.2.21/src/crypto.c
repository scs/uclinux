/* crypto.c --- Simple crypto wrappers for applications.
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

#include "gc.h"

/**
 * gsasl_nonce:
 * @data: output array to be filled with unpredictable random data.
 * @datalen: size of output array.
 *
 * Store unpredictable data of given size in the provided buffer.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_nonce (char *data, size_t datalen)
{
  return gc_nonce (data, datalen);
}

/**
 * gsasl_random:
 * @data: output array to be filled with strong random data.
 * @datalen: size of output array.
 *
 * Store cryptographically strong random data of given size in the
 * provided buffer.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_random (char *data, size_t datalen)
{
  return gc_random (data, datalen);
}

/**
 * gsasl_md5:
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @out: newly allocated character array with hash of data.
 *
 * Compute hash of data using MD5.  The @out buffer must be
 * deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_md5 (const char *in, size_t inlen, char *out[16])
{
  *out = malloc (16);
  if (!*out)
    return GSASL_MALLOC_ERROR;
  return gc_md5 (in, inlen, *out);
}

/**
 * gsasl_hmac_md5:
 * @key: input character array with key to use.
 * @keylen: length of input character array with key to use.
 * @in: input character array of data to hash.
 * @inlen: length of input character array of data to hash.
 * @outhash: newly allocated character array with keyed hash of data.
 *
 * Compute keyed checksum of data using HMAC-MD5.  The @outhash buffer
 * must be deallocated by the caller.
 *
 * Return value: Returns %GSASL_OK iff successful.
 **/
int
gsasl_hmac_md5 (const char *key, size_t keylen,
		const char *in, size_t inlen, char *outhash[16])
{
  *outhash = malloc (16);
  if (!*outhash)
    return GSASL_MALLOC_ERROR;
  return gc_hmac_md5 (key, keylen, in, inlen, *outhash);
}
