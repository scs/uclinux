/* digest.c --- Generate a CRAM-MD5 hex encoded HMAC-MD5 response string.
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

#include <string.h>

/* Get prototype. */
#include "digest.h"

/* Get gc_hmac_md5. */
#include "gc.h"

/*
 * From draft-ietf-sasl-crammd5-02.txt:
 *
 *   The latter is computed by applying the keyed MD5 algorithm from
 *   [KEYED-MD5] where the key is a shared secret and the digested
 *   text is the challenge (including angle-brackets). The client
 *   MUST NOT interpret or attempt to validate the contents of the
 *   challenge in any way.
 *
 *   This shared secret is a string known only to the client and
 *   server.  The "digest" parameter itself is a 16-octet value which
 *   is sent in hexadecimal format, using lower-case US-ASCII
 *   characters.
 * ...
 *   digest     = 32(DIGIT / %x61-66)
 *   ; A hexadecimal string using only lower-case
 *   ; letters
 *
 */

#if CRAM_MD5_DIGEST_LEN != 2*GC_MD5_DIGEST_SIZE
# error MD5 length mismatch
#endif

#define HEXCHAR(c) ((c & 0x0F) > 9 ? 'a' + (c & 0x0F) - 10 : '0' + (c & 0x0F))

void
cram_md5_digest (const char *challenge,
		 size_t challengelen,
		 const char *secret,
		 size_t secretlen, char response[CRAM_MD5_DIGEST_LEN])
{
  char hash[GC_MD5_DIGEST_SIZE];
  size_t i;

  gc_hmac_md5 (secret, secretlen ? secretlen : strlen (secret),
	       challenge, challengelen ? challengelen : strlen (challenge),
	       hash);

  for (i = 0; i < GC_MD5_DIGEST_SIZE; i++)
    {
      *response++ = HEXCHAR (hash[i] >> 4);
      *response++ = HEXCHAR (hash[i]);
    }
}
