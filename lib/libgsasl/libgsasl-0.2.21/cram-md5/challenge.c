/* challenge.c --- Generate a CRAM-MD5 challenge string.
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

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Get prototype. */
#include "challenge.h"

/* Get gc_nonce. */
#include <gc.h>

/*
 * From draft-ietf-sasl-crammd5-02.txt:
 *
 *   The data encoded in the challenge contains a presumptively
 *   arbitrary string of random digits, a time-stamp, and the
 *   fully-qualified primary host name of the server.
 * ...
 *   challenge  = "<" 1*DIGIT "." 1*DIGIT "@" hostname ">"
 *   hostname   = 1*(ALPHA / DIGIT) *("." / "-" / ALPHA / DIGIT)
 *
 * This implementation avoid the information leakage by always using 0
 * as the time stamp and a fixed host name.  This should be
 * unproblematic, as any client that try to validate the challenge
 * string somehow, would violate the same specification:
 *
 *   The client MUST NOT interpret or attempt to validate the
 *   contents of the challenge in any way.
 *
 */

/* The sequence of X in TEMPLATE must be twice as long as NONCELEN. */
#define NONCELEN 10
#define TEMPLATE "<XXXXXXXXXXXXXXXXXXXX.0@localhost>"

/* The probabilities for each digit are skewed (0-5 is more likely to
   occur than 6-9), but it is just used as a nonce anyway. */
#define DIGIT(c) (((c) & 0x0F) > 9 ?		\
		    '0' + ((c) & 0x0F) - 10 :	\
		    '0' + ((c) & 0x0F))

void
cram_md5_challenge (char challenge[CRAM_MD5_CHALLENGE_LEN])
{
  char nonce[NONCELEN];
  size_t i;

  assert (strlen (TEMPLATE) == CRAM_MD5_CHALLENGE_LEN - 1);

  memcpy (challenge, TEMPLATE, CRAM_MD5_CHALLENGE_LEN);

  gc_nonce (nonce, sizeof (nonce));

  for (i = 0; i < sizeof (nonce); i++)
    {
      challenge[1 + i] = DIGIT (nonce[i]);
      challenge[11 + i] = DIGIT (nonce[i] >> 4);
    }
}
