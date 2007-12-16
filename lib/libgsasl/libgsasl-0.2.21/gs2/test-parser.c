/* test-parser.c --- Self tests of GS2 parser & printer.
 * Copyright (C) 2006  Simon Josefsson
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gs2parser.h"

int
main (int argc, char *argv[])
{
  struct gs2_token tok;
  int rc;

  {
    char token[4] = "\x00\x00\x00\x00";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc < 0)
      {
	printf ("gs2_parser zero rc %d\n", rc);
	abort ();
      }
    if (tok.context_token != NULL ||
	tok.context_length != 0 ||
	tok.wrap_token != NULL ||
	tok.wrap_length != 0)
      {
	printf ("gs2_parser zero failure (%d: %x-%d-%x-%d)\n",
		sizeof (token),
		tok.context_token, tok.context_length,
		tok.wrap_token, tok.wrap_length);
	abort ();
      }
  }

  {
    char token[4] = "\x00\x00\x00\x01";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc >= 0)
      {
	printf ("gs2_parser one-empty rc %d\n", rc);
	abort ();
      }
  }

  {
    char token[4] = "\x00\x00\x00\x04";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc >= 0)
      {
	printf ("gs2_parser four-empty rc %d\n", rc);
	abort ();
      }
  }

  {
    char token[5] = "\x00\x00\x00\x00\x65";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc < 0)
      {
	printf ("gs2_parser zero-ok rc %d\n", rc);
	abort ();
      }
    if (tok.context_token != NULL ||
	tok.context_length != 0 ||
	tok.wrap_token != &token[4] ||
	tok.wrap_length != 1)
      {
	printf ("gs2_parser zero-ok failure (%x-%d-%x-%d)\n",
		tok.context_token, tok.context_length,
		tok.wrap_token, tok.wrap_length);
	abort ();
      }
  }

  {
    char token[5] = "\x00\x00\x00\x01\x65";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc < 0)
      {
	printf ("gs2_parser one-ok rc %d\n", rc);
	abort ();
      }
    if (tok.context_token != &token[4] ||
	tok.context_length != 1 ||
	tok.wrap_token != NULL ||
	tok.wrap_length != 0)
      {
	printf ("gs2_parser one-ok failure (%x-%d-%x-%d)\n",
		tok.context_token, tok.context_length,
		tok.wrap_token, tok.wrap_length);
	abort ();
      }
  }

  {
    char token[6] = "\x00\x00\x00\x00\xAA\xBB";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc < 0)
      {
	printf ("gs2_parser zero-two-ok rc %d\n", rc);
	abort ();
      }
    if (tok.context_token != NULL ||
	tok.context_length != 0 ||
	tok.wrap_token != &token[4] ||
	tok.wrap_length != 2)
      {
	printf ("gs2_parser zero-two-ok failure (%x-%d-%x-%d)\n",
		tok.context_token, tok.context_length,
		tok.wrap_token, tok.wrap_length);
	abort ();
      }
  }

  {
    char token[6] = "\x00\x00\x00\x02\xAA\xAB";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc < 0)
      {
	printf ("gs2_parser zero-two-ok rc %d\n", rc);
	abort ();
      }
    if (tok.context_token != &token[4] ||
	tok.context_length != 2 ||
	tok.wrap_token != NULL ||
	tok.wrap_length != 0)
      {
	printf ("gs2_parser zero-two-ok failure (%x-%d-%x-%d)\n",
		tok.context_token, tok.context_length,
		tok.wrap_token, tok.wrap_length);
	abort ();
      }
  }

  {
    char token[6] = "\x00\x00\x00\x01\xAA\xAB";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc < 0)
      {
	printf ("gs2_parser both rc %d\n", rc);
	abort ();
      }
    if (tok.context_token != &token[4] ||
	tok.context_length != 1 ||
	tok.wrap_token != &token[5] ||
	tok.wrap_length != 1)
      {
	printf ("gs2_parser both failure (%x-%d-%x-%d)\n",
		tok.context_token, tok.context_length,
		tok.wrap_token, tok.wrap_length);
	abort ();
      }
  }

  {
    char token[8] = "\x00\x00\x00\x02\xAA\xBA\xAB\xBB";
    rc = gs2_parser (token, sizeof (token), &tok);
    if (rc < 0)
      {
	printf ("gs2_parser both2 rc %d\n", rc);
	abort ();
      }
    if (tok.context_token != &token[4] ||
	tok.context_length != 2 ||
	tok.wrap_token != &token[6] ||
	tok.wrap_length != 2)
      {
	printf ("gs2_parser both2 failure (%x-%d-%x-%d)\n",
		tok.context_token, tok.context_length,
		tok.wrap_token, tok.wrap_length);
	abort ();
      }
  }

  return 0;
}
