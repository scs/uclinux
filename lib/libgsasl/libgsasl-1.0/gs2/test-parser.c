/* test-parser.c --- Self tests of GS2 parser & printer.
 * Copyright (C) 2006, 2007, 2008  Simon Josefsson
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

#define ZERO "\x00\x00\x00\x00"
#define ONE "\x00\x00\x00\x01"
#define TWO "\x00\x00\x00\x02"
#define DATA "\x41"
#define DATA2 "\x42"

struct
{
  char *name;
  char *token;
  size_t length;
  int expected_rc;
  char *expected_context;
  size_t expected_context_length;
  char *expected_wrap;
  size_t expected_wrap_length;
} tv[] =
{
  /* *INDENT-OFF* */
  { "string0", "foobarbaz", 0, -1 },
  { "string1", "foobarbaz", 1, -1 },
  { "string2", "foobarbaz", 2, -1 },
  { "string3", "foobarbaz", 3, -1 },
  { "string4", "foobarbaz", 4, -1 },
  { "string5", "foobarbaz", 5, -1 },
  { "string6", "foobarbaz", 6, -1 },
  { "string7", "foobarbaz", 7, -1 },
  { "string8", "foobarbaz", 8, -1 },
  { "string9", "foobarbaz", 9, -1 },
  { "allzero", ZERO ZERO, 8, -1 },
  { "allzero-overlong", ZERO ZERO DATA, 9, -1 },
  { "one-empty", ONE ZERO, 8, -1 },
  { "one-empty2", ZERO ONE, 8, -1 },
  { "size-one", ONE ZERO DATA, 9, 0, DATA, 1, NULL, 0 },
  { "size-one2", ZERO ONE DATA, 9, 0, NULL, 0, DATA, 1 },
  { "size-one3", ONE ONE DATA DATA, 10, 0, DATA, 1, DATA, 1 },
  { "size-one-overlong", ZERO ONE DATA DATA, 10, -1 },
  { "size-one-overlong2", ONE ZERO DATA DATA, 10, -1 },
  { "size-one-overlong3", ONE ONE DATA DATA DATA, 11, -1 },
  { "size-two", TWO TWO DATA DATA2 DATA DATA2, 12, 0,
    DATA DATA2, 2, DATA2 DATA, 2 },
  /* *INDENT-ON* */
};

int
main (int argc, char *argv[])
{
  struct gs2_token tok;
  int rc;
  size_t i;

  for (i = 0; i < sizeof (tv) / sizeof (tv[0]); i++)
    {
      rc = gs2_parser (tv[i].token, tv[i].length, &tok);
      if (rc != tv[i].expected_rc)
	{
	  printf ("gs2 tv[%d] '%s': %.*s expected %d got %d\n",
		  i, tv[i].name, tv[i].length,
		  tv[i].token, tv[i].expected_rc, rc);
	}
      if (rc >= 0 &&
	  (tv[i].expected_context_length != tok.context_length ||
	   memcmp (tv[i].expected_context, tok.context_token,
		   tok.context_length) != 0))
	{
	  printf ("gs2 tv[%d] '%s': "
		  "expected context %.*s (size %d) got %.*s (size %d)\n",
		  i, tv[i].name,
		  tv[i].expected_context_length,
		  tv[i].expected_context,
		  tv[i].expected_context_length,
		  tok.context_length, tok.context_token, tok.context_length);
	  abort ();
	}
    }

  return 0;
}
