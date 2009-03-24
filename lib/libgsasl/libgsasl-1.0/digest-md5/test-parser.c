/* test-parser.c --- Self tests of DIGEST-MD5 parser & printer.
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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

#include "parser.h"
#include "printer.h"
#include "digesthmac.h"

#include "gc.h"

int
main (int argc, char *argv[])
{
  digest_md5_challenge c;
  digest_md5_response r;
  digest_md5_finish f;
  char buf32[33];
  char buf16[16];
  int rc;
  char *tmp;

  {
    const char *token = "nonce=4711, foo=bar, algorithm=md5-sess";

    printf ("challenge `%s': ", token);
    rc = digest_md5_parse_challenge (token, 0, &c);
    if (rc != 0)
      abort ();
    printf ("nonce `%s': %s", c.nonce,
	    strcmp ("4711", c.nonce) == 0 ? "PASS" : "FAILURE");
    printf ("\n");
    tmp = digest_md5_print_challenge (&c);
    if (!tmp)
      abort ();
    printf ("printed `%s' PASS\n", tmp);
    free (tmp);
  }

  {
    const char *token = "qop=\"auth, auth-conf\", nonce=42, algorithm=md5-sess";

    printf ("challenge `%s': ", token);
    rc = digest_md5_parse_challenge (token, 0, &c);
    if (rc == 0)
      abort ();
    printf ("PASS\n");
  }

  {
    const char *token = "cipher=\"des\", nonce=42, algorithm=md5-sess";

    printf ("challenge `%s': ", token);
    rc = digest_md5_parse_challenge (token, 0, &c);
    if (rc == 0)
      abort ();
    printf ("PASS\n");
  }

  {
    const char *token = "qop=\"auth, auth-conf\", nonce=42, "
      "algorithm=md5-sess, cipher=\"des\"";

    printf ("challenge `%s': ", token);
    rc = digest_md5_parse_challenge (token, 0, &c);
    if (rc != 0)
      abort ();
    printf ("qop %02x ciphers %02x: %s\n", c.qops, c.ciphers,
	    (c.qops == 5 && c.ciphers == 1) ? "PASS" : "FAILURE");
    tmp = digest_md5_print_challenge (&c);
    if (!tmp)
      abort ();
    printf ("printed `%s' PASS\n", tmp);
    free (tmp);
  }

  {
    const char *token = "bar=foo, foo=bar";

    printf ("challenge `%s': ", token);
    rc = digest_md5_parse_challenge (token, 0, &c);
    if (rc == 0)
      abort ();
    printf ("PASS\n");
  }

  {
    const char *token = "realm=foo, realm=bar, nonce=42, algorithm=md5-sess";

    printf ("challenge `%s': ", token);
    rc = digest_md5_parse_challenge (token, 0, &c);
    if (rc != 0)
      abort ();
    if (c.nrealms != 2)
      abort ();
    printf ("realms `%s', `%s': PASS\n", c.realms[0], c.realms[1]);
    tmp = digest_md5_print_challenge (&c);
    if (!tmp)
      abort ();
    printf ("printed `%s' PASS\n", tmp);
    free (tmp);
  }

  /* Response */

  {
    const char *token = "bar=foo, foo=bar";

    printf ("response `%s': ", token);
    rc = digest_md5_parse_response (token, 0, &r);
    if (rc == 0)
      abort ();
    printf ("PASS\n");
  }

  {
    const char *token = "username=jas, nonce=42, cnonce=4711, nc=00000001, "
      "digest-uri=foo, response=01234567890123456789012345678901";

    printf ("response `%s': ", token);
    rc = digest_md5_parse_response (token, 0, &r);
    if (rc != 0)
      abort ();
    printf ("username `%s', nonce `%s', cnonce `%s',"
	    " nc %08lx, digest-uri `%s', response `%s': PASS\n",
	    r.username, r.nonce, r.cnonce, r.nc, r.digesturi, r.response);
    tmp = digest_md5_print_response (&r);
    if (!tmp)
      abort ();
    printf ("printed `%s' PASS\n", tmp);
    free (tmp);
  }

  /* Auth-response, finish. */

  {
    const char *token = "rspauth=\"6a204da26b9888ee40bb3052ff056a67\"";

    printf ("finish `%s': ", token);
    rc = digest_md5_parse_finish (token, 0, &f);
    if (rc != 0)
      abort ();
    printf ("`%s'? %s\n", f.rspauth,
	    strcmp ("6a204da26b9888ee40bb3052ff056a67", f.rspauth) == 0
	    ? "ok" : "FAILURE");
  }

  {
    const char *token = "bar=foo, foo=bar";

    printf ("finish `%s': ", token);
    rc = digest_md5_parse_finish (token, 0, &f);
    if (rc == 0)
      abort ();
    printf ("invalid? PASS\n");
  }

  rc = gc_init ();
  if (rc != 0)
    abort ();

  memset (buf16, 'Q', 16);

  rc = digest_md5_hmac (buf32, buf16, "nonce", 1, "cnonce",
			DIGEST_MD5_QOP_AUTH, "authzid", "digesturi",
			1, 0, NULL, NULL, NULL, NULL);
  if (rc != 0)
    abort ();
  buf32[32] = '\0';
  if (strcmp (buf32, "6a204da26b9888ee40bb3052ff056a67") != 0)
    abort ();
  printf ("digest: `%s': PASS\n", buf32);

  rc = digest_md5_hmac (buf32, buf16, "nonce", 1, "cnonce",
			DIGEST_MD5_QOP_AUTH, "authzid", "digesturi", 0, 0,
			NULL, NULL, NULL, NULL);
  if (rc != 0)
    abort ();
  buf32[32] = '\0';
  if (strcmp (buf32, "6c1f58bfa46e9c225b93745c84204efd") != 0)
    abort ();
  printf ("digest: `%s': PASS\n", buf32);

  return 0;
}
