/* digesthmac.c --- Compute DIGEST-MD5 response value.
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "digesthmac.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

/* Get sprintf. */
#include <stdio.h>

/* Get gc_md5. */
#include <gc.h>

#define HEXCHAR(c) ((c & 0x0F) > 9 ? 'a' + (c & 0x0F) - 10 : '0' + (c & 0x0F))

#define QOP_AUTH "auth"
#define QOP_AUTH_INT "auth-int"
#define QOP_AUTH_CONF "auth-conf"

#define A2_PRE "AUTHENTICATE:"
#define A2_POST ":00000000000000000000000000000000"
#define COLON ":"
#define MD5LEN 16
#define RESPONSE_LENGTH 32
#define RSPAUTH_LENGTH RESPONSE_LENGTH
#define DERIVE_CLIENT_INTEGRITY_KEY_STRING \
  "Digest session key to client-to-server signing key magic constant"
#define DERIVE_CLIENT_INTEGRITY_KEY_STRING_LEN 65
#define DERIVE_SERVER_INTEGRITY_KEY_STRING \
  "Digest session key to server-to-client signing key magic constant"
#define DERIVE_SERVER_INTEGRITY_KEY_STRING_LEN 65
#define DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING \
  "Digest H(A1) to client-to-server sealing key magic constant"
#define DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN 59
#define DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING \
  "Digest H(A1) to server-to-client sealing key magic constant"
#define DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING_LEN 59

/* Compute in 33 bytes large array OUTPUT the DIGEST-MD5 response
   value.  SECRET holds the 16 bytes MD5 hash SS, i.e.,
   H(username:realm:passwd).  NONCE is a zero terminated string with
   the server nonce.  NC is the nonce-count, typically 1 for initial
   authentication.  CNONCE is a zero terminated string with the client
   nonce.  QOP is the quality of protection to use.  AUTHZID is a zero
   terminated string with the authorization identity.  DIGESTURI is a
   zero terminated string with the server principal (e.g.,
   imap/mail.example.org).  RSPAUTH is a boolean which indicate
   whether to compute a value for the RSPAUTH response or the "real"
   authentication.  CIPHER is the cipher to use.  KIC, KIS, KCC, KCS
   are either NULL, or points to 16 byte arrays that will hold the
   computed keys on output.  Returns 0 on success. */
int
digest_md5_hmac (char *output, char secret[MD5LEN], char *nonce,
		 unsigned long nc, char *cnonce, digest_md5_qop qop,
		 char *authzid, char *digesturi, int rspauth,
		 digest_md5_cipher cipher,
		 char *kic, char *kis, char *kcc, char *kcs)
{
  const char *a2string = rspauth ? COLON : A2_PRE;
  char nchex[9];
  char a1hexhash[2 * MD5LEN];
  char a2hexhash[2 * MD5LEN];
  char hash[MD5LEN];
  char *tmp, *p;
  size_t tmplen;
  int rc;
  int i;

  /* A1 */

  tmplen = MD5LEN + strlen (COLON) + strlen (nonce) +
    strlen (COLON) + strlen (cnonce);
  if (authzid && strlen (authzid) > 0)
    tmplen += strlen (COLON) + strlen (authzid);

  p = tmp = malloc (tmplen);
  if (tmp == NULL)
    return -1;

  memcpy (p, secret, MD5LEN);
  p += MD5LEN;
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, nonce, strlen (nonce));
  p += strlen (nonce);
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, cnonce, strlen (cnonce));
  p += strlen (cnonce);
  if (authzid && strlen (authzid) > 0)
    {
      memcpy (p, COLON, strlen (COLON));
      p += strlen (COLON);
      memcpy (p, authzid, strlen (authzid));
      p += strlen (authzid);
    }

  rc = gc_md5 (tmp, tmplen, hash);
  free (tmp);
  if (rc)
    return rc;

  if (kic)
    {
      char hash2[MD5LEN];
      char tmp[MD5LEN + DERIVE_CLIENT_INTEGRITY_KEY_STRING_LEN];
      size_t tmplen = MD5LEN + DERIVE_CLIENT_INTEGRITY_KEY_STRING_LEN;

      memcpy (tmp, hash, MD5LEN);
      memcpy (tmp + MD5LEN, DERIVE_CLIENT_INTEGRITY_KEY_STRING,
	      DERIVE_CLIENT_INTEGRITY_KEY_STRING_LEN);

      rc = gc_md5 (tmp, tmplen, hash2);
      if (rc)
	return rc;

      memcpy (kic, hash2, MD5LEN);
    }

  if (kis)
    {
      char hash2[MD5LEN];
      char tmp[MD5LEN + DERIVE_SERVER_INTEGRITY_KEY_STRING_LEN];

      memcpy (tmp, hash, MD5LEN);
      memcpy (tmp + MD5LEN, DERIVE_SERVER_INTEGRITY_KEY_STRING,
	      DERIVE_SERVER_INTEGRITY_KEY_STRING_LEN);

      rc = gc_md5 (tmp,
		   MD5LEN + DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN,
		   hash2);
      if (rc)
	return rc;

      memcpy (kis, hash2, MD5LEN);
    }

  if (kcc)
    {
      char hash2[MD5LEN];
      int n;
      char tmp[MD5LEN + DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN];

      if (cipher == DIGEST_MD5_CIPHER_RC4_40)
	n = 5;
      else if (cipher == DIGEST_MD5_CIPHER_RC4_56)
	n = 7;
      else
	n = MD5LEN;

      memcpy (tmp, hash, n);
      memcpy (tmp + n, DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING,
	      DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN);

      rc = gc_md5 (tmp, n + DERIVE_CLIENT_CONFIDENTIALITY_KEY_STRING_LEN,
		   hash2);
      if (rc)
	return rc;

      memcpy (kcc, hash2, MD5LEN);
    }

  if (kcs)
    {
      char hash2[MD5LEN];
      int n;
      char tmp[MD5LEN + DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING_LEN];

      if (cipher == DIGEST_MD5_CIPHER_RC4_40)
	n = 5;
      else if (cipher == DIGEST_MD5_CIPHER_RC4_56)
	n = 7;
      else
	n = MD5LEN;

      memcpy (tmp, hash, n);
      memcpy (tmp + n, DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING,
	      DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING_LEN);

      rc = gc_md5 (tmp, n + DERIVE_SERVER_CONFIDENTIALITY_KEY_STRING_LEN,
		   hash2);
      if (rc)
	return rc;

      memcpy (kcs, hash2, MD5LEN);
    }

  for (i = 0; i < MD5LEN; i++)
    {
      a1hexhash[2 * i + 1] = HEXCHAR (hash[i]);
      a1hexhash[2 * i + 0] = HEXCHAR (hash[i] >> 4);
    }

  /* A2 */

  tmplen = strlen (a2string) + strlen (digesturi);
  if (qop & DIGEST_MD5_QOP_AUTH_INT || qop & DIGEST_MD5_QOP_AUTH_CONF)
    tmplen += strlen (A2_POST);

  p = tmp = malloc (tmplen);
  if (tmp == NULL)
    return -1;

  memcpy (p, a2string, strlen (a2string));
  p += strlen (a2string);
  memcpy (p, digesturi, strlen (digesturi));
  p += strlen (digesturi);
  if (qop & DIGEST_MD5_QOP_AUTH_INT || qop & DIGEST_MD5_QOP_AUTH_CONF)
    memcpy (p, A2_POST, strlen (A2_POST));

  rc = gc_md5 (tmp, tmplen, hash);
  free (tmp);
  if (rc)
    return rc;

  for (i = 0; i < MD5LEN; i++)
    {
      a2hexhash[2 * i + 1] = HEXCHAR (hash[i]);
      a2hexhash[2 * i + 0] = HEXCHAR (hash[i] >> 4);
    }

  /* response_value */

  sprintf (nchex, "%08lx", nc);

  tmplen = 2 * MD5LEN + strlen (COLON) + strlen (nonce) + strlen (COLON) +
    strlen (nchex) + strlen (COLON) + strlen (cnonce) + strlen (COLON);
  if (qop & DIGEST_MD5_QOP_AUTH_CONF)
    tmplen += strlen (QOP_AUTH_CONF);
  else if (qop & DIGEST_MD5_QOP_AUTH_INT)
    tmplen += strlen (QOP_AUTH_INT);
  else if (qop & DIGEST_MD5_QOP_AUTH)
    tmplen += strlen (QOP_AUTH);
  tmplen += strlen (COLON) + 2 * MD5LEN;

  p = tmp = malloc (tmplen);
  if (tmp == NULL)
    return -1;

  memcpy (p, a1hexhash, 2 * MD5LEN);
  p += 2 * MD5LEN;
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, nonce, strlen (nonce));
  p += strlen (nonce);
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, nchex, strlen (nchex));
  p += strlen (nchex);
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, cnonce, strlen (cnonce));
  p += strlen (cnonce);
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  if (qop & DIGEST_MD5_QOP_AUTH_CONF)
    {
      memcpy (p, QOP_AUTH_CONF, strlen (QOP_AUTH_CONF));
      p += strlen (QOP_AUTH_CONF);
    }
  else if (qop & DIGEST_MD5_QOP_AUTH_INT)
    {
      memcpy (p, QOP_AUTH_INT, strlen (QOP_AUTH_INT));
      p += strlen (QOP_AUTH_INT);
    }
  else if (qop & DIGEST_MD5_QOP_AUTH)
    {
      memcpy (p, QOP_AUTH, strlen (QOP_AUTH));
      p += strlen (QOP_AUTH);
    }
  memcpy (p, COLON, strlen (COLON));
  p += strlen (COLON);
  memcpy (p, a2hexhash, 2 * MD5LEN);

  rc = gc_md5 (tmp, tmplen, hash);
  free (tmp);
  if (rc)
    return rc;

  for (i = 0; i < MD5LEN; i++)
    {
      output[2 * i + 1] = HEXCHAR (hash[i]);
      output[2 * i + 0] = HEXCHAR (hash[i] >> 4);
    }
  output[32] = '\0';

  return 0;
}
