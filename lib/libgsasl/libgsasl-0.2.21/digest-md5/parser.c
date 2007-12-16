/* parser.c --- DIGEST-MD5 parser.
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

/* Get prototypes. */
#include "parser.h"

/* Get malloc, free. */
#include <stdlib.h>

/* Get memcpy, strlen. */
#include <string.h>

/* Get validator. */
#include "validate.h"

#define DEFAULT_CHARSET "utf-8"
#define DEFAULT_ALGORITHM "md5-sess"

enum
{
  /* the order must match the following struct */
  CHALLENGE_REALM = 0,
  CHALLENGE_NONCE,
  CHALLENGE_QOP,
  CHALLENGE_STALE,
  CHALLENGE_MAXBUF,
  CHALLENGE_CHARSET,
  CHALLENGE_ALGORITHM,
  CHALLENGE_CIPHER
};

static const char *const digest_challenge_opts[] = {
  /* the order must match the previous enum */
  "realm",
  "nonce",
  "qop",
  "stale",
  "maxbuf",
  "charset",
  "algorithm",
  "cipher",
  NULL
};

/* qop-value         = "auth" | "auth-int" | "auth-conf" | qop-token */
enum
{
  /* the order must match the following struct */
  QOP_AUTH = 0,
  QOP_AUTH_INT,
  QOP_AUTH_CONF
};

static const char *const qop_opts[] = {
  /* the order must match the previous enum */
  "auth",
  "auth-int",
  "auth-conf",
  NULL
};

/* cipher-value      = "3des" | "des" | "rc4-40" | "rc4" |
 *                     "rc4-56" | "aes-cbc" | cipher-token
 *                     ;; "des" and "3des" ciphers are obsolete.
 */
enum
{
  /* the order must match the following struct */
  CIPHER_DES = 0,
  CIPHER_3DES,
  CIPHER_RC4,
  CIPHER_RC4_40,
  CIPHER_RC4_56,
  CIPHER_AES_CBC
};

static const char *const cipher_opts[] = {
  /* the order must match the previous enum */
  "des",
  "3des",
  "rc4",
  "rc4-40",
  "rc4-56",
  "aes-cbc",
  NULL
};

static int
parse_challenge (char *challenge, digest_md5_challenge * out)
{
  int done_algorithm = 0;
  int disable_qop_auth_conf = 0;
  char *value;

  memset (out, 0, sizeof (*out));

  /* The size of a digest-challenge MUST be less than 2048 bytes. */
  if (strlen (challenge) >= 2048)
    return -1;

  while (*challenge != '\0')
    switch (digest_md5_getsubopt (&challenge, digest_challenge_opts, &value))
      {
      case CHALLENGE_REALM:
	{
	  char **tmp;
	  out->nrealms++;
	  tmp = realloc (out->realms, out->nrealms * sizeof (*out->realms));
	  if (!tmp)
	    return -1;
	  out->realms = tmp;
	  out->realms[out->nrealms - 1] = strdup (value);
	  if (!out->realms[out->nrealms - 1])
	    return -1;
	}
	break;

      case CHALLENGE_NONCE:
	/* This directive is required and MUST appear exactly once; if
	   not present, or if multiple instances are present, the
	   client should abort the authentication exchange. */
	if (out->nonce)
	  return -1;
	out->nonce = strdup (value);
	if (!out->nonce)
	  return -1;
	break;

      case CHALLENGE_QOP:
	/* <<What if this directive is present multiple times? Error,
	   or take the union of all values?>> */
	if (out->qops)
	  return -1;
	{
	  char *subsubopts;
	  char *val;

	  subsubopts = value;
	  while (*subsubopts != '\0')
	    switch (digest_md5_getsubopt (&subsubopts, qop_opts, &val))
	      {
	      case QOP_AUTH:
		out->qops |= DIGEST_MD5_QOP_AUTH;
		break;

	      case QOP_AUTH_INT:
		out->qops |= DIGEST_MD5_QOP_AUTH_INT;
		break;

	      case QOP_AUTH_CONF:
		out->qops |= DIGEST_MD5_QOP_AUTH_CONF;
		break;

	      default:
		/* The client MUST ignore unrecognized options */
		break;
	      }
	}
	/* if the client recognizes no cipher, it MUST behave as if
	   "auth-conf" qop option wasn't provided by the server. */
	if (disable_qop_auth_conf)
	  out->qops &= ~DIGEST_MD5_QOP_AUTH_CONF;
	/* if the client recognizes no option, it MUST abort the
	   authentication exchange. */
	if (!out->qops)
	  return -1;
	break;

      case CHALLENGE_STALE:
	/* This directive may appear at most once; if multiple
	   instances are present, the client MUST abort the
	   authentication exchange. */
	if (out->stale)
	  return -1;
	out->stale = 1;
	break;

      case CHALLENGE_MAXBUF:
	/* This directive may appear at most once; if multiple
	   instances are present, or the value is out of range the
	   client MUST abort the authentication exchange. */
	if (out->servermaxbuf)
	  return -1;
	out->servermaxbuf = strtoul (value, NULL, 10);
	/* FIXME: error handling. */
	/* The value MUST be bigger than 16 (32 for Confidentiality
	   protection with the "aes-cbc" cipher) and smaller or equal
	   to 16777215 (i.e. 2**24-1). */
	if (out->servermaxbuf <= 16 || out->servermaxbuf > 16777215)
	  return -1;
	break;

      case CHALLENGE_CHARSET:
	/* This directive may appear at most once; if multiple
	   instances are present, the client MUST abort the
	   authentication exchange. */
	if (out->utf8)
	  return -1;
	if (strcmp (DEFAULT_CHARSET, value) != 0)
	  return -1;
	out->utf8 = 1;
	break;

      case CHALLENGE_ALGORITHM:
	/* This directive is required and MUST appear exactly once; if
	   not present, or if multiple instances are present, the
	   client SHOULD abort the authentication exchange. */
	if (done_algorithm)
	  return -1;
	if (strcmp (DEFAULT_ALGORITHM, value) != 0)
	  return -1;
	done_algorithm = 1;
	break;


      case CHALLENGE_CIPHER:
	/* This directive must be present exactly once if "auth-conf"
	   is offered in the "qop-options" directive */
	if (out->ciphers)
	  return -1;
	{
	  char *subsubopts;
	  char *val;

	  subsubopts = value;
	  while (*subsubopts != '\0')
	    switch (digest_md5_getsubopt (&subsubopts, cipher_opts, &val))
	      {
	      case CIPHER_DES:
		out->ciphers |= DIGEST_MD5_CIPHER_DES;
		break;

	      case CIPHER_3DES:
		out->ciphers |= DIGEST_MD5_CIPHER_3DES;
		break;

	      case CIPHER_RC4:
		out->ciphers |= DIGEST_MD5_CIPHER_RC4;
		break;

	      case CIPHER_RC4_40:
		out->ciphers |= DIGEST_MD5_CIPHER_RC4_40;
		break;

	      case CIPHER_RC4_56:
		out->ciphers |= DIGEST_MD5_CIPHER_RC4_56;
		break;

	      case CIPHER_AES_CBC:
		out->ciphers |= DIGEST_MD5_CIPHER_AES_CBC;
		break;

	      default:
		/* The client MUST ignore unrecognized ciphers */
		break;
	      }
	}
	/* if the client recognizes no cipher, it MUST behave as if
	   "auth-conf" qop option wasn't provided by the server. */
	if (!out->ciphers)
	  {
	    disable_qop_auth_conf = 1;
	    if (out->qops)
	      {
		/* if the client recognizes no option, it MUST abort the
		   authentication exchange. */
		out->qops &= ~DIGEST_MD5_QOP_AUTH_CONF;
		if (!out->qops)
		  return -1;
	      }
	  }
	break;

      default:
	/* The client MUST ignore any unrecognized directives. */
	break;
      }

  /* This directive is required and MUST appear exactly once; if
     not present, or if multiple instances are present, the
     client SHOULD abort the authentication exchange. */
  if (!done_algorithm)
    return -1;

  /* Validate that we have the mandatory fields. */
  if (digest_md5_validate_challenge (out) != 0)
    return -1;

  return 0;
}

enum
{
  /* the order must match the following struct */
  RESPONSE_USERNAME = 0,
  RESPONSE_REALM,
  RESPONSE_NONCE,
  RESPONSE_CNONCE,
  RESPONSE_NC,
  RESPONSE_QOP,
  RESPONSE_DIGEST_URI,
  RESPONSE_RESPONSE,
  RESPONSE_MAXBUF,
  RESPONSE_CHARSET,
  RESPONSE_CIPHER,
  RESPONSE_AUTHZID
};

static const char *const digest_response_opts[] = {
  /* the order must match the previous enum */
  "username",
  "realm",
  "nonce",
  "cnonce",
  "nc",
  "qop",
  "digest-uri",
  "response",
  "maxbuf",
  "charset",
  "cipher",
  "authzid",
  NULL
};

static int
parse_response (char *response, digest_md5_response * out)
{
  char *value;

  memset (out, 0, sizeof (*out));

  /* The size of a digest-response MUST be less than 4096 bytes. */
  if (strlen (response) >= 4096)
    return -1;

  while (*response != '\0')
    switch (digest_md5_getsubopt (&response, digest_response_opts, &value))
      {
      case RESPONSE_USERNAME:
	/* This directive is required and MUST be present exactly
	   once; otherwise, authentication fails. */
	if (out->username)
	  return -1;
	out->username = strdup (value);
	if (!out->username)
	  return -1;
	break;

      case RESPONSE_REALM:
	/* This directive is required if the server provided any
	   realms in the "digest-challenge", in which case it may
	   appear exactly once and its value SHOULD be one of those
	   realms. */
	if (out->realm)
	  return -1;
	out->realm = strdup (value);
	if (!out->realm)
	  return -1;
	break;

      case RESPONSE_NONCE:
	/* This directive is required and MUST be present exactly
	   once; otherwise, authentication fails. */
	if (out->nonce)
	  return -1;
	out->nonce = strdup (value);
	if (!out->nonce)
	  return -1;
	break;

      case RESPONSE_CNONCE:
	/* This directive is required and MUST be present exactly once;
	   otherwise, authentication fails. */
	if (out->cnonce)
	  return -1;
	out->cnonce = strdup (value);
	if (!out->cnonce)
	  return -1;
	break;

      case RESPONSE_NC:
	/* This directive is required and MUST be present exactly
	   once; otherwise, authentication fails. */
	if (out->nc)
	  return -1;
	/* nc-value = 8LHEX */
	if (strlen (value) != 8)
	  return -1;
	out->nc = strtoul (value, NULL, 16);
	/* FIXME: error handling. */
	break;

      case RESPONSE_QOP:
	/* If present, it may appear exactly once and its value MUST
	   be one of the alternatives in qop-options.  */
	if (out->qop)
	  return -1;
	if (strcmp (value, "auth") == 0)
	  out->qop = DIGEST_MD5_QOP_AUTH;
	else if (strcmp (value, "auth-int") == 0)
	  out->qop = DIGEST_MD5_QOP_AUTH_INT;
	else if (strcmp (value, "auth-conf") == 0)
	  out->qop = DIGEST_MD5_QOP_AUTH_CONF;
	else
	  return -1;
	break;

      case RESPONSE_DIGEST_URI:
	/* This directive is required and MUST be present exactly
	   once; if multiple instances are present, the client MUST
	   abort the authentication exchange. */
	if (out->digesturi)
	  return -1;
	/* FIXME: sub-parse. */
	out->digesturi = strdup (value);
	if (!out->digesturi)
	  return -1;
	break;

      case RESPONSE_RESPONSE:
	/* This directive is required and MUST be present exactly
	   once; otherwise, authentication fails. */
	if (*out->response)
	  return -1;
	/* A string of 32 hex digits */
	if (strlen (value) != DIGEST_MD5_RESPONSE_LENGTH)
	  return -1;
	strcpy (out->response, value);
	break;

      case RESPONSE_MAXBUF:
	/* This directive may appear at most once; if multiple
	   instances are present, the server MUST abort the
	   authentication exchange. */
	if (out->clientmaxbuf)
	  return -1;
	out->clientmaxbuf = strtoul (value, NULL, 10);
	/* FIXME: error handling. */
	/* If the value is less or equal to 16 (<<32 for aes-cbc>>) or
	   bigger than 16777215 (i.e. 2**24-1), the server MUST abort
	   the authentication exchange. */
	if (out->clientmaxbuf <= 16 || out->clientmaxbuf > 16777215)
	  return -1;
	break;

      case RESPONSE_CHARSET:
	if (strcmp (DEFAULT_CHARSET, value) != 0)
	  return -1;
	out->utf8 = 1;
	break;

      case RESPONSE_CIPHER:
	if (out->cipher)
	  return -1;
	if (strcmp (value, "3des") == 0)
	  out->cipher = DIGEST_MD5_CIPHER_3DES;
	else if (strcmp (value, "des") == 0)
	  out->cipher = DIGEST_MD5_CIPHER_DES;
	else if (strcmp (value, "rc4-40") == 0)
	  out->cipher = DIGEST_MD5_CIPHER_RC4_40;
	else if (strcmp (value, "rc4") == 0)
	  out->cipher = DIGEST_MD5_CIPHER_RC4;
	else if (strcmp (value, "rc4-56") == 0)
	  out->cipher = DIGEST_MD5_CIPHER_RC4_56;
	else if (strcmp (value, "aes-cbc") == 0)
	  out->cipher = DIGEST_MD5_CIPHER_AES_CBC;
	else
	  return -1;
	break;

      case RESPONSE_AUTHZID:
	/* This directive may appear at most once; if multiple
	   instances are present, the server MUST abort the
	   authentication exchange.  <<FIXME NOT IN DRAFT>> */
	if (out->authzid)
	  return -1;
	/*  The authzid MUST NOT be an empty string. */
	if (*value == '\0')
	  return -1;
	out->authzid = strdup (value);
	if (!out->authzid)
	  return -1;
	break;

      default:
	/* The client MUST ignore any unrecognized directives. */
	break;
      }

  /* Validate that we have the mandatory fields. */
  if (digest_md5_validate_response (out) != 0)
    return -1;

  return 0;
}

enum
{
  /* the order must match the following struct */
  RESPONSEAUTH_RSPAUTH = 0
};

static const char *const digest_responseauth_opts[] = {
  /* the order must match the previous enum */
  "rspauth",
  NULL
};

static int
parse_finish (char *finish, digest_md5_finish * out)
{
  char *value;

  memset (out, 0, sizeof (*out));

  /* The size of a response-auth MUST be less than 2048 bytes. */
  if (strlen (finish) >= 2048)
    return -1;

  while (*finish != '\0')
    switch (digest_md5_getsubopt (&finish, digest_responseauth_opts, &value))
      {
      case RESPONSEAUTH_RSPAUTH:
	if (*out->rspauth)
	  return -1;
	/* A string of 32 hex digits */
	if (strlen (value) != DIGEST_MD5_RESPONSE_LENGTH)
	  return -1;
	strcpy (out->rspauth, value);
	break;

      default:
	/* The client MUST ignore any unrecognized directives. */
	break;
      }

  /* Validate that we have the mandatory fields. */
  if (digest_md5_validate_finish (out) != 0)
    return -1;

  return 0;
}

int
digest_md5_parse_challenge (const char *challenge, size_t len,
			    digest_md5_challenge * out)
{
  size_t inlen = len ? len : strlen (challenge);
  char *subopts = malloc (inlen + 1);
  int rc;

  if (!subopts)
    return -1;

  memcpy (subopts, challenge, inlen);
  subopts[inlen] = '\0';

  rc = parse_challenge (subopts, out);

  free (subopts);

  return rc;
}

int
digest_md5_parse_response (const char *response, size_t len,
			   digest_md5_response * out)
{
  size_t inlen = len ? len : strlen (response);
  char *subopts = malloc (inlen + 1);
  int rc;

  if (!subopts)
    return -1;

  memcpy (subopts, response, inlen);
  subopts[inlen] = '\0';

  rc = parse_response (subopts, out);

  free (subopts);

  return rc;
}

int
digest_md5_parse_finish (const char *finish, size_t len,
			 digest_md5_finish * out)
{
  size_t inlen = len ? len : strlen (finish);
  char *subopts = malloc (inlen + 1);
  int rc;

  if (!subopts)
    return -1;

  memcpy (subopts, finish, inlen);
  subopts[inlen] = '\0';

  rc = parse_finish (subopts, out);

  free (subopts);

  return rc;
}
