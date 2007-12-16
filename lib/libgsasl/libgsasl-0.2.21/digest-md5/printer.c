/* printer.h --- Convert DIGEST-MD5 token structures into strings.
 * Copyright (C) 2004, 2007  Simon Josefsson
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
#include "printer.h"

/* Get free. */
#include <stdlib.h>

/* Get asprintf. */
#include <stdio.h>

/* Get token validator. */
#include "validate.h"

/* Append a key/value pair to a comma'd string list.  Additionally enclose
   the value in quotes if requested. */
static int
comma_append (char **dst, const char *key, const char *value, int quotes)
{
  char *tmp;
  int result;

  if (*dst)
    if (value)
      if (quotes)
	result = asprintf (&tmp, "%s, %s=\"%s\"", *dst, key, value);
      else
	result = asprintf (&tmp, "%s, %s=%s", *dst, key, value);
    else
      result = asprintf (&tmp, "%s, %s", *dst, key);
  else if (value)
    if (quotes)
      result = asprintf (&tmp, "%s=\"%s\"", key, value);
    else
      result = asprintf (&tmp, "%s=%s", key, value);
  else
    result = asprintf (&tmp, "%s", key);

  if (result < 0)
    return result;

  if (*dst)
    free (*dst);

  *dst = tmp;

  return result;
}

char *
digest_md5_print_challenge (digest_md5_challenge * c)
{
  char *out = NULL;
  size_t i;

  /* Below we assume the mandatory fields are present, verify that
     first to avoid crashes. */
  if (digest_md5_validate_challenge (c) != 0)
    return NULL;

  for (i = 0; i < c->nrealms; i++)
    {
      if (comma_append (&out, "realm", c->realms[i], 1) < 0)
	{
	  free (out);
	  return NULL;
	}
    }

  if (c->nonce)
    if (comma_append (&out, "nonce", c->nonce, 1) < 0)
      {
	free (out);
	return NULL;
      }

  if (c->qops)
    {
      char *tmp = NULL;

      if (c->qops & DIGEST_MD5_QOP_AUTH)
	if (comma_append (&tmp, "auth", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (c->qops & DIGEST_MD5_QOP_AUTH_INT)
	if (comma_append (&tmp, "auth-int", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (c->qops & DIGEST_MD5_QOP_AUTH_CONF)
	if (comma_append (&tmp, "auth-conf", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (comma_append (&out, "qop", tmp, 1) < 0)
	{
	  free (tmp);
	  free (out);
	  return NULL;
	}

      free (tmp);
    }

  if (c->stale)
    if (comma_append (&out, "stale", "true", 0) < 0)
      {
	free (out);
	return NULL;
      }

  if (c->servermaxbuf)
    {
      char *tmp;

      if (asprintf (&tmp, "%lu", c->servermaxbuf) < 0)
	{
	  free (out);
	  return NULL;
	}

      if (comma_append (&out, "maxbuf", tmp, 0) < 0)
	{
	  free (out);
	  return NULL;
	}

      free (tmp);
    }

  if (c->utf8)
    if (comma_append (&out, "charset", "utf-8", 0) < 0)
      {
	free (out);
	return NULL;
      }

  if (comma_append (&out, "algorithm", "md5-sess", 0) < 0)
    {
      free (out);
      return NULL;
    }

  if (c->ciphers)
    {
      char *tmp = NULL;

      if (c->ciphers & DIGEST_MD5_CIPHER_3DES)
	if (comma_append (&tmp, "3des", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (c->ciphers & DIGEST_MD5_CIPHER_DES)
	if (comma_append (&tmp, "des", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (c->ciphers & DIGEST_MD5_CIPHER_RC4_40)
	if (comma_append (&tmp, "rc4-40", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (c->ciphers & DIGEST_MD5_CIPHER_RC4)
	if (comma_append (&tmp, "rc4", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (c->ciphers & DIGEST_MD5_CIPHER_RC4_56)
	if (comma_append (&tmp, "rc4-56", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (c->ciphers & DIGEST_MD5_CIPHER_AES_CBC)
	if (comma_append (&tmp, "aes-cbc", NULL, 0) < 0)
	  {
	    free (tmp);
	    free (out);
	    return NULL;
	  }

      if (comma_append (&out, "cipher", tmp, 1) < 0)
	{
	  free (tmp);
	  free (out);
	  return NULL;
	}

      free (tmp);
    }

  return out;
}

char *
digest_md5_print_response (digest_md5_response * r)
{
  char *out = NULL;
  const char *qop = NULL;
  const char *cipher = NULL;

  /* Below we assume the mandatory fields are present, verify that
     first to avoid crashes. */
  if (digest_md5_validate_response (r) != 0)
    return NULL;

  if (r->qop & DIGEST_MD5_QOP_AUTH_CONF)
    qop = "qop=auth-conf";
  else if (r->qop & DIGEST_MD5_QOP_AUTH_INT)
    qop = "qop=auth-int";
  else if (r->qop & DIGEST_MD5_QOP_AUTH)
    qop = "qop=auth";

  if (r->cipher & DIGEST_MD5_CIPHER_3DES)
    cipher = "cipher=3des";
  else if (r->cipher & DIGEST_MD5_CIPHER_DES)
    cipher = "cipher=des";
  else if (r->cipher & DIGEST_MD5_CIPHER_RC4_40)
    cipher = "cipher=rc4-40";
  else if (r->cipher & DIGEST_MD5_CIPHER_RC4)
    cipher = "cipher=rc4";
  else if (r->cipher & DIGEST_MD5_CIPHER_RC4_56)
    cipher = "cipher=rc4-56";
  else if (r->cipher & DIGEST_MD5_CIPHER_AES_CBC)
    cipher = "cipher=aes-cbc";
  else if (r->cipher & DIGEST_MD5_CIPHER_3DES)
    cipher = "cipher=3des";

  if (r->username)
    if (comma_append (&out, "username", r->username, 1) < 0)
      {
	free (out);
	return NULL;
      }

  if (r->realm)
    if (comma_append (&out, "realm", r->realm, 1) < 0)
      {
	free (out);
	return NULL;
      }

  if (r->nonce)
    if (comma_append (&out, "nonce", r->nonce, 1) < 0)
      {
	free (out);
	return NULL;
      }

  if (r->cnonce)
    if (comma_append (&out, "cnonce", r->cnonce, 1) < 0)
      {
	free (out);
	return NULL;
      }

  if (r->nc)
    {
      char *tmp;

      if (asprintf (&tmp, "%08lx", r->nc) < 0)
	{
	  free (out);
	  return NULL;
	}

      if (comma_append (&out, "nc", tmp, 0) < 0)
	{
	  free (tmp);
	  free (out);
	  return NULL;
	}

      free (tmp);
    }

  if (qop)
    if (comma_append (&out, qop, NULL, 0) < 0)
      {
	free (out);
	return NULL;
      }

  if (r->digesturi)
    if (comma_append (&out, "digest-uri", r->digesturi, 1) < 0)
      {
	free (out);
	return NULL;
      }

  if (r->response)
    if (comma_append (&out, "response", r->response, 0) < 0)
      {
	free (out);
	return NULL;
      }

  if (r->clientmaxbuf)
    {
      char *tmp;

      if (asprintf (&tmp, "%lu", r->clientmaxbuf) < 0)
	{
	  free (out);
	  return NULL;
	}

      if (comma_append (&out, "maxbuf", tmp, 0) < 0)
	{
	  free (tmp);
	  free (out);
	  return NULL;
	}

      free (tmp);
    }

  if (r->utf8)
    if (comma_append (&out, "charset", "utf-8", 0) < 0)
      {
	free (out);
	return NULL;
      }

  if (cipher)
    if (comma_append (&out, cipher, NULL, 0) < 0)
      {
	free (out);
	return NULL;
      }

  if (r->authzid)
    if (comma_append (&out, "authzid", r->authzid, 1) < 0)
      {
	free (out);
	return NULL;
      }

  return out;
}

char *
digest_md5_print_finish (digest_md5_finish * finish)
{
  char *out;

  /* Below we assume the mandatory fields are present, verify that
     first to avoid crashes. */
  if (digest_md5_validate_finish (finish) != 0)
    return NULL;

  if (asprintf (&out, "rspauth=%s", finish->rspauth) < 0)
    return NULL;

  return out;
}
