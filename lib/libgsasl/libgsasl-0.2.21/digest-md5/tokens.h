/* tokens.h --- Types for DIGEST-MD5 tokens.
 * Copyright (C) 2004  Simon Josefsson
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

#ifndef DIGEST_MD5_TOKENS_H
# define DIGEST_MD5_TOKENS_H

/* Get size_t. */
#include <stddef.h>

/* Length of MD5 output. */
#define DIGEST_MD5_LENGTH 16

/* Quality of Protection types. */
enum digest_md5_qop
{
  DIGEST_MD5_QOP_AUTH = 1,
  DIGEST_MD5_QOP_AUTH_INT = 2,
  DIGEST_MD5_QOP_AUTH_CONF = 4
};
typedef enum digest_md5_qop digest_md5_qop;

/* Cipher types. */
enum digest_md5_cipher
{
  DIGEST_MD5_CIPHER_DES = 1,
  DIGEST_MD5_CIPHER_3DES = 2,
  DIGEST_MD5_CIPHER_RC4 = 4,
  DIGEST_MD5_CIPHER_RC4_40 = 8,
  DIGEST_MD5_CIPHER_RC4_56 = 16,
  DIGEST_MD5_CIPHER_AES_CBC = 32
};
typedef enum digest_md5_cipher digest_md5_cipher;

/*
 * digest-challenge  =
 *       1#( realm | nonce | qop-options | stale | server_maxbuf | charset
 *             algorithm | cipher-opts | auth-param )
 *
 * realm             = "realm" "=" <"> realm-value <">
 * realm-value       = qdstr-val
 * nonce             = "nonce" "=" <"> nonce-value <">
 * nonce-value       = *qdtext
 * qop-options       = "qop" "=" <"> qop-list <">
 * qop-list          = 1#qop-value
 * qop-value         = "auth" | "auth-int" | "auth-conf" | qop-token
 *                    ;; qop-token is reserved for identifying future
 *                    ;; extensions to DIGEST-MD5
 * qop-token         = token
 * stale             = "stale" "=" "true"
 * server_maxbuf     = "maxbuf" "=" maxbuf-value
 * maxbuf-value      = 1*DIGIT
 * charset           = "charset" "=" "utf-8"
 * algorithm         = "algorithm" "=" "md5-sess"
 * cipher-opts       = "cipher" "=" <"> 1#cipher-value <">
 * cipher-value      = "3des" | "des" | "rc4-40" | "rc4" |
 *                     "rc4-56" | "aes-cbc" | cipher-token
 *                     ;; "des" and "3des" ciphers are obsolete.
 *                     ;; cipher-token is reserved for new ciphersuites
 * cipher-token      = token
 * auth-param        = token "=" ( token | quoted-string )
 *
 */
struct digest_md5_challenge
{
  size_t nrealms;
  char **realms;
  char *nonce;
  int qops;
  int stale;
  unsigned long servermaxbuf;
  int utf8;
  int ciphers;
};
typedef struct digest_md5_challenge digest_md5_challenge;

#define DIGEST_MD5_RESPONSE_LENGTH 32

/*
 * digest-response  = 1#( username | realm | nonce | cnonce |
 *                        nonce-count | qop | digest-uri | response |
 *                        client_maxbuf | charset | cipher | authzid |
 *                        auth-param )
 *
 *     username         = "username" "=" <"> username-value <">
 *     username-value   = qdstr-val
 *     cnonce           = "cnonce" "=" <"> cnonce-value <">
 *     cnonce-value     = *qdtext
 *     nonce-count      = "nc" "=" nc-value
 *     nc-value         = 8LHEX
 *     client_maxbuf    = "maxbuf" "=" maxbuf-value
 *     qop              = "qop" "=" qop-value
 *     digest-uri       = "digest-uri" "=" <"> digest-uri-value <">
 *     digest-uri-value  = serv-type "/" host [ "/" serv-name ]
 *     serv-type        = 1*ALPHA
 *     serv-name        = host
 *     response         = "response" "=" response-value
 *     response-value   = 32LHEX
 *     LHEX             = "0" | "1" | "2" | "3" |
 *                        "4" | "5" | "6" | "7" |
 *                        "8" | "9" | "a" | "b" |
 *                        "c" | "d" | "e" | "f"
 *     cipher           = "cipher" "=" cipher-value
 *     authzid          = "authzid" "=" <"> authzid-value <">
 *     authzid-value    = qdstr-val
 *
 */
struct digest_md5_response
{
  char *username;
  char *realm;
  char *nonce;
  char *cnonce;
  unsigned long nc;
  digest_md5_qop qop;
  char *digesturi;
  unsigned long clientmaxbuf;
  int utf8;
  digest_md5_cipher cipher;
  char *authzid;
  char response[DIGEST_MD5_RESPONSE_LENGTH + 1];
};
typedef struct digest_md5_response digest_md5_response;

/*
 * response-auth = "rspauth" "=" response-value
 */
struct digest_md5_finish
{
  char rspauth[DIGEST_MD5_RESPONSE_LENGTH + 1];
};
typedef struct digest_md5_finish digest_md5_finish;

#endif /* DIGEST_MD5_TOKENS_H */
