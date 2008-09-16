/* digesthmac.h --- Compute DIGEST-MD5 response value.
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

#ifndef DIGEST_MD5_DIGESTHMAC_H
# define DIGEST_MD5_DIGESTHMAC_H

/* Get token types. */
#include "tokens.h"

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
extern int digest_md5_hmac (char *output, char secret[DIGEST_MD5_LENGTH],
			    char *nonce, unsigned long nc, char *cnonce,
			    digest_md5_qop qop, char *authzid,
			    char *digesturi, int rspauth,
			    digest_md5_cipher cipher, char *kic, char *kis,
			    char *kcc, char *kcs);

#endif /* DIGEST_MD5_DIGESTHMAC_H */
