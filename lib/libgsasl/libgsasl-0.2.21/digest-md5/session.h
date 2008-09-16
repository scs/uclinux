/* session.h --- Data integrity/privacy protection of DIGEST-MD5.
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

#ifndef DIGEST_MD5_SESSION_H
# define DIGEST_MD5_SESSION_H

/* Get token types. */
#include "tokens.h"

extern int digest_md5_encode (const char *input, size_t input_len,
			      char **output, size_t * output_len,
			      digest_md5_qop qop,
			      unsigned long sendseqnum,
			      char key[DIGEST_MD5_LENGTH]);

extern int digest_md5_decode (const char *input, size_t input_len,
			      char **output, size_t * output_len,
			      digest_md5_qop qop,
			      unsigned long readseqnum,
			      char key[DIGEST_MD5_LENGTH]);

#endif /* DIGEST_MD5_SESSION_H */
