/* validate.h --- Validate consistency of DIGEST-MD5 tokens.
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

#ifndef DIGEST_MD5_VALIDATE_H
# define DIGEST_MD5_VALIDATE_H

/* Get token types. */
#include "tokens.h"

extern int digest_md5_validate_challenge (digest_md5_challenge * c);

extern int digest_md5_validate_response (digest_md5_response * r);

extern int digest_md5_validate_finish (digest_md5_finish * f);

extern int digest_md5_validate (digest_md5_challenge * c,
				digest_md5_response * r);

#endif /* DIGEST_MD5_VALIDATE_H */
