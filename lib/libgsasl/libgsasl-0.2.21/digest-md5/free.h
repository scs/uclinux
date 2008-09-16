/* free.h --- Free allocated data in DIGEST-MD5 token structures.
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

#ifndef DIGEST_MD5_FREE_H
# define DIGEST_MD5_FREE_H

/* Get token types. */
#include "tokens.h"

extern void digest_md5_free_challenge (digest_md5_challenge * c);

extern void digest_md5_free_response (digest_md5_response * r);

extern void digest_md5_free_finish (digest_md5_finish * f);

#endif /* DIGEST_MD5_FREE_H */
