/* parser.h --- DIGEST-MD5 parser.
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

#ifndef DIGEST_MD5_PARSER_H
# define DIGEST_MD5_PARSER_H

/* Get token types. */
#include "tokens.h"

extern int digest_md5_getsubopt (char **optionp,
				 const char *const *tokens, char **valuep);

extern int digest_md5_parse_challenge (const char *challenge, size_t len,
				       digest_md5_challenge * out);

extern int digest_md5_parse_response (const char *response, size_t len,
				      digest_md5_response * out);

extern int digest_md5_parse_finish (const char *finish, size_t len,
				    digest_md5_finish * out);

#endif /* DIGEST_MD5_PARSER_H */
