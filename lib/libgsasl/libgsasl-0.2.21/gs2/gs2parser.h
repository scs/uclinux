/* gs2parser.h --- GS2 parser.
 * Copyright (C) 2006  Simon Josefsson
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

#ifndef GS2_PARSER_H
# define GS2_PARSER_H

#include <string.h>

struct gs2_token {
  const char *context_token;
  size_t context_length;
  const char *wrap_token;
  size_t wrap_length;
};

extern int gs2_parser (const char *token, size_t toklen,
		       struct gs2_token *out);

extern int gs2_encode (const char *context, size_t context_length,
		       const char *wrap, size_t wrap_length,
		       char *out, size_t *outlen);

#endif /* GS2_PARSER_H */
