/* printer.h --- Convert DIGEST-MD5 token structures into strings.
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

#ifndef DIGEST_MD5_PRINTER_H
# define DIGEST_MD5_PRINTER_H

/* Get token types. */
#include "tokens.h"

extern char *digest_md5_print_challenge (digest_md5_challenge * challenge);

extern char *digest_md5_print_response (digest_md5_response * response);

extern char *digest_md5_print_finish (digest_md5_finish * out);

#endif /* DIGEST_MD5_PRINTER_H */
