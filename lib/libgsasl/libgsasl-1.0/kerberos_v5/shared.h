/* shared.h --- Experimental SASL mechanism KERBEROS_V5, shared definitions.
 * Copyright (C) 2003, 2004  Simon Josefsson
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

#include "kerberos_v5.h"

/* Get Shishi API. */
#include <shishi.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>		/* ntohl */
#endif

#define DEBUG 0

#define BITMAP_LEN 1
#define MAXBUF_LEN 4
#define RANDOM_LEN 16
#define MUTUAL (1 << 3)

#define SERVER_HELLO_LEN BITMAP_LEN + MAXBUF_LEN + RANDOM_LEN
#define CLIENT_HELLO_LEN BITMAP_LEN + MAXBUF_LEN

#define MAXBUF_DEFAULT 65536
