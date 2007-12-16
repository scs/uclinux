/* mechinfo.c --- Definition of DIGEST-MD5 mechanism.
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

#if HAVE_CONFIG_H
# include "config.h"
#endif

/* Get specification. */
#include "digest-md5.h"

Gsasl_mechanism gsasl_digest_md5_mechanism = {
  GSASL_DIGEST_MD5_NAME,
  {
   NULL,
   NULL,
#ifdef USE_CLIENT
   _gsasl_digest_md5_client_start,
#else
   NULL,
#endif
#ifdef USE_CLIENT
   _gsasl_digest_md5_client_step,
#else
   NULL,
#endif
#ifdef USE_CLIENT
   _gsasl_digest_md5_client_finish,
#else
   NULL,
#endif
#ifdef USE_CLIENT
   _gsasl_digest_md5_client_encode,
#else
   NULL,
#endif
#ifdef USE_CLIENT
   _gsasl_digest_md5_client_decode
#else
   NULL
#endif
   }
  ,
  {
   NULL,
   NULL,
#ifdef USE_SERVER
   _gsasl_digest_md5_server_start,
#else
   NULL,
#endif
#ifdef USE_SERVER
   _gsasl_digest_md5_server_step,
#else
   NULL,
#endif
#ifdef USE_SERVER
   _gsasl_digest_md5_server_finish,
#else
   NULL,
#endif
#ifdef USE_SERVER
   _gsasl_digest_md5_server_encode,
#else
   NULL,
#endif
#ifdef USE_SERVER
   _gsasl_digest_md5_server_decode
#else
   NULL
#endif
   }
};
