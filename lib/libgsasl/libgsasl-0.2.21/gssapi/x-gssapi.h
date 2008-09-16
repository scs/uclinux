/* x-gssapi.h --- Prototypes for SASL mechanism GSSAPI as defined in RFC 2222.
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

#ifndef X_GSSAPI_H
#define X_GSSAPI_H

#include <gsasl.h>

#define GSASL_GSSAPI_NAME "GSSAPI"

extern Gsasl_mechanism gsasl_gssapi_mechanism;

extern int _gsasl_gssapi_client_start (Gsasl_session * sctx,
				       void **mech_data);
extern int _gsasl_gssapi_client_step (Gsasl_session * sctx,
				      void *mech_data,
				      const char *input, size_t input_len,
				      char **output, size_t * output_len);
extern void _gsasl_gssapi_client_finish (Gsasl_session * sctx,
					 void *mech_data);
extern int _gsasl_gssapi_client_encode (Gsasl_session * sctx,
					void *mech_data,
					const char *input, size_t input_len,
					char **output, size_t * output_len);
extern int _gsasl_gssapi_client_decode (Gsasl_session * sctx,
					void *mech_data,
					const char *input, size_t input_len,
					char **output, size_t * output_len);

extern int _gsasl_gssapi_server_start (Gsasl_session * sctx,
				       void **mech_data);
extern int _gsasl_gssapi_server_step (Gsasl_session * sctx,
				      void *mech_data,
				      const char *input, size_t input_len,
				      char **output, size_t * output_len);
extern void _gsasl_gssapi_server_finish (Gsasl_session * sctx,
					 void *mech_data);

#endif /* X_GSSAPI_H */
