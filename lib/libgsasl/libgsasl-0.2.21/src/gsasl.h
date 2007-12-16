/* gsasl.h --- Header file for GNU SASL Library.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007  Simon Josefsson
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
 * License License along with GNU SASL Library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifndef GSASL_H
# define GSASL_H

# include <stdio.h>		/* FILE */
# include <stddef.h>		/* size_t */
# include <unistd.h>		/* ssize_t */

# ifdef __cplusplus
extern "C"
{
# endif

  /**
   * GSASL_VERSION
   *
   * String defined via CPP denoting the header file version number.
   * Used together with stringprep_check_version() to verify header file
   * and run-time library consistency.
   */
# define GSASL_VERSION "0.2.21"

  /* RFC 2222: SASL mechanisms are named by strings, from 1 to 20
   * characters in length, consisting of upper-case letters, digits,
   * hyphens, and/or underscores.  SASL mechanism names must be
   * registered with the IANA.
   */
  enum
  {
    GSASL_MIN_MECHANISM_SIZE = 1,
    GSASL_MAX_MECHANISM_SIZE = 20
  };
  extern const char *GSASL_VALID_MECHANISM_CHARACTERS;

  /* Error codes */
  typedef enum
  {
    GSASL_OK = 0,
    GSASL_NEEDS_MORE = 1,
    GSASL_UNKNOWN_MECHANISM = 2,
    GSASL_MECHANISM_CALLED_TOO_MANY_TIMES = 3,
    GSASL_MALLOC_ERROR = 7,
    GSASL_BASE64_ERROR = 8,
    GSASL_CRYPTO_ERROR = 9,
    GSASL_SASLPREP_ERROR = 29,
    GSASL_MECHANISM_PARSE_ERROR = 30,
    GSASL_AUTHENTICATION_ERROR = 31,
    GSASL_INTEGRITY_ERROR = 33,
    GSASL_NO_CLIENT_CODE = 35,
    GSASL_NO_SERVER_CODE = 36,
    GSASL_NO_CALLBACK = 51,
    GSASL_NO_ANONYMOUS_TOKEN = 52,
    GSASL_NO_AUTHID = 53,
    GSASL_NO_AUTHZID = 54,
    GSASL_NO_PASSWORD = 55,
    GSASL_NO_PASSCODE = 56,
    GSASL_NO_PIN = 57,
    GSASL_NO_SERVICE = 58,
    GSASL_NO_HOSTNAME = 59,
    /* Mechanism specific errors. */
    GSASL_GSSAPI_RELEASE_BUFFER_ERROR = 37,
    GSASL_GSSAPI_IMPORT_NAME_ERROR = 38,
    GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR = 39,
    GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR = 40,
    GSASL_GSSAPI_UNWRAP_ERROR = 41,
    GSASL_GSSAPI_WRAP_ERROR = 42,
    GSASL_GSSAPI_ACQUIRE_CRED_ERROR = 43,
    GSASL_GSSAPI_DISPLAY_NAME_ERROR = 44,
    GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR = 45,
    GSASL_KERBEROS_V5_INIT_ERROR = 46,
    GSASL_KERBEROS_V5_INTERNAL_ERROR = 47,
    GSASL_SHISHI_ERROR = GSASL_KERBEROS_V5_INTERNAL_ERROR,
    GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE = 48,
    GSASL_SECURID_SERVER_NEED_NEW_PIN = 49
  } Gsasl_rc;

  /* Quality of Protection types, used by DIGEST-MD5 */
  typedef enum
  {
    GSASL_QOP_AUTH = 1,
    GSASL_QOP_AUTH_INT = 2,
    GSASL_QOP_AUTH_CONF = 4
  } Gsasl_qop;

  /* Cipher types, used by DIGEST-MD5 */
  typedef enum
  {
    GSASL_CIPHER_DES = 1,
    GSASL_CIPHER_3DES = 2,
    GSASL_CIPHER_RC4 = 4,
    GSASL_CIPHER_RC4_40 = 8,
    GSASL_CIPHER_RC4_56 = 16,
    GSASL_CIPHER_AES = 32
  } Gsasl_cipher;

  /* SASLprep flags, see gsasl_saslprep(). */
  typedef enum
  {
    GSASL_ALLOW_UNASSIGNED = 1
  } Gsasl_saslprep_flags;

  /* Library handles */
  typedef struct Gsasl Gsasl;
  typedef struct Gsasl_session Gsasl_session;

  /* Callback/property types. */
  typedef enum
  {
    /* Information properties, e.g., username. */
    GSASL_AUTHID = 1,
    GSASL_AUTHZID = 2,
    GSASL_PASSWORD = 3,
    GSASL_ANONYMOUS_TOKEN = 4,
    GSASL_SERVICE = 5,
    GSASL_HOSTNAME = 6,
    GSASL_GSSAPI_DISPLAY_NAME = 7,
    GSASL_PASSCODE = 8,
    GSASL_SUGGESTED_PIN = 9,
    GSASL_PIN = 10,
    GSASL_REALM = 11,
    /* Server validation callback properties. */
    GSASL_VALIDATE_SIMPLE = 500,
    GSASL_VALIDATE_EXTERNAL = 501,
    GSASL_VALIDATE_ANONYMOUS = 502,
    GSASL_VALIDATE_GSSAPI = 503,
    GSASL_VALIDATE_SECURID = 504
  } Gsasl_property;

  /**
   * Gsasl_callback_function:
   * @ctx: libgsasl handle.
   * @sctx: session handle, may be NULL.
   * @prop: enumerated value of Gsasl_property type.
   *
   * Prototype of function that the application should implement.  Use
   * gsasl_callback_set() to inform the library about your callback
   * function.
   *
   * It is called by the SASL library when it need some information
   * from the application.  Depending on the value of @prop, it should
   * either set some property (e.g., username or password) using
   * gsasl_property_set(), or it should extract some properties (e.g.,
   * authentication and authorization identities) using
   * gsasl_property_fast() and use them to make a policy decision,
   * perhaps returning GSASL_AUTHENTICATION_ERROR or GSASL_OK
   * depending on whether the policy permitted the operation.
   *
   * Return value: Any valid return code, the interpretation of which
   *   depend on the @prop value.
   *
   * Since: 0.2.0
   **/
  typedef int (*Gsasl_callback_function) (Gsasl * ctx, Gsasl_session * sctx,
					  Gsasl_property prop);

  /* Library entry and exit points: version.c, init.c, done.c */
  extern int gsasl_init (Gsasl ** ctx);
  extern void gsasl_done (Gsasl * ctx);
  extern const char *gsasl_check_version (const char *req_version);

  /* Callback handling: callback.c */
  extern void gsasl_callback_set (Gsasl * ctx, Gsasl_callback_function cb);
  extern int gsasl_callback (Gsasl * ctx, Gsasl_session * sctx,
			     Gsasl_property prop);

  extern void gsasl_callback_hook_set (Gsasl * ctx, void *hook);
  extern void *gsasl_callback_hook_get (Gsasl * ctx);

  extern void gsasl_session_hook_set (Gsasl_session * sctx, void *hook);
  extern void *gsasl_session_hook_get (Gsasl_session * sctx);

  /* Property handling: property.c */
  extern void gsasl_property_set (Gsasl_session * sctx, Gsasl_property prop,
				  const char *data);
  extern void gsasl_property_set_raw (Gsasl_session * sctx,
				      Gsasl_property prop, const char *data,
				      size_t len);
  extern const char *gsasl_property_get (Gsasl_session * sctx,
					 Gsasl_property prop);
  extern const char *gsasl_property_fast (Gsasl_session * sctx,
					  Gsasl_property prop);

  /* Mechanism handling: listmech.c, supportp.c, suggest.c */
  extern int gsasl_client_mechlist (Gsasl * ctx, char **out);
  extern int gsasl_client_support_p (Gsasl * ctx, const char *name);
  extern const char *gsasl_client_suggest_mechanism (Gsasl * ctx,
						     const char *mechlist);

  extern int gsasl_server_mechlist (Gsasl * ctx, char **out);
  extern int gsasl_server_support_p (Gsasl * ctx, const char *name);

  /* Authentication functions: xstart.c, xstep.c, xfinish.c */
  extern int gsasl_client_start (Gsasl * ctx, const char *mech,
				 Gsasl_session ** sctx);
  extern int gsasl_server_start (Gsasl * ctx, const char *mech,
				 Gsasl_session ** sctx);
  extern int gsasl_step (Gsasl_session * sctx,
			 const char *input, size_t input_len,
			 char **output, size_t * output_len);
  extern int gsasl_step64 (Gsasl_session * sctx,
			   const char *b64input, char **b64output);
  extern void gsasl_finish (Gsasl_session * sctx);

  /* Session functions: xcode.c */
  extern int gsasl_encode (Gsasl_session * sctx,
			   const char *input, size_t input_len,
			   char **output, size_t * output_len);
  extern int gsasl_decode (Gsasl_session * sctx,
			   const char *input, size_t input_len,
			   char **output, size_t * output_len);

  /* Error handling: error.c */
  extern const char *gsasl_strerror (int err);

  /* Internationalized string processing: stringprep.c */
  extern int gsasl_saslprep (const char *in, Gsasl_saslprep_flags flags,
			     char **out, int *stringpreprc);

  /* Utilities: base64.c, md5pwd.c, crypto.c */
  extern int gsasl_simple_getpass (const char *filename,
				   const char *username,
				   char **key);
  extern int gsasl_base64_to (const char *in, size_t inlen,
			      char **out, size_t * outlen);
  extern int gsasl_base64_from (const char *in, size_t inlen,
				char **out, size_t * outlen);
  extern int gsasl_nonce (char *data, size_t datalen);
  extern int gsasl_random (char *data, size_t datalen);
  extern int gsasl_md5 (const char *in, size_t inlen, char *out[16]);
  extern int gsasl_hmac_md5 (const char *key, size_t keylen,
			     const char *in, size_t inlen, char *outhash[16]);
  extern void gsasl_free (void *ptr);

  /* Get the mechanism API. */
# include <gsasl-mech.h>

#ifndef GSASL_NO_OBSOLETE
  /* For compatibility with earlier versions. */
# include <gsasl-compat.h>
#endif

# ifdef __cplusplus
}
# endif

#endif				/* GSASL_H */
