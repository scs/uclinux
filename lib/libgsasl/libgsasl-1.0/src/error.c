/* error.c --- Error handling functionality.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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

#include "internal.h"

/* I18n of error codes. */
#include "gettext.h"
#define _(String) dgettext (PACKAGE, String)
#define gettext_noop(String) String
#define N_(String) gettext_noop (String)

#define ERR(name, desc) { name, #name, desc }

#ifdef GSASL_NO_OBSOLETE
#define OBS(i, name, desc) { i, NULL, NULL }
#else
#define OBS(i, name, desc) { name, #name, desc }
#endif

static struct {
  int rc;
  const char *name;
  const char *description;
} errors[] = {
  ERR (GSASL_OK, N_("Libgsasl success")),
  ERR (GSASL_NEEDS_MORE, N_("SASL mechanism needs more data")),
  ERR (GSASL_UNKNOWN_MECHANISM, N_("Unknown SASL mechanism")),
  ERR (GSASL_MECHANISM_CALLED_TOO_MANY_TIMES,
       N_("SASL mechanism called too many times")),
  OBS (4, GSASL_TOO_SMALL_BUFFER,
       N_("SASL function needs larger buffer (internal error)")),
  OBS (5, GSASL_FOPEN_ERROR, N_("Could not open file in SASL library")),
  OBS (6, GSASL_FCLOSE_ERROR, N_("Could not close file in SASL library")),
  ERR (GSASL_MALLOC_ERROR, N_("Memory allocation error in SASL library")),
  ERR (GSASL_BASE64_ERROR, N_("Base 64 coding error in SASL library")),
  ERR (GSASL_CRYPTO_ERROR, N_("Low-level crypto error in SASL library")),
  { 10, NULL, NULL },
  OBS (11, GSASL_NEED_CLIENT_ANONYMOUS_CALLBACK,
       N_("SASL mechanism needs gsasl_client_callback_anonymous() callback"
	  " (application error)")),
  OBS (12, GSASL_NEED_CLIENT_PASSWORD_CALLBACK,
       N_("SASL mechanism needs gsasl_client_callback_password() callback"
	  " (application error)")),
  OBS (13, GSASL_NEED_CLIENT_PASSCODE_CALLBACK,
       N_("SASL mechanism needs gsasl_client_callback_passcode() callback"
	  " (application error)")),
  OBS (14, GSASL_NEED_CLIENT_PIN_CALLBACK,
       N_("SASL mechanism needs gsasl_client_callback_pin() callback"
	  " (application error)")),
  OBS (15, GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK,
       N_("SASL mechanism needs gsasl_client_callback_authorization_id() "
	  "callback (application error)")),
  OBS (16, GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK,
       N_("SASL mechanism needs gsasl_client_callback_authentication_id() "
	  "callback (application error)")),
  OBS (17, GSASL_NEED_CLIENT_SERVICE_CALLBACK,
       N_("SASL mechanism needs gsasl_client_callback_service() callback "
	  "(application error)")),
  OBS (18, GSASL_NEED_SERVER_VALIDATE_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_validate() callback "
	  "(application error)")),
  OBS (19, GSASL_NEED_SERVER_CRAM_MD5_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_cram_md5() callback "
	  "(application error)")),
  OBS (20, GSASL_NEED_SERVER_DIGEST_MD5_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_digest_md5() callback "
	  "(application error)")),
  OBS (21, GSASL_NEED_SERVER_EXTERNAL_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_external() callback "
	  "(application error)")),
  OBS (22, GSASL_NEED_SERVER_ANONYMOUS_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_anonymous() callback "
	  "(application error)")),
  OBS (23, GSASL_NEED_SERVER_REALM_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_realm() callback "
	  "(application error)")),
  OBS (24, GSASL_NEED_SERVER_SECURID_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_securid() callback "
	  "(application error)")),
  OBS (25, GSASL_NEED_SERVER_SERVICE_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_service() callback "
	  "(application error)")),
  OBS (26, GSASL_NEED_SERVER_GSSAPI_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_gssapi() callback "
	  "(application error)")),
  OBS (27, GSASL_NEED_SERVER_RETRIEVE_CALLBACK,
       N_("SASL mechanism needs gsasl_server_callback_retrieve() callback "
	  "(application error)")),
  OBS (28, GSASL_UNICODE_NORMALIZATION_ERROR,
       N_("Failed to perform Unicode Normalization on string.")),
  ERR (GSASL_SASLPREP_ERROR,
       N_("Could not prepare internationalized (non-ASCII) string.")),
  ERR (GSASL_MECHANISM_PARSE_ERROR,
       N_("SASL mechanism could not parse input")),
  ERR (GSASL_AUTHENTICATION_ERROR, N_("Error authenticating user")),
  OBS (32, GSASL_CANNOT_GET_CTX,
       N_("Cannot get internal library handle (library error)")),
  ERR (GSASL_INTEGRITY_ERROR, N_("Integrity error in application payload")),
  OBS (34, GSASL_NO_MORE_REALMS, N_("No more realms available (non-fatal)")),
  ERR (GSASL_NO_CLIENT_CODE,
       N_("Client-side functionality not available in library "
	  "(application error)")),
  ERR (GSASL_NO_SERVER_CODE,
       N_("Server-side functionality not available in library "
	  "(application error)")),
  ERR (GSASL_GSSAPI_RELEASE_BUFFER_ERROR,
       N_("GSSAPI library could not deallocate memory in "
	  "gss_release_buffer() in SASL library.  This is a serious "
	  "internal error.")),
  ERR (GSASL_GSSAPI_IMPORT_NAME_ERROR,
       N_("GSSAPI library could not understand a peer name in "
	  "gss_import_name() in SASL library.  This is most likely due "
	  "to incorrect service and/or hostnames.")),
  ERR (GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR,
       N_("GSSAPI error in client while negotiating security context in "
	  "gss_init_sec_context() in SASL library.  This is most likely "
	  "due insufficient credentials or malicious interactions.")),
  ERR (GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR,
       N_("GSSAPI error in server while negotiating security context in "
	  "gss_init_sec_context() in SASL library.  This is most likely due "
	  "insufficient credentials or malicious interactions.")),
  ERR (GSASL_GSSAPI_UNWRAP_ERROR,
       N_("GSSAPI error while decrypting or decoding data in gss_unwrap() in "
	  "SASL library.  This is most likely due to data corruption.")),
  ERR (GSASL_GSSAPI_WRAP_ERROR,
       N_("GSSAPI error while encrypting or encoding data in gss_wrap() in "
	  "SASL library.")),
  ERR (GSASL_GSSAPI_ACQUIRE_CRED_ERROR,
       N_("GSSAPI error acquiring credentials in gss_acquire_cred() in "
	  "SASL library.  This is most likely due to not having the proper "
	  "Kerberos key available in /etc/krb5.keytab on the server.")),
  ERR (GSASL_GSSAPI_DISPLAY_NAME_ERROR,
       N_("GSSAPI error creating a display name denoting the client in "
	  "gss_display_name() in SASL library.  This is probably because "
	  "the client supplied bad data.")),
  ERR (GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR,
       N_("Other entity requested integrity or confidentiality protection "
	  "in GSSAPI mechanism but this is currently not implemented.")),
  ERR (GSASL_KERBEROS_V5_INIT_ERROR,
       N_("Kerberos V5 initialization failure.")),
  ERR (GSASL_KERBEROS_V5_INTERNAL_ERROR,
       N_("Kerberos V5 internal error.")),
  ERR (GSASL_SECURID_SERVER_NEED_ADDITIONAL_PASSCODE,
       N_("SecurID needs additional passcode.")),
  ERR (GSASL_SECURID_SERVER_NEED_NEW_PIN,
       N_("SecurID needs new pin.")),
  OBS (50, GSASL_INVALID_HANDLE,
       N_("The provided library handle was invalid (application error)")),
  ERR (GSASL_NO_CALLBACK,
       N_("No callback specified by caller (application error).")),
  ERR (GSASL_NO_ANONYMOUS_TOKEN,
       N_("Authentication failed because the anonymous token was "
	  "not provided.")),
  ERR (GSASL_NO_AUTHID,
       N_("Authentication failed because the authentication identity was "
	  "not provided.")),
  ERR (GSASL_NO_AUTHZID,
       N_("Authentication failed because the authorization identity was "
	  "not provided.")),
  ERR (GSASL_NO_PASSWORD,
       N_("Authentication failed because the password was not provided.")),
  ERR (GSASL_NO_PASSCODE,
       N_("Authentication failed because the passcode was not provided.")),
  ERR (GSASL_NO_PIN,
       N_("Authentication failed because the pin code was not provided.")),
  ERR (GSASL_NO_SERVICE,
       N_("Authentication failed because the service name was not provided.")),
  ERR (GSASL_NO_HOSTNAME,
       N_("Authentication failed because the host name was not provided."))
};

/**
 * gsasl_strerror:
 * @err: libgsasl error code
 *
 * Convert return code to human readable string explanation of the
 * reason for the particular error code.
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing an explanation of the error code @err.
 **/
const char *
gsasl_strerror (int err)
{
  static const char *unknown = N_("Libgsasl unknown error");
  const char *p;

  bindtextdomain (PACKAGE, LOCALEDIR);

  if (err < 0 || err >= (sizeof (errors) / sizeof (errors[0])))
    return _(unknown);

  p = errors[err].description;
  if (!p)
    p = unknown;

  return _(p);
}


/**
 * gsasl_strerror_name:
 * @err: libgsasl error code
 *
 * Convert return code to human readable string representing the error
 * code symbol itself.  For example, gsasl_strerror_name(%GSASL_OK)
 * returns the string "GSASL_OK".
 *
 * This string can be used to output a diagnostic message to the user.
 *
 * Return value: Returns a pointer to a statically allocated string
 *   containing a string version of the error code @err, or %NULL if
 *   the error code is not known.
 *
 * Since: 0.2.29
 **/
const char *
gsasl_strerror_name (int err)
{
  if (err < 0 || err >= (sizeof (errors) / sizeof (errors[0])))
    return NULL;

  return errors[err].name;
}
