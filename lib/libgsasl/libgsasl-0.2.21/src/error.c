/* error.c --- Error handling functionality.
 * Copyright (C) 2002, 2003, 2004, 2005, 2006  Simon Josefsson
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

/**
 * gsasl_strerror:
 * @err: libgsasl error code
 *
 * Convert return code to human readable string.
 *
 * Return value: Returns a pointer to a statically allocated string
 * containing a description of the error with the error value @err.
 * This string can be used to output a diagnostic message to the user.
 **/
const char *
gsasl_strerror (int err)
{
  const char *p;

  bindtextdomain (PACKAGE, LOCALEDIR);

  switch (err)
    {
    case GSASL_OK:
      p = _("Libgsasl success");
      break;

    case GSASL_NEEDS_MORE:
      p = _("SASL mechanism needs more data");
      break;

    case GSASL_UNKNOWN_MECHANISM:
      p = _("Unknown SASL mechanism");
      break;

    case GSASL_MECHANISM_CALLED_TOO_MANY_TIMES:
      p = _("SASL mechanism called too many times");
      break;

    case GSASL_MALLOC_ERROR:
      p = _("Memory allocation error in SASL library");
      break;

    case GSASL_BASE64_ERROR:
      p = _("Base 64 coding error in SASL library");
      break;

    case GSASL_CRYPTO_ERROR:
      p = _("Low-level crypto error in SASL library");
      break;

    case GSASL_GSSAPI_RELEASE_BUFFER_ERROR:
      p = _("GSSAPI library could not deallocate memory in "
	    "gss_release_buffer() in SASL library.  This is a serious "
	    "internal error.");
      break;

    case GSASL_GSSAPI_IMPORT_NAME_ERROR:
      p = _("GSSAPI library could not understand a peer name in "
	    "gss_import_name() in SASL library.  This is most likely "
	    "due to incorrect service and/or hostnames.");
      break;

    case GSASL_GSSAPI_INIT_SEC_CONTEXT_ERROR:
      p = _("GSSAPI error in client while negotiating security context in "
	    "gss_init_sec_context() in SASL library.  This is most likely "
	    "due insufficient credentials or malicious interactions.");
      break;

    case GSASL_GSSAPI_ACCEPT_SEC_CONTEXT_ERROR:
      p = _("GSSAPI error in server while negotiating security context in "
	    "gss_init_sec_context() in SASL library.  This is most likely "
	    "due insufficient credentials or malicious interactions.");
      break;

    case GSASL_GSSAPI_UNWRAP_ERROR:
      p = _("GSSAPI error while decrypting or decoding data in "
	    "gss_unwrap() in SASL library.  This is most likely "
	    "due to data corruption.");
      break;

    case GSASL_GSSAPI_WRAP_ERROR:
      p = _("GSSAPI error while encrypting or encoding data in "
	    "gss_wrap() in SASL library.");
      break;

    case GSASL_GSSAPI_ACQUIRE_CRED_ERROR:
      p = _("GSSAPI error acquiring credentials in "
	    "gss_acquire_cred() in SASL library.  This is most likely due"
	    " to not having the proper Kerberos key available in "
	    "/etc/krb5.keytab on the server.");
      break;

    case GSASL_GSSAPI_DISPLAY_NAME_ERROR:
      p = _("GSSAPI error creating a display name denoting the "
	    "client in gss_display_name() in SASL library.  This is "
	    "probably because the client supplied bad data.");
      break;

    case GSASL_GSSAPI_UNSUPPORTED_PROTECTION_ERROR:
      p = _("Other entity requested integrity or confidentiality "
	    "protection in GSSAPI mechanism but this is currently "
	    "not implemented.");
      break;

    case GSASL_MECHANISM_PARSE_ERROR:
      p = _("SASL mechanism could not parse input");
      break;

    case GSASL_AUTHENTICATION_ERROR:
      p = _("Error authenticating user");
      break;

    case GSASL_INTEGRITY_ERROR:
      p = _("Integrity error in application payload");
      break;

    case GSASL_NO_CLIENT_CODE:
      p = _("Client-side functionality not available in library "
	    "(application error)");
      break;

    case GSASL_NO_SERVER_CODE:
      p = _("Server-side functionality not available in library "
	    "(application error)");
      break;

    case GSASL_NO_CALLBACK:
      p = _("No callback specified by caller (application error).");
      break;

    case GSASL_NO_ANONYMOUS_TOKEN:
      p = _("Authentication failed because the "
	    "anonymous token was not provided.");
      break;

    case GSASL_NO_AUTHID:
      p = _("Authentication failed because the "
	    "authentication identity was not provided.");
      break;

    case GSASL_NO_AUTHZID:
      p = _("Authentication failed because the "
	    "authorization identity was not provided.");
      break;

    case GSASL_NO_PASSWORD:
      p = _("Authentication failed because the "
	    "password was not provided.");
      break;

    case GSASL_NO_PASSCODE:
      p = _("Authentication failed because the "
	    "passcode was not provided.");
      break;

    case GSASL_NO_PIN:
      p = _("Authentication failed because the "
	    "pin code was not provided.");
      break;

    case GSASL_NO_SERVICE:
      p = _("Authentication failed because the "
	    "service name was not provided.");
      break;

    case GSASL_NO_HOSTNAME:
      p = _("Authentication failed because the "
	    "host name was not provided.");
      break;

    case GSASL_SASLPREP_ERROR:
      p = _("Could not prepare internationalized (non-ASCII) string.");
      break;

#ifndef GSASL_NO_OBSOLETE
    case GSASL_TOO_SMALL_BUFFER:
      p = _("SASL function needs larger buffer (internal error)");
      break;

    case GSASL_FOPEN_ERROR:
      p = _("Could not open file in SASL library");
      break;

    case GSASL_FCLOSE_ERROR:
      p = _("Could not close file in SASL library");
      break;

    case GSASL_CANNOT_GET_CTX:
      p = _("Cannot get internal library handle (library error)");
      break;

    case GSASL_NEED_CLIENT_ANONYMOUS_CALLBACK:
      p = _("SASL mechanism needs gsasl_client_callback_anonymous() callback "
	    "(application error)");
      break;

    case GSASL_NEED_CLIENT_PASSWORD_CALLBACK:
      p = _("SASL mechanism needs gsasl_client_callback_password() callback "
	    "(application error)");
      break;

    case GSASL_NEED_CLIENT_PASSCODE_CALLBACK:
      p = _("SASL mechanism needs gsasl_client_callback_passcode() callback "
	    "(application error)");
      break;

    case GSASL_NEED_CLIENT_PIN_CALLBACK:
      p = _("SASL mechanism needs gsasl_client_callback_pin() callback "
	    "(application error)");
      break;

    case GSASL_NEED_CLIENT_AUTHORIZATION_ID_CALLBACK:
      p = _("SASL mechanism needs gsasl_client_callback_authorization_id() "
	    "callback (application error)");
      break;

    case GSASL_NEED_CLIENT_AUTHENTICATION_ID_CALLBACK:
      p = _("SASL mechanism needs gsasl_client_callback_authentication_id() "
	    "callback (application error)");
      break;

    case GSASL_NEED_CLIENT_SERVICE_CALLBACK:
      p = _("SASL mechanism needs gsasl_client_callback_service() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_VALIDATE_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_validate() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_CRAM_MD5_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_cram_md5() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_DIGEST_MD5_CALLBACK:
      p =
	_("SASL mechanism needs gsasl_server_callback_digest_md5() callback "
	  "(application error)");
      break;

    case GSASL_NEED_SERVER_ANONYMOUS_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_anonymous() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_EXTERNAL_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_external() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_REALM_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_realm() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_SECURID_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_securid() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_SERVICE_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_service() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_GSSAPI_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_gssapi() callback "
	    "(application error)");
      break;

    case GSASL_NEED_SERVER_RETRIEVE_CALLBACK:
      p = _("SASL mechanism needs gsasl_server_callback_retrieve() "
	    "callback (application error)");
      break;

    case GSASL_UNICODE_NORMALIZATION_ERROR:
      p = _("Failed to perform Unicode Normalization on string.");
      break;

    case GSASL_NO_MORE_REALMS:
      p = _("No more realms available (non-fatal)");
      break;

    case GSASL_INVALID_HANDLE:
      p = _("The provided library handle was invalid (application error)");
      break;
#endif

    default:
      p = _("Libgsasl unknown error");
      break;
    }

  return p;

}
