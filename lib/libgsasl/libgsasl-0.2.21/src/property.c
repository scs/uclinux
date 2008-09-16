/* property.c --- Callback property handling.
 * Copyright (C) 2004, 2005  Simon Josefsson
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

static char **
map (Gsasl_session * sctx, Gsasl_property prop)
{
  char **p = NULL;

  if (!sctx)
    return NULL;

  switch (prop)
    {
    case GSASL_ANONYMOUS_TOKEN:
      p = &sctx->anonymous_token;
      break;

    case GSASL_SERVICE:
      p = &sctx->service;
      break;

    case GSASL_HOSTNAME:
      p = &sctx->hostname;
      break;

    case GSASL_AUTHID:
      p = &sctx->authid;
      break;

    case GSASL_AUTHZID:
      p = &sctx->authzid;
      break;

    case GSASL_PASSWORD:
      p = &sctx->password;
      break;

    case GSASL_PASSCODE:
      p = &sctx->passcode;
      break;

    case GSASL_PIN:
      p = &sctx->pin;
      break;

    case GSASL_SUGGESTED_PIN:
      p = &sctx->suggestedpin;
      break;

    case GSASL_GSSAPI_DISPLAY_NAME:
      p = &sctx->gssapi_display_name;
      break;

    case GSASL_REALM:
      p = &sctx->realm;
      break;

    default:
      break;
    }

  return p;
}

/**
 * gsasl_property_set:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 * @data: zero terminated character string to store.
 *
 * Make a copy of @data and store it in the session handle for the
 * indicated property @prop.
 *
 * You can immediately deallocate @data after calling this function,
 * without affecting the data stored in the session handle.
 *
 * Since: 0.2.0
 **/
void
gsasl_property_set (Gsasl_session * sctx, Gsasl_property prop,
		    const char *data)
{
  gsasl_property_set_raw (sctx, prop, data, data ? strlen (data) : 0);
}

/**
 * gsasl_property_set_raw:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 * @data: character string to store.
 * @len: length of character string to store.
 *
 * Make a copy of @len sized @data and store a zero terminated version
 * of it in the session handle for the indicated property @prop.
 *
 * You can immediately deallocate @data after calling this function,
 * without affecting the data stored in the session handle.
 *
 * Except for the length indicator, this function is identical to
 * gsasl_property_set.
 *
 * Since: 0.2.0
 **/
void
gsasl_property_set_raw (Gsasl_session * sctx, Gsasl_property prop,
			const char *data, size_t len)
{
  char **p = map (sctx, prop);

  if (p)
    {
      if (*p)
	free (*p);
      if (data)
	{
	  *p = malloc (len + 1);
	  if (*p)
	    {
	      memcpy (*p, data, len);
	      (*p)[len] = '\0';
	    }
	}
      else
	*p = NULL;
    }
}

/**
 * gsasl_property_fast:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 *
 * Retrieve the data stored in the session handle for given property
 * @prop.
 *
 * The pointer is to live data, and must not be deallocated or
 * modified in any way.
 *
 * This function will not invoke the application callback.
 *
 * Return value: Return property value, if known, or %NULL if no value
 *   known.
 *
 * Since: 0.2.0
 **/
const char *
gsasl_property_fast (Gsasl_session * sctx, Gsasl_property prop)
{
  char **p = map (sctx, prop);

  if (p)
    return *p;

  return NULL;
}

/**
 * gsasl_property_get:
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type, indicating the
 *        type of data in @data.
 *
 * Retrieve the data stored in the session handle for given property
 * @prop, possibly invoking the application callback to get the value.
 *
 * The pointer is to live data, and must not be deallocated or
 * modified in any way.
 *
 * This function will invoke the application callback, using
 * gsasl_callback(), when a property value is not known.
 *
 * If no value is known, and no callback is specified or if the
 * callback fail to return data, and if any obsolete callback
 * functions has been set by the application, this function will try
 * to call these obsolete callbacks, and store the returned data as
 * the corresponding property.  This behaviour of this function will
 * be removed when the obsolete callback interfaces are removed.
 *
 * Return value: Return data for property, or NULL if no value known.
 *
 * Since: 0.2.0
 **/
const char *
gsasl_property_get (Gsasl_session * sctx, Gsasl_property prop)
{
  const char *p = gsasl_property_fast (sctx, prop);

  if (!p)
    {
      gsasl_callback (NULL, sctx, prop);
      p = gsasl_property_fast (sctx, prop);
    }

#ifndef GSASL_NO_OBSOLETE
  if (!p)
    {
      Gsasl_client_callback_anonymous cb_anonymous;
      Gsasl_client_callback_authorization_id cb_authorization_id;
      Gsasl_client_callback_authentication_id cb_authentication_id;
      Gsasl_client_callback_password cb_password;
      Gsasl_client_callback_passcode cb_passcode;
      Gsasl_client_callback_pin cb_pin;
      Gsasl_client_callback_service cb_service;
      Gsasl_client_callback_realm cb_realm;
      char buf[BUFSIZ];
      size_t buflen = BUFSIZ - 1;
      int res;

      buf[0] = '\0';

      /* Call obsolete callbacks to get properties.  Remove this when
       * the obsolete callbacks are no longer supported. */

      switch (prop)
	{
	case GSASL_SERVICE:
	  cb_service = gsasl_client_callback_service_get (sctx->ctx);
	  if (!cb_service)
	    break;
	  res = cb_service (sctx, buf, &buflen, NULL, 0, NULL, 0);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_HOSTNAME:
	  cb_service = gsasl_client_callback_service_get (sctx->ctx);
	  if (!cb_service)
	    break;
	  res = cb_service (sctx, NULL, 0, buf, &buflen, NULL, 0);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_ANONYMOUS_TOKEN:
	  cb_anonymous = gsasl_client_callback_anonymous_get (sctx->ctx);
	  if (!cb_anonymous)
	    break;
	  res = cb_anonymous (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_AUTHID:
	  cb_authentication_id =
	    gsasl_client_callback_authentication_id_get (sctx->ctx);
	  if (!cb_authentication_id)
	    break;
	  res = cb_authentication_id (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_AUTHZID:
	  cb_authorization_id =
	    gsasl_client_callback_authorization_id_get (sctx->ctx);
	  if (!cb_authorization_id)
	    break;
	  res = cb_authorization_id (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_PASSWORD:
	  cb_password = gsasl_client_callback_password_get (sctx->ctx);
	  if (!cb_password)
	    break;
	  res = cb_password (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_PASSCODE:
	  cb_passcode = gsasl_client_callback_passcode_get (sctx->ctx);
	  if (!cb_passcode)
	    break;
	  res = cb_passcode (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_PIN:
	  cb_pin = gsasl_client_callback_pin_get (sctx->ctx);
	  if (!cb_pin)
	    break;
	  res = cb_pin (sctx, sctx->suggestedpin, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;

	case GSASL_REALM:
	  cb_realm = gsasl_client_callback_realm_get (sctx->ctx);
	  if (!cb_realm)
	    break;
	  res = cb_realm (sctx, buf, &buflen);
	  if (res != GSASL_OK)
	    break;
	  buf[buflen] = '\0';
	  gsasl_property_set (sctx, prop, buf);
	  break;


	default:
	  break;
	}
      p = gsasl_property_fast (sctx, prop);
    }
#endif

  return p;
}
