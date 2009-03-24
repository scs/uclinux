/* callback.c --- Callback handling.
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

/**
 * gsasl_callback_set:
 * @ctx: handle received from gsasl_init().
 * @cb: pointer to function implemented by application.
 *
 * Store the pointer to the application provided callback in the
 * library handle.  The callback will be used, via gsasl_callback(),
 * by mechanisms to discover various parameters (such as username and
 * passwords).  The callback function will be called with a
 * Gsasl_property value indicating the requested behaviour.  For
 * example, for %GSASL_ANONYMOUS_TOKEN, the function is expected to
 * invoke gsasl_property_set(@CTX, %GSASL_ANONYMOUS_TOKEN, "token")
 * where "token" is the anonymous token the application wishes the
 * SASL mechanism to use.  See the manual for the meaning of all
 * parameters.
 *
 * Since: 0.2.0
 **/
void
gsasl_callback_set (Gsasl * ctx, Gsasl_callback_function cb)
{
  ctx->cb = cb;
}

/**
 * gsasl_callback:
 * @ctx: handle received from gsasl_init(), may be %NULL to derive it
 *   from @sctx.
 * @sctx: session handle.
 * @prop: enumerated value of Gsasl_property type.
 *
 * Invoke the application callback.  The @prop value indicate what the
 * callback is expected to do.  For example, for
 * %GSASL_ANONYMOUS_TOKEN, the function is expected to invoke
 * gsasl_property_set(@SCTX, %GSASL_ANONYMOUS_TOKEN, "token") where
 * "token" is the anonymous token the application wishes the SASL
 * mechanism to use.  See the manual for the meaning of all
 * parameters.
 *
 * Note that if no callback has been set by the application, but the
 * obsolete callback interface has been used, this function will
 * translate the old callback interface into the new.  This interface
 * should be sufficient to invoke all callbacks, both new and old.
 *
 * Return value: Returns whatever the application callback return, or
 *   %GSASL_NO_CALLBACK if no application was known.
 *
 * Since: 0.2.0
 **/
int
gsasl_callback (Gsasl * ctx, Gsasl_session * sctx, Gsasl_property prop)
{
  if (ctx == NULL && sctx == NULL)
    return GSASL_NO_CALLBACK;

  if (ctx == NULL)
    ctx = sctx->ctx;

  if (ctx->cb)
    return ctx->cb (ctx, sctx, prop);

#ifndef GSASL_NO_OBSOLETE
  return _gsasl_obsolete_callback (ctx, sctx, prop);
#endif

  return GSASL_NO_CALLBACK;
}

/**
 * gsasl_callback_hook_set:
 * @ctx: libgsasl handle.
 * @hook: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl handle.
 *
 * The application data can be later (for instance, inside a callback)
 * be retrieved by calling gsasl_callback_hook_get().  This is
 * normally used by the application to maintain a global state between
 * the main program and callbacks.
 *
 * Since: 0.2.0
 **/
void
gsasl_callback_hook_set (Gsasl * ctx, void *hook)
{
  ctx->application_hook = hook;
}

/**
 * gsasl_callback_hook_get:
 * @ctx: libgsasl handle.
 *
 * Retrieve application specific data from libgsasl handle.
 *
 * The application data is set using gsasl_callback_hook_set().  This
 * is normally used by the application to maintain a global state
 * between the main program and callbacks.
 *
 * Return value: Returns the application specific data, or %NULL.
 *
 * Since: 0.2.0
 **/
void *
gsasl_callback_hook_get (Gsasl * ctx)
{
  return ctx->application_hook;
}

/**
 * gsasl_session_hook_set:
 * @sctx: libgsasl session handle.
 * @hook: opaque pointer to application specific data.
 *
 * Store application specific data in the libgsasl session handle.
 *
 * The application data can be later (for instance, inside a callback)
 * be retrieved by calling gsasl_session_hook_get().  This is normally
 * used by the application to maintain a per-session state between the
 * main program and callbacks.
 *
 * Since: 0.2.14
 **/
void
gsasl_session_hook_set (Gsasl_session * sctx, void *hook)
{
  sctx->application_hook = hook;
}

/**
 * gsasl_session_hook_get:
 * @sctx: libgsasl session handle.
 *
 * Retrieve application specific data from libgsasl session handle.
 *
 * The application data is set using gsasl_callback_hook_set().  This
 * is normally used by the application to maintain a per-session state
 * between the main program and callbacks.
 *
 * Return value: Returns the application specific data, or %NULL.
 *
 * Since: 0.2.14
 **/
void *
gsasl_session_hook_get (Gsasl_session * sctx)
{
  return sctx->application_hook;
}
