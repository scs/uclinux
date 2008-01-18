/*
 * ipod_error.h
 *
 * Duane Maxwell
 * (c) 2005 by Linspire Inc
 *
 * This library is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTIBILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307  USA
 */

#ifndef __IPOD_ERROR_H__
#define __IPOD_ERROR_H__

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/** \file ipod_error.h
 *  \brief Error handling
 *
 * An application can override the default error handling routines by setting
 * a new function.  By default, the routine calls vfprintf to stderr.
 */

/** \brief An application-specific error handling routine
 *
 * \param userData additional application-specific data sent to the callback
 * \param fmt the printf-style format string
 * \param ap a vector of parameters for the format string
 */
typedef void (*ipod_error_func)(void *userData,const char *fmt, va_list ap);

/** \brief Error routine called by internal functions
 *
 * \param fmt printf-type format for additional parameters
 *
 */
extern void ipod_error(const char *fmt,...);

/** \brief Set the callback for error handling
 *
 * \param func the error handling function
 * \param userData additional application-specific data to be sent to the error handling function
 */
extern void ipod_error_set_func(ipod_error_func func, void *userData);

#ifdef __cplusplus
};
#endif

#endif
