/* free.c --- Wrapper around the `free' function, primarily for Windows
 * Copyright (C) 2004, 2005, 2006, 2007, 2008, 2009  Simon Josefsson
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

/* Get specification. */
#include "internal.h"

/**
 * gsasl_free:
 * @ptr: memory pointer
 *
 * Invoke free(@ptr) to de-allocate memory pointer.  Typically used on
 * strings allocated by other libgsasl functions.
 *
 * This is useful on Windows where libgsasl is linked to one CRT and
 * the application is linked to another CRT.  Then malloc/free will
 * not use the same heap.  This happens if you build libgsasl using
 * mingw32 and the application with Visual Studio.
 *
 * Since: 0.2.19
 **/
void
gsasl_free (void *ptr)
{
  free (ptr);
}
