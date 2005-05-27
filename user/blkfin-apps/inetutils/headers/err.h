/* err.h --- 4.4BSD utility functions for error messages.
Copyright (C) 1995, 1996, 1997 Free Software Foundation, Inc.
This file was part of the GNU C Library.

The GNU C Library is free software; you can redistribute it and/or
modify it under the terms of the GNU Library General Public License as
published by the Free Software Foundation; either version 2 of the
License, or (at your option) any later version.

The GNU C Library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Library General Public License for more details.

You should have received a copy of the GNU Library General Public
License along with the GNU C Library; see the file COPYING.LIB.  If
not, write to the Free Software Foundation, Inc., 675 Mass Ave,
Cambridge, MA 02139, USA.  */

#ifndef	_ERR_H_
#define	_ERR_H_	1

#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
#include <stdarg.h>
#endif

/* Print FORMAT on stderr.  */
extern void warn __P ((const char *format, ...));
extern void vwarn __P ((const char *format, va_list));

/* Print "program: ", and FORMAT, and a newline, on stderr.  */
extern void warnx __P ((const char *format, ...));
extern void vwarnx __P ((const char *format, va_list));

/* Likewise, and then exit with STATUS.  */
extern void err __P ((int __status, const char *format, ...));
extern void verr __P ((int __status, const char *format, va_list));
extern void errx __P ((int __status, const char *format, ...));
extern void verrx __P ((int __status, const char *, va_list));

#endif	/* err.h */
