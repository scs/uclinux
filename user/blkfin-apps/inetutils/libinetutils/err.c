/* 4.4BSD utility functions for error messages.

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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
#include <stdarg.h>
#else
#include <varargs.h>
#endif
#include <err.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <stdio.h>

extern char *__progname;

#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__

#define VA(call)							      \
{									      \
  va_list ap;								      \
  va_start (ap, format);						      \
  call;									      \
  va_end (ap);								      \
}
#define VAS VA

#else /* !(HAVE_STDARG_H && __STDC__) */

#define _VA(call, DECLS, INIT)						      \
{									      \
  DECLS									      \
  const char *format;							      \
  va_list ap;								      \
  va_start (ap);							      \
  INIT									      \
  format = va_arg (ap, const char *);					      \
  call;									      \
  va_end (ap);								      \
}
#define VA(call) _VA(call,,)
#define VAS(call) _VA(call, int status;, status = va_arg (ap, int);)

#endif /* HAVE_STDARG_H && __STDC__ */

void
vwarnx (format, ap)
     const char *format;
     va_list ap;
{
  if (__progname)
    fprintf (stderr, "%s: ", __progname);
  if (format)
    vfprintf (stderr, format, ap);
  putc ('\n', stderr);
}

void
vwarn (format, ap)
     const char *format;
     va_list ap;
{
  int error = errno;

  if (__progname)
    fprintf (stderr, "%s: ", __progname);
  if (format)
    {
      vfprintf (stderr, format, ap);
      fputs (": ", stderr);
    }
  fprintf (stderr, "%s\n", strerror (error));
}


void
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
warn (const char *format, ...)
#else
warn (va_alist) va_dcl
#endif
{
  VA (vwarn (format, ap))
}

void
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
warnx (const char *format, ...)
#else
warnx (va_alist) va_dcl
#endif
{
  VA (vwarnx (format, ap))
}

void
verr (status, format, ap)
     int status;
     const char *format;
     va_list ap;
{
  vwarn (format, ap);
  exit (status);
}

void
verrx (status, format, ap)
     int status;
     const char *format;
     va_list ap;
{
  vwarnx (format, ap);
  exit (status);
}

void
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
err (int status, const char *format, ...)
#else
err (va_alist) va_dcl
#endif
{
  VAS (verr (status, format, ap))
}

void
#if defined(HAVE_STDARG_H) && defined(__STDC__) && __STDC__
errx (int status, const char *format, ...)
#else
errx (va_alist) va_dcl
#endif
{
  VAS (verrx (status, format, ap))
}
