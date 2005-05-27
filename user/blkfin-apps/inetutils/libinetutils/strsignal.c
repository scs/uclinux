/* GNU mailutils - a suite of utilities for electronic mail
   Copyright (C) 1999, 2000, 2001 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Library Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Library General Public License for more details.

   You should have received a copy of the GNU Library General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#if HAVE_CONFIG_H
# include <config.h>
#endif
#include <unistd.h>
#include <signal.h>
#ifndef SYS_SIGLIST_DECLARED
/* For snprintf ().  */
#include <stdio.h>
#endif

#ifndef __P
# ifdef __STDC__
#  define __P(args) args
# else
#  define __P(args) ()
# endif
#endif /*__P */

/* Some systems do not define NSIG in <signal.h>.  */
#ifndef NSIG
# ifdef  _NSIG
#  define NSIG    _NSIG
# else
#  define NSIG    32
# endif
#endif

/* FIXME: Should probably go in a .h somewhere.  */
char *strsignal __P ((int));

char *
strsignal (int signo)
{
#ifdef SYS_SIGLIST_DECLARED
  /* Let's try to protect ourself a little.  */
  if (signo > 0 || signo < NSIG)
    return (char *)sys_siglist[signo];
  return (char *)"";
#else
  static char buf[64];
  snprintf (buf, sizeof buf, "Signal %d", signo);
  return buf;
#endif
}
