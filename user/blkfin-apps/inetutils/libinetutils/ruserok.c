/* Based on the rcmd.c.new file distributed with linux libc 5.4.19
   Adapted to inetutils by Bernhard Rosenkraenzer <bero@startrek.in-trier.de>

   Note that a lot in this file is superfluous; hopefully it won't be a
   problem for systems that need it for iruserok &c....  */
/*
 * Copyright (c) 1983, 1993, 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#include <pwd.h>
#include <sys/file.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/socket.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#if defined(STDC_HEADERS) || defined(HAVE_STDLIB_H)
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
# include <string.h>
#endif
#include <netinet/in.h>
#ifdef HAVE_ARPA_NAMESER_H
# include <arpa/nameser.h>
#endif
#include <netdb.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <errno.h>
#ifdef TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# ifdef HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <resolv.h>

extern int iruserok(u_long raddr, int superuser,
		    const char *ruser, const char *luser);

int
ruserok (const char *rhost, int superuser, const char *ruser,
	 const char *luser)
{
  struct hostent *hp;
  u_long addr;
  char **ap;

  hp = gethostbyname (rhost);
  if (hp == NULL)
    return -1;
#ifdef HAVE_STRUCT_HOSTENT_H_ADDR_LIST
  for (ap = hp->h_addr_list; *ap; ++ap)
    {
      memcpy (&addr, *ap, sizeof (addr));
      if (iruserok (addr, superuser, ruser, luser) == 0)
	return 0;
  }
#else
  memcpy(&addr, hp->h_addr, sizeof (addr));
  if (iruserok(addr, superuser, ruser, luser) == 0)
    return (0);
#endif
  return (-1);
}
