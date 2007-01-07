
/***********************************************************************
 * error.c -- Some simple error handling routines.                     *
 *                                                                     *
 ***********************************************************************
 *  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  *
 *  program is free software; you can redistribute it and/or modify    *
 *  it under the terms of the GNU General Public License as published  *
 *  by the Free Software Foundation; Version 2.  This guarantees your  *
 *  right to use, modify, and redistribute this software under certain *
 *  conditions.  If this license is unacceptable to you, we may be     *
 *  willing to sell alternative licenses (contact sales@insecure.com). *
 *                                                                     *
 *  If you received these files with a written license agreement       *
 *  stating terms other than the (GPL) terms above, then that          *
 *  alternative license agreement takes precendence over this comment. *
 *                                                                     *
 *  Source is provided to this software because we believe users have  *
 *  a right to know exactly what a program is going to do before they  *
 *  run it.  This also allows you to audit the software for security   *
 *  holes (none have been found so far).                               *
 *                                                                     *
 *  Source code also allows you to port Nmap to new platforms, fix     *
 *  bugs, and add new features.  You are highly encouraged to send     *
 *  your changes to fyodor@insecure.org for possible incorporation     *
 *  into the main distribution.  By sending these changes to Fyodor or *
 *  one the insecure.org development mailing lists, it is assumed that *
 *  you are offering Fyodor the unlimited, non-exclusive right to      *
 *  reuse, modify, and relicense the code.  This is important because  *
 *  the inability to relicense code has caused devastating problems    *
 *  for other Free Software projects (such as KDE and NASM).  Nmap     *
 *  will always be available Open Source.  If you wish to specify      *
 *  special license conditions of your contributions, just say so      *
 *  when you send them.                                                *
 *                                                                     *
 *  This program is distributed in the hope that it will be useful,    *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  *
 *  General Public License for more details (                          *
 *  http://www.gnu.org/copyleft/gpl.html ).                            *
 *                                                                     *
 ***********************************************************************/

/* $Id: nmap_error.c,v 1.1 2003/02/24 14:46:18 renaud Exp $ */

#include "nmap_error.h"

#ifdef WIN32
#include <windows.h>
#endif				/* WIN32 */

void fatal(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fflush(stdout);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\nQUITTING!\n");
	va_end(ap);
	exit(1);
}

void error(char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	fflush(stdout);
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
	va_end(ap);
	return;
}

void pfatal(char *err, ...)
{
#ifdef WIN32
	int lasterror = 0;
	char *errstr = NULL;
#endif
	va_list ap;
	va_start(ap, err);
	fflush(stdout);
	vfprintf(stderr, err, ap);
	va_end(ap);
#ifdef WIN32
	lasterror = GetLastError();
	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, lasterror, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) & errstr, 0, NULL);
	fprintf(stderr, ": %s (%d)\n", errstr, lasterror);
	HeapFree(GetProcessHeap(), 0, errstr);
#else
	perror(" ");
#endif				/* WIN32 perror() compatability switch */
	fflush(stderr);
	exit(1);
}

void gh_perror(char *err, ...)
{
	va_list ap;
	va_start(ap, err);
	fflush(stdout);
	vfprintf(stderr, err, ap);
	va_end(ap);
	perror(" ");
	fflush(stderr);
	return;
}
