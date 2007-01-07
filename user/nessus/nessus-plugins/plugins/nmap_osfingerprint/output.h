
/***********************************************************************
 * output.c -- Handles the Nmap output system.  This currently         *
 * involves console-style human readable output, XML output,           *
 * Script |<iddi3 output, and the legacy greppable output (used to be  *
 * called "machine readable").  I expect that future output forms      *
 * (such as HTML) may be created by a different program, library, or   *
 * script using the XML output.                                        *
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

/* $Id: output.h,v 1.1 2003/02/24 14:46:19 renaud Exp $ */

#ifndef OUTPUT_H
#define OUTPUT_H

#define LOG_TYPES 5
#define LOG_MASK 31
#define LOG_NORMAL 1
#define LOG_MACHINE 2
#define LOG_HTML 4
#define LOG_SKID 8
#define LOG_XML 16
#define LOG_STDOUT 1024
#define LOG_SKID_NOXLT 2048

#define LOG_NAMES {"normal", "machine", "HTML", "$Cr!pT |<!dd!3", "XML"}

#include "nmap.h"
#include "portlist.h"
#include "tcpip.h"
#include "global_structures.h"

/* Write some information (printf style args) to the given log stream(s) */
void log_write(int logt, const char *fmt, ...);

/* Close the given log stream(s) */
void log_close(int logt);

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt);

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void log_flush_all();

/* Open a log descriptor of the type given to the filename given.  If
   append is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int log_open(int logt, int append, char *filename);

/* Used in creating skript kiddie style output.  |<-R4d! */
void skid_output(char *s);


/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed */
void printosscanoutput(struct hoststruct *currenths, struct arglist *);

#endif				/* OUTPUT_H */
