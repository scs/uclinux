
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

/* $Id: output.c,v 1.5 2003/04/02 13:06:52 renaud Exp $ */

#include "output.h"
#include "osscan.h"

extern struct ops o;
static char *logtypes[LOG_TYPES] = LOG_NAMES;

/* Write some information (printf style args) to the given log stream(s) */
void log_write(int logt, const char *fmt, ...)
{
#if 0
	va_list ap;
	int i, l = logt, skid = 1;
	char buffer[1000];

	va_start(ap, fmt);
	if (l & LOG_STDOUT) {
		vfprintf(o.nmap_stdout, fmt, ap);
		l -= LOG_STDOUT;
	}
	if (l & LOG_SKID_NOXLT) {
		skid = 0;
		l -= LOG_SKID_NOXLT;
		l |= LOG_SKID;
	}
	if (l < 0 || l > LOG_MASK)
		return;
	for (i = 0; l; l >>= 1, i++) {
		if (!o.logfd[i] || !(l & 1))
			continue;
		vsnprintf(buffer, sizeof(buffer) - 1, fmt, ap);
		if (skid && ((1 << i) & LOG_SKID))
			skid_output(buffer);
		fwrite(buffer, 1, strlen(buffer), o.logfd[i]);
	}
	va_end(ap);
#endif	
}

/* Close the given log stream(s) */
void log_close(int logt)
{
	int i;
	if (logt < 0 || logt > LOG_MASK)
		return;
	for (i = 0; logt; logt >>= 1, i++)
		if (o.logfd[i] && (logt & 1))
			fclose(o.logfd[i]);
}

/* Flush the given log stream(s).  In other words, all buffered output
   is written to the log immediately */
void log_flush(int logt)
{
	int i;

	if (logt & LOG_STDOUT) {
		fflush(o.nmap_stdout);
		logt -= LOG_STDOUT;
	}
	if (logt & LOG_SKID_NOXLT)
		fatal("You are not allowed to log_flush() with LOG_SKID_NOXLT");

	if (logt < 0 || logt > LOG_MASK)
		return;

	for (i = 0; logt; logt >>= 1, i++) {
		if (!o.logfd[i] || !(logt & 1))
			continue;
		fflush(o.logfd[i]);
	}

}

/* Flush every single log stream -- all buffered output is written to the
   corresponding logs immediately */
void log_flush_all()
{
	int fileno;

	for (fileno = 0; fileno < LOG_TYPES; fileno++) {
		if (o.logfd[fileno])
			fflush(o.logfd[fileno]);
	}
	fflush(stdout);
	fflush(stderr);
}

/* Open a log descriptor of the type given to the filename given.  If 
   append is nonzero, the file will be appended instead of clobbered if
   it already exists.  If the file does not exist, it will be created */
int log_open(int logt, int append, char *filename)
{
	int i = 0;
	if (logt <= 0 || logt > LOG_MASK)
		return -1;
	while ((logt & 1) == 0) {
		i++;
		logt >>= 1;
	}
	if (o.logfd[i])
		fatal("Only one %s output filename allowed", logtypes[i]);
	if (*filename == '-' && *(filename + 1) == '\0') {
		o.logfd[i] = stdout;
		o.nmap_stdout = fopen("/dev/null", "w");
		if (!o.nmap_stdout)
			fatal("Could not assign /dev/null to stdout for writing");
	} else {
		if (o.append_output)
			o.logfd[i] = fopen(filename, "a");
		else
			o.logfd[i] = fopen(filename, "w");
		if (!o.logfd[i])
			fatal("Failed to open %s output file %s for writing", logtypes[i], filename);
	}
	return 1;
}

/* Used in creating skript kiddie style output.  |<-R4d! */
void skid_output(char *s)
{
	int i;
	for (i = 0; s[i]; i++)
		if (rand() % 2 == 0)
			/* Substitutions commented out are not known to me, but maybe look nice */
			switch (s[i]) {
			case 'A':
				s[i] = '4';
				break;
				/*    case 'B': s[i]='8'; break;
				   case 'b': s[i]='6'; break;
				   case 'c': s[i]='k'; break;
				   case 'C': s[i]='K'; break; */
			case 'e':
			case 'E':
				s[i] = '3';
				break;
			case 'i':
			case 'I':
				s[i] = "!|1"[rand() % 3];
				break;
				/*      case 'k': s[i]='c'; break;
				   case 'K': s[i]='C'; break; */
			case 'o':
			case 'O':
				s[i] = '0';
				break;
			case 's':
			case 'S':
				if (s[i + 1] && !isalnum((int) s[i + 1]))
					s[i] = 'z';
				else
					s[i] = '$';
				break;
			case 'z':
				s[i] = 's';
				break;
			case 'Z':
				s[i] = 'S';
				break;
		} else {
			if (s[i] >= 'A' && s[i] <= 'Z' && (rand() % 3 == 0))
				s[i] += 'a' - 'A';
			else if (s[i] >= 'a' && s[i] <= 'z' && (rand() % 3 == 0))
				s[i] -= 'a' - 'A';
		}
}


/* Prints the formatted OS Scan output to stdout, logfiles, etc (but only
   if an OS Scan was performed */
void printosscanoutput(struct hoststruct *currenths, struct arglist * desc)
{
	char report[1024];
	assert(currenths->osscan_performed);
	
	if(currenths->seq.seqclass == SEQ_CONSTANT)plug_set_key(desc, "Host/tcpseq", ARG_STRING, "constant");
	else if(currenths->seq.seqclass == SEQ_64K)plug_set_key(desc, "Host/tcpseq", ARG_STRING, "64k");
	else if(currenths->seq.seqclass == SEQ_i800)plug_set_key(desc, "Host/tcpseq", ARG_STRING, "i800");
	else if(currenths->seq.seqclass == SEQ_TD)plug_set_key(desc, "Host/tcpseq", ARG_STRING, "time_dependant");
	else if(currenths->seq.seqclass == SEQ_RI)plug_set_key(desc, "Host/tcpseq", ARG_STRING, "random");
	else if(currenths->seq.seqclass == SEQ_TR)plug_set_key(desc, "Host/tcpseq", ARG_STRING, "truly_random");
	
	snprintf(report, sizeof(report), "Remote OS guess : %s\n", currenths->FPR.prints[0]->OS_name);
	plug_set_key(desc, "Host/OS", ARG_STRING, currenths->FPR.prints[0]->OS_name);
	post_note(desc, 0, report);
	/*
	fprintf(stdout, "Scanned: %s\nRemote OS guess: %s\n", inet_ntoa(currenths->host), currenths->FPR.prints[0]->OS_name);
	*/
}
