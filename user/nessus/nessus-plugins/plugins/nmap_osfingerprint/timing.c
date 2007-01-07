
/***********************************************************************
 * timing.c -- Functions related to computing scan timing (such as     *
 * keeping track of and adjusting smoothed round trip times,           *
 * statistical deviations, timeout values, etc.  Various user options  *
 * (such as the timing policy (-T)) also play a role in these          *
 * calculations                                                        *
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

/* $Id: timing.c,v 1.1 2003/02/24 14:46:20 renaud Exp $ */

#include "timing.h"

extern struct ops o;

/* Sleeps if necessary to ensure that it isn't called twice withen less
   time than o.send_delay.  If it is passed a non-null tv, the POST-SLEEP
   time is recorded in it */
void enforce_scan_delay(struct timeval *tv)
{
	static int init = -1;
	static struct timeval lastcall;
	struct timeval now;
	int time_diff;

	if (!o.scan_delay) {
		if (tv)
			gettimeofday(tv, NULL);
		return;
	}

	if (init == -1) {
		gettimeofday(&lastcall, NULL);
		init = 0;
		if (tv)
			memcpy(tv, &lastcall, sizeof(struct timeval));
		return;
	}

	gettimeofday(&now, NULL);
	time_diff = TIMEVAL_MSEC_SUBTRACT(now, lastcall);
	if (time_diff < o.scan_delay) {
		if (o.debugging > 1) {
			printf("Sleeping for %d milliseconds in enforce_scan_delay()\n", o.scan_delay - time_diff);
		}
		usleep((o.scan_delay - time_diff) * 1000);
		gettimeofday(&lastcall, NULL);
	} else
		memcpy(&lastcall, &now, sizeof(struct timeval));
	if (tv) {
		memcpy(tv, &lastcall, sizeof(struct timeval));
	}

	return;
}
