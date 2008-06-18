/*
*
*  A2DPD - Bluetooth A2DP daemon for Linux
*
*  Copyright (C) 2006  Frédéric DALLEAU <frederic.dalleau@palmsource.com>
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2 of the License, or
*  (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; if not, write to the Free Software
*  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#define MAXTOTALCOUNT (700000*1000)

#include "a2dp_timer.h"
#include <time.h>
#include <unistd.h>
#include <syslog.h>

void sleeptodate(LPTIMERINFO lpTimerInfo, struct timeval *date, int predelay)
{
	struct timeval now;
	struct timeval resolutionval = { 0, predelay + (int) (lpTimerInfo->timer_resolution.tv_nsec / 1000) };

	// See if we have time to wait
	timeradd(&lpTimerInfo->timeofday, &resolutionval, &now);
	if (timercmp(date, &now, >)) {
		// Synchronise with usleep 20 ms cycle
		usleep(1);
		// See if we must wait again
		gettimeofday(&now, NULL);
		timeradd(&now, &resolutionval, &now);
		if (timercmp(date, &now, >)) {
			struct timeval interval = { 0, 0 };
			timersub(date, &now, &interval);
			// sleep
			usleep(interval.tv_usec);
		}
	} else {
		// We're late, do not wait
	}
}

// This version uses values never reset
void keepfreqtotal(LPTIMERINFO lpTimerInfo, int predelay)
{
	struct timeval playtime, theoricaldate;

	//FIXME It is not necessary to use unsigned long if we reset periodically the value of itotalcount (see MAXTOTALCOUNT)
	// if MAXTOTALCOUNT < 700000, we will fit in signed 32bit and reset no more than every 36 mins.
	// Resetting that value might cause a small sound break.
	// Setting MAXTOTALCOUNT to lpTimerInfo->fps will reset every second (useful for testing purposes)
	playtime.tv_sec = ((unsigned long) ((1.0 * (lpTimerInfo->itotalcount) / lpTimerInfo->fps)));
	playtime.tv_usec = ((unsigned long) ((1.0 * 1000.0 * 1000.0 / lpTimerInfo->fps) * (lpTimerInfo->itotalcount))) % 1000000;
	timeradd(&lpTimerInfo->totalcounter, &playtime, &theoricaldate);

	// If calculated date is higher than current date
	if (timercmp(&theoricaldate, &lpTimerInfo->timeofday, >)) {
		sleeptodate(lpTimerInfo, &theoricaldate, predelay);
	}
}

void a2dp_timer_notifyframe(LPTIMERINFO lpTimerInfo)
{
	struct timeval lastframe_interval = { 0, 0 };
	struct timeval maxallowed_interval = { 0, 200 * 1000 };
	gettimeofday(&lpTimerInfo->timeofday, NULL);
	timersub(&lpTimerInfo->timeofday, &lpTimerInfo->lastframe, &lastframe_interval);
	// Previous frames older than 1 second, reset counters
	if (timercmp(&lastframe_interval, &maxallowed_interval, >)) {
		// We must reset the total counter because else, we will believe the date is late
		gettimeofday(&lpTimerInfo->totalcounter, NULL);
		lpTimerInfo->itotalcount = 0;
	}
	gettimeofday(&lpTimerInfo->lastframe, NULL);
}

void a2dp_timer_sleep(LPTIMERINFO lpTimerInfo, int predelay)
{
	gettimeofday(&lpTimerInfo->timeofday, NULL);

	// Initialize timers
	if (lpTimerInfo->staticcounter.tv_sec == 0)
		gettimeofday(&lpTimerInfo->staticcounter, NULL);
	if (lpTimerInfo->totalcounter.tv_sec == 0 || lpTimerInfo->itotalcount > MAXTOTALCOUNT) {
		gettimeofday(&lpTimerInfo->totalcounter, NULL);
		lpTimerInfo->itotalcount = 0;
	}
	if (lpTimerInfo->timer_resolution.tv_nsec == 0)
		clock_getres(CLOCK_REALTIME, &lpTimerInfo->timer_resolution);

	// Duration since last call
	timersub(&lpTimerInfo->timeofday, &lpTimerInfo->staticcounter, &lpTimerInfo->duration);

	// Display data once per second
	if (lpTimerInfo->duration.tv_sec > 0) {
		// Reset all statistics
		gettimeofday(&lpTimerInfo->staticcounter, NULL);
		lpTimerInfo->display = lpTimerInfo->icount;
		lpTimerInfo->icount = 0;
	} else {
		lpTimerInfo->display = 0;
	}

	keepfreqtotal(lpTimerInfo, predelay);

	lpTimerInfo->icount++;
	lpTimerInfo->itotalcount++;
}
