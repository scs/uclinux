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


#ifndef __A2DP_TIMER_H__
#define __A2DP_TIMER_H__

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <sys/time.h>

#define A2DPTIMERPREDELAY       2000

// 
typedef struct 
{
        float fps;                              // Number of frames per second to achieve

        struct timespec timer_resolution;       // Resolution of the timer in nanoseconds
        struct timeval timeofday;               // Date of this frame
        struct timeval lastframe;               // Date of last frame
        struct timeval staticcounter;           // Date of frame 0 (icount=0) reseted each second
        struct timeval totalcounter;            // Date of frame 0 (itotalcount=0)
        struct timeval duration;                // Time since last frame
        int icount;                             // Count of frames for this second
        int itotalcount;                        // Count of frames since startup
        int display;                            // non zéro if a second has just ended
} TIMERINFO, *LPTIMERINFO;

// Use notify frame when some data is sent
void a2dp_timer_notifyframe(LPTIMERINFO lpTimerInfo);

// Use sleep in your upper level loop
// When no calls to notify_frame are done, internal statistics counter will be reseted
void a2dp_timer_sleep(LPTIMERINFO lpTimerInfo, int predelay);

#endif
