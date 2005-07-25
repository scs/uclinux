/*
** $Id$
**
** perf.h
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker <droelker@sourcefire.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
**
**  DESCRIPTION
**    These are the basic functions and structures that are needed to call 
**    performance functions.
**
** Copyright (C) 2002 Sourcefire,Inc
** Dan Roelker
**
**
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

#ifndef _PERF_H
#define _PERF_H

#ifndef WIN32
#define UINT64 unsigned long long
#endif

#define SFPERF_BASE     1
#define SFPERF_FLOW     2
#define SFPERF_EVENT    4
#define SFPERF_BASE_MAX 8
#define SFPERF_CONSOLE  16
#define SFPERF_FILE     32
#define SFPERF_PKTCNT   64 

#include "perf-base.h"
#include "perf-flow.h"
#include "perf-event.h"

typedef struct _SFPERF {

    int    iPerfFlags;
    int    iPktCnt;

    int    sample_interval;
    int    sample_time;

    SFBASE  sfBase;
    SFFLOW  sfFlow;
    SFEVENT sfEvent;

    char    file[1024];
    FILE  * fh;
    
} SFPERF;

int sfInitPerformanceStatistics(SFPERF *sfPerf);
int sfSetPerformanceSampleTime(SFPERF *sfPerf, int iSeconds);
int sfSetPerformanceAccounting(SFPERF *sfPerf, int iReset);
int sfSetPerformanceStatistics(SFPERF *sfPerf, int iFlag);
int sfSetPerformanceStatisticsEx(SFPERF *sfPerf, int iFlag, void * param);
int sfPerformanceStats(SFPERF *sfPerf, unsigned char *pucPacket, int len,
                       int iRebuiltPkt);

#endif
