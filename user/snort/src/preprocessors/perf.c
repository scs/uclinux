/*
**  $Id$
**
**  perf.c
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
**    These are the basic functions that are needed to call performance
**    functions.
**
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifndef WIN32
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif /* WIN32 */

#include "perf.h"

int CheckSampleInterval(time_t curr_time, SFPERF *sfPerf);
int InitPerfStats(SFPERF *sfPerf);
int UpdatePerfStats(SFPERF *sfPerf, unsigned char *pucPacket, int len,
        int iRebuiltPkt);
int ProcessPerfStats(SFPERF *sfPerf);


int sfInitPerformanceStatistics(SFPERF *sfPerf)
{
    memset(sfPerf, 0x00, sizeof(SFPERF));
    sfSetPerformanceSampleTime(sfPerf, 0);
    sfSetPerformanceStatistics(sfPerf, 0);

    return 0;
}

int sfSetPerformanceSampleTime(SFPERF *sfPerf, int iSeconds)
{
    sfPerf->sample_time = 0;
    
    if(iSeconds < 0)
    {
        iSeconds = 0;
    }

    sfPerf->sample_interval = iSeconds;

    return 0;
}


int sfSetPerformanceAccounting(SFPERF *sfPerf, int iReset)
{
    sfPerf->sfBase.iReset = iReset;
    
    return 0;
}


int sfSetPerformanceStatistics(SFPERF *sfPerf, int iFlag)
{
    if(iFlag & SFPERF_BASE)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_BASE;
    }

#ifndef LINUX_SMP

    if(iFlag & SFPERF_BASE_MAX)
    {
        sfPerf->sfBase.iFlags |= MAX_PERF_STATS;
    }

#endif

    if(iFlag & SFPERF_FLOW)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_FLOW;
    }
    if(iFlag & SFPERF_EVENT)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_EVENT;
    }
    if(iFlag & SFPERF_CONSOLE)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_CONSOLE;
    }
    
    return 0;
}
int sfSetPerformanceStatisticsEx(SFPERF *sfPerf, int iFlag, void * p)
{
#ifndef WIN32    
    mode_t old_umask;
#endif 
    
    if(iFlag & SFPERF_FILE)
    {
        sfPerf->iPerfFlags = sfPerf->iPerfFlags | SFPERF_FILE;
        
	    strncpy( sfPerf->file, p, sizeof(sfPerf->file)-1 );
        sfPerf->file[sizeof(sfPerf->file)-1] = 0x00;

        /* this file needs to be readable by everyone */
#ifndef WIN32
        old_umask = umask(022);
#endif         

	sfPerf->fh = fopen(sfPerf->file,"at");

#ifndef WIN32
        umask(old_umask);
#endif
        
	if( !sfPerf->fh ) return -1;
    }
    else if(iFlag & SFPERF_PKTCNT)
    {
        sfPerf->iPktCnt = *(int*)p;
    }
    return 0;
}


int sfPerformanceStats(SFPERF *sfPerf, unsigned char *pucPacket, int len,
                       int iRebuiltPkt)
{
    static unsigned int cnt=0;

    if( cnt==0 || cnt >= sfPerf->iPktCnt )
    {
       cnt=1;
       CheckSampleInterval(time(NULL), sfPerf);
    }

    cnt++;

    UpdatePerfStats(sfPerf, pucPacket, len, iRebuiltPkt);

    return 0;
}

int CheckSampleInterval(time_t curr_time, SFPERF *sfPerf)
{
    time_t prev_time = sfPerf->sample_time;

    /*
    *  This is for when sfBasePerformance is
    *  starting up.
    */
    if(prev_time == 0)
    {
        InitPerfStats(sfPerf);
    }
    else if((curr_time - prev_time) >= sfPerf->sample_interval)
    {
        ProcessPerfStats(sfPerf);
        InitPerfStats(sfPerf);
    }

    return 0;
}

int InitPerfStats(SFPERF *sfPerf)
{
    static int first = 1;
    /*
    *  Reset sample time for next sampling
    */
    sfPerf->sample_time = time(NULL);

    if(sfPerf->iPerfFlags & SFPERF_BASE)
    {  
        if(InitBaseStats(&(sfPerf->sfBase)))
            return -1;
    }
    if(sfPerf->iPerfFlags & SFPERF_FLOW)
    {  
        if(first) InitFlowStats(&(sfPerf->sfFlow));
        first = 0;
    }
    if(sfPerf->iPerfFlags & SFPERF_EVENT)
    {  
        InitEventStats(&(sfPerf->sfEvent));
    }

    return 0;
}

int UpdatePerfStats(SFPERF *sfPerf, unsigned char *pucPacket, int len,
                    int iRebuiltPkt)
{
    if(sfPerf->iPerfFlags & SFPERF_BASE)
    {
        UpdateBaseStats(&(sfPerf->sfBase), len, iRebuiltPkt);
    }
    if(sfPerf->iPerfFlags & SFPERF_FLOW)
    {
        UpdateFlowStats(&(sfPerf->sfFlow), pucPacket, len, iRebuiltPkt);
    }

    return 0;
}

int ProcessPerfStats(SFPERF *sfPerf)
{
    if(sfPerf->iPerfFlags & SFPERF_BASE)
    {
	/* Allow this to go out to console and/or a file */
        ProcessBaseStats(&(sfPerf->sfBase),
			 sfPerf->iPerfFlags & SFPERF_CONSOLE,
			 sfPerf->iPerfFlags & SFPERF_FILE,
			 sfPerf->fh );
    }
    
    /* Always goes to the console */
    if(sfPerf->iPerfFlags & SFPERF_FLOW)
    {
        if( sfPerf->iPerfFlags & SFPERF_CONSOLE )
            ProcessFlowStats(&(sfPerf->sfFlow));
    }
   
    if(sfPerf->iPerfFlags & SFPERF_EVENT)
    {
        if( sfPerf->iPerfFlags & SFPERF_CONSOLE )
            ProcessEventStats(&(sfPerf->sfEvent));
    }

    return 0;
}
    
