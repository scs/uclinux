/*
mediastreamer2 library - modular sound and video processing and streaming
Copyright (C) 2006  Simon MORLAT (simon.morlat@linphone.org)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*/


#ifndef MS_TICKER_H
#define MS_TICKER_H


#include "msfilter.h"
#include "mscommon.h"

struct _MSTicker
{
	ms_mutex_t lock;
	ms_cond_t cond;
	MSList *execution_list;     /* the list of source filters to be executed.*/
	ms_thread_t thread;   /* the thread ressource*/
	int interval; /* in miliseconds*/
	int exec_id;
	uint32_t ticks;
	uint64_t time;	/* a time since the start of the ticker expressed in milisec*/
	bool_t run;       /* flag to indicate whether the ticker must be run or not */
};

typedef struct _MSTicker MSTicker;
	

MSTicker *ms_ticker_new();

/**
 * function_name:ms_ticker_attach
 * @ticker:  A #MSTicker object.
 * @f:  A #MSFilter object.
 *
 * Attach a chain of filters to a ticker.
 *
 * Returns: 0 if successfull, -1 otherwise.
 */
int ms_ticker_attach(MSTicker *ticker,MSFilter *f);

/**
 * ms_ticker_detach:
 * @ticker:  A #MSTicker object.
 * @f:  A #MSFilter object.
 *
 * Dettach a chain of filters to a ticker.
 * The processing chain will no more be executed.
 *
 * Returns: 0 if successfull, -1 otherwise.
 */
int ms_ticker_detach(MSTicker *ticker,MSFilter *f);

void ms_ticker_destroy(MSTicker *ticker);


/* private functions:*/




#endif
