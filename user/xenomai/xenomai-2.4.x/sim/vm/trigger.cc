/*
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 1997-2000 Realiant Systems.  All rights reserved.
 * Copyright (C) 2001,2002 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * The original code is FROGS - A Free Object-oriented General-purpose
 * Simulator, released November 10, 1999. The initial developer of the
 * original code is Realiant Systems (http://www.realiant.com).
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <stdio.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <time.h>
#include "vmutils/string++.h"
#include "vm/source.h"
#include "vm/trigger.h"

// MvmTrigger: a base object for defining event sources.
// A trigger calls a user-defined handler following a
// selectable event generation law.

MvmTrigger::MvmTrigger (void (*_handler)(void *),
			void *_clientData,
			unsigned _stacksz) :
    MvmThread("Trigger",MVM_IFACE_HIDDEN,_stacksz)
{
    source = NULL;
    handler = _handler;
    clientData = _clientData;
}

MvmTrigger::~MvmTrigger ()

{
    wakeupQ.forget(this);

    if (source)
	delete source;
}

void MvmTrigger::body ()

{
    if (!handler) // should never get there...
	suspend();
    
    for (;;)
	{
	delete wakeupQ.get();
	handler(clientData);
	}
}

// MvmUniTrigger: an event source based on a uniform
// numerical generation law.

MvmUniTrigger::MvmUniTrigger (void (*_handler)(void *),
			      const char *_paramString,
			      void *_clientData,
			      int _priority,
			      unsigned _stacksz) :
    MvmTrigger(_handler,_clientData,_stacksz)
{
    ITime stime, etime, l, r(MAXITIME);
 
    if (!decodeTimeBounds(_paramString,stime,etime,l,r))
	return;

    if (r == MAXITIME)
	{
	r = l * 2.0;
	l = ZEROTIME;
	}

    source = new MvmUniSource(l,
			      r,
			      new MvmInfo,
			      &wakeupQ,
			      1,
			      stime,
			      etime,
			      _priority);
}

// MvmExpTrigger: an event source based on an exponential
// numerical generation law.

MvmExpTrigger::MvmExpTrigger (void (*_handler)(void *),
			      const char *_paramString,
			      void *_clientData,
			      int _priority,
			      unsigned _stacksz) :
    MvmTrigger(_handler,_clientData,_stacksz)
{
    ITime stime, etime, mean, fake(MAXITIME);

    if (!decodeTimeBounds(_paramString,stime,etime,mean,fake))
	return;

    source = new MvmExpSource(mean,
			      new MvmInfo,
			      &wakeupQ,
			      1,
			      stime,
			      etime,
			      _priority);
}

// MvmPerTrigger: an event source based on a periodical
// numerical generation law.

MvmPerTrigger::MvmPerTrigger (void (*_handler)(void *),
			      const char *_paramString,
			      void *_clientData,
			      int _priority,
			      unsigned _stacksz) :
    MvmTrigger(_handler,_clientData,_stacksz)
{
    ITime stime, etime, period, fake(MAXITIME);

    if (!decodeTimeBounds(_paramString,stime,etime,period,fake))
	return;

    if (stime == ZEROTIME)
	// When it does not specify a start time, a user usually expects
	// the first call to the handler to occur at NOW + period. Prevent
	// the source from drawing start time at random, which would
	// be quite perturbating from the user's standpoint.
	stime = MvmClock + period;

    source = new MvmPerSource(period,
			      new MvmInfo,
			      &wakeupQ,
			      1,
			      stime,
			      etime,
			      _priority);
}

// MvmFileTrigger: an event source based on file information.

MvmFileTrigger::MvmFileTrigger (void (*_handler)(void *),
				const char *_fileName,
				void *_clientData,
				int _priority,
				unsigned _stacksz) :
    MvmTrigger(_handler,_clientData,_stacksz) {

    source = new MvmFileSource(CString(_fileName).expand(),
			       new MvmInfo,
			       &wakeupQ,
			       1,
			       _priority);
}

// MvmTimerTrigger: an event source based on a (single-shot)
// timer information.

MvmTimerTrigger::MvmTimerTrigger (void (*_handler)(void *),
				  const char *_paramString,
				  void *_clientData,
				  unsigned _stacksz) :
    MvmTrigger(_handler,_clientData,_stacksz),
    triggerDate(NEGTIME) {

    setTimer(_paramString);
}

void MvmTimerTrigger::body ()

{
    for (;;)
	{
	if (handler && triggerDate >= MvmClock)
	    {
	    delay(triggerDate - MvmClock);

	    if (MvmClock < triggerDate)
		// This may happen if the trigger is reprogrammed on
		// the fly in order to elapse before the previous
		// timeout date.
		continue;

	    handler(clientData);
	    }
	
	suspend();
	}
}

int MvmTimerTrigger::setTimer (ITime _date)

{
    triggerDate = _date;
    resume();
    return 0;
}

int MvmTimerTrigger::setTimer (const char *_date)

{
    ITime stime, etime;

    if (!decodeTimeRange(_date,stime,etime))
	{
	triggerDate = NEGTIME;
	return -1;
	}

    triggerDate = stime;
    resume();

    return 0;
}

int MvmTimerTrigger::isValid () const {

    return triggerDate >= ZEROTIME;
}
