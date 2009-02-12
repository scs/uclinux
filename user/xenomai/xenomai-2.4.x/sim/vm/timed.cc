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
 * Author(s): tb
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <sys/types.h>
#include <sys/time.h>
#include <memory.h>
#include <signal.h>
#include <unistd.h>
#include "vm/manager.h"
#include "vm/monitor.h"
#include "vm/timed.h"

MvmScheduler::MvmScheduler ()

{ activeObject = NULL; }

MvmTimed *MvmScheduler::schedule ()

{
    callouts.apply(&MvmCallout::process);
    MvmTimed *t = get();

    if (!t)
	MvmManager::This->fatal("MvmScheduler::schedule() - nothing to schedule?");

    activeObject = t;
    t->activate();

    return t;
}

void MvmScheduler::addCallout (MvmCallout *callout,
			       MvmThread *boundThread)
{
    if (boundThread)
	callout->boundThread = boundThread;

    callouts.append(callout);
}

void MvmScheduler::removeCallout (MvmCallout *callout) {

    callouts.remove(callout);
}

MvmTimed *MvmScheduler::exchange ()

{
    MvmTimed *t = get();

    if (!t)
	MvmManager::This->fatal("MvmScheduler::exchange() - nothing to schedule?");

    t->setTime(MvmClock);
    prepend(activeObject);
    activeObject = t;
    t->activate();

    return t;
}

void MvmScheduler::insert (MvmTimed *to)

{
    MvmTimed *t = (MvmTimed *)first();

    while (t && t->getTime() < to->getTime())
	t = (MvmTimed *)t->next();

    while (t && t->getTime() == to->getTime() && t->prio() >= to->prio())
	t = (MvmTimed *)t->next();

    List::insert(t,to);
}

void MvmScheduler::insert (MvmTimed *t, ITime it)

{
    t->setTime(MvmClock + it);
    insert(t);
}

MvmSchedSlave::MvmSchedSlave (MvmScheduler *mt, MvmTimed *mg)

{
    master = mt;
    manager = mg;
    tNext = MAXITIME;
}

MvmTimed *MvmSchedSlave::schedule ()

{
    if (!manager)
	return 0;

    if (!_first)
	{
	activeObject = 0;
	tNext = MAXITIME;
	return 0;
	}

    activeObject = first();

    if (manager->getState() == TS_IDLE)
	{
	manager->resume();
	return activeObject;
	}

    ITime t = activeObject->getTime();

    if (t < MvmClock)
	MvmManager::This->fatal("MvmSchedSlave::schedule() - preposterous time value");

    if (t < tNext)
	{
	tNext = t;
	manager->setTime(t);

	if (manager->getState() == TS_RUNNING &&
	    !master->isActive(manager))
	    {
	    master->remove(manager);
	    master->insert(manager);
	    }
	}

    return activeObject;
}

MvmTimed::MvmTimed (const char *_name,
		    MvmScheduler *_sched,
		    int _pflags)
    : MvmObject(_name,NULL,_pflags,MvmMonitor::This)

{ sched = _sched; }

void MvmTimed::suspend ()

{
    if (PLink::isLinked())
  	sched->remove(this);

    setState(TS_IDLE);
}

void MvmTimed::resume ()

{
    sched->insert(this,ZEROTIME);
    setState(TS_RUNNING);
}

void MvmTimed::delay (ITime it)

{
    if (it < ZEROTIME)
	MvmManager::This->fatal("MvmTimed::delay() - negative time value");

    setTime(MvmClock + it);
    sched->insert(this);
}

void MvmTimed::ifInit () {

    MvmObject::ifInit();
}

MvmCallout::MvmCallout (MvmThread *_boundThread) {

    boundThread = _boundThread;
}

// MvmListener:: a callout performing multiplexed input selection for
// the simulation process. Pretend that we do not have to guarantee
// high responsiveness when reactivating threads upon input detection
// (this would not make any sense as the host's idea of time has nothing
// to do with the simulated time); thus, we can reduce the overload
// checking for available input each 8 invocations (see timed.h
// for testDropCount() implementation).

MvmListener::MvmListener (int fd) :
    MvmCallout(NULL)
{
    waitCount = 0;
    dropCount = 1;
    FD_ZERO(&waitSet);

    if (fd >= 0)
	{
	FD_SET(fd,&waitSet);
	waitCount++;
	}
}

MvmListener::MvmListener (fd_set *_waitSet) :
    MvmCallout(NULL)
{
    waitCount = 0;
    dropCount = 1;
    waitSet = *_waitSet;

    for (int n = 0; n < FD_SETSIZE; n++)
	{
	if (FD_ISSET(n,&waitSet))
	    waitCount++;
	}
}

int MvmListener::poll (fd_set *_readySet,
		       struct timeval *_tv)
{
    int nmax;

    if (!_readySet)
	{
	int nfds = waitCount;

	for (nmax = 0; nmax < FD_SETSIZE && nfds > 0; nmax++)
	    {
	    if (FD_ISSET(nmax,&waitSet))
		{
		FD_SET(nmax,&readySet);
		nfds--;
		}
	    else
		FD_CLR(nmax,&readySet);
	    }

	_readySet = &readySet;
	}
    else
	nmax = FD_SETSIZE;

    return ::select(nmax,_readySet,NULL,NULL,_tv);
}

int MvmListener::poll (fd_set *_readySet)

{
    struct timeval tv = { 0, 0 };
    return poll(_readySet,&tv);
}

void MvmListener::addFildes (int fd)

{
    if (!FD_ISSET(fd,&waitSet))
	{ FD_SET(fd,&waitSet); waitCount++; }
}

void MvmListener::removeFildes (int fd)

{
    if (FD_ISSET(fd,&waitSet))
	{ FD_CLR(fd,&waitSet); waitCount--; }
}

void MvmListener::process ()

{
    if (waitCount > 0 && boundThread && !testDropCount() && poll(NULL) > 0)
	boundThread->resume();
}
