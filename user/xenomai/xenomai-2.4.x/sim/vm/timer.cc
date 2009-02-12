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
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include "vm/timer.h"
#include "vm/manager.h"

int MvmTimer::globalTrace = 0;

MvmTimerManager *MvmTimerManager::This = NULL;

MvmSchedSlave MvmTimer::timerChain;

MvmTimerManager::MvmTimerManager () :
    MvmThread("Timer manager",MVM_IFACE_HIDDEN)
{
    This = this;

#ifdef CONFIG_XENO_MVM_DEBUG
    if (MvmTimer::globalTrace > 1)
	MvmDebug << "TIMER MANAGER created\n";
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmTimerManager::body ()

{
    ITime tNext;

    for(;;)
	{
	MvmTimer *so = (MvmTimer *)MvmTimer::timerChain.first();

	if (!so)
	    {
#ifdef CONFIG_XENO_MVM_DEBUG
	    if (MvmTimer::globalTrace > 0)
		MvmDebug << MvmClock << " TIMER MANAGER idle\n";
#endif // CONFIG_XENO_MVM_DEBUG

	    suspend();

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (MvmTimer::globalTrace > 0)
		MvmDebug << MvmClock << " TIMER MANAGER resumed\n";
#endif // CONFIG_XENO_MVM_DEBUG

	    continue;
	    }

	tNext = so->getTime();

	if (tNext < MvmClock)
	    MvmManager::This->fatal("MvmTimerManager::body() - preposterous time value");

	if (tNext == MvmClock)
	    {
	    so = (MvmTimer *)MvmTimer::timerChain.get();
	    so->activate();
	    continue;
	    }

	schedTime = tNext;
	MvmTimer::timerChain.setTNext(tNext);

#ifdef CONFIG_XENO_MVM_DEBUG
	if (MvmTimer::globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " TIMER MANAGER scheduled at "
		     << tNext << " for " << so << '\n';

	    if (MvmTimer::globalTrace > 1)
		printTimerChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG

	delay(tNext - MvmClock);
	}
}

MvmTimer::MvmTimer (const char *_name,
		    ITime dt,
		    MvmThread *th,
		    int _flags) :
    MvmTimed(_name,&timerChain,_flags)
{
    if (dt < ZEROTIME)
	return;

    waitingThread = th;
    schedTime = MvmClock + dt;
    sched->insert(this);
    setState(ARMED);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	{
	MvmDebug << "TIMER " << this << " created and scheduled at "
		 << schedTime << '\n';

	if (globalTrace > 1)
	    printTimerChain();
	}
#endif // CONFIG_XENO_MVM_DEBUG

    sched->schedule();
}

MvmTimer::MvmTimer (const char *_name,
		    MvmThread *_th,
		    int _pflags) :
    MvmTimed(_name,&timerChain,_pflags)
{
    waitingThread = _th;
    setState(TS_IDLE);
}

MvmTimer::MvmTimer (const char *_name,
		    int _pflags) :
    MvmTimed(_name,&timerChain,_pflags),
    waitingThread(NULL)

{ setState(TS_IDLE); }

MvmTimer::~MvmTimer()

{
    if (state == ARMED)
	sched->remove(this);

    setState(DEAD);
}

void MvmTimer::activate()

{
    // this timer could be destroyed as a result of calling
    // the timeout() method -- thus, perform all required
    // actions on this object *before* invoking the expiration
    // callout.
    
    setState(EXPIRED);
    
    if (waitingThread)
	{
#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    MvmDebug << MvmClock << " TIMER "
		     <<	ifGetName() << " " << this
		     << " expired for thread "
		     << waitingThread->ifGetName() << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	waitingThread->timeout(this);
	}
#ifdef CONFIG_XENO_MVM_DEBUG
    else if (globalTrace > 0)
	MvmDebug << MvmClock << " TIMER "
		 << ifGetName() << " " << this << " expired\n";
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmTimer::set (ITime dt)

{
    if (dt < ZEROTIME)
	return;

    if (state == ARMED)
	sched->remove(this);

    schedTime = MvmClock + dt;
    sched->insert(this);
    setState(ARMED);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	{
	MvmDebug << "TIMER " << ifGetName() << " " << this
		 << " scheduled at " << schedTime << '\n';

	if (globalTrace > 1)
	    printTimerChain();
	}
#endif // CONFIG_XENO_MVM_DEBUG

    sched->schedule();
}

void MvmTimer::reset ()

{
    if (state == ARMED)
	{
	sched->remove(this);
	setState(DISARMED);
	}
    else
	setState(TS_IDLE);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0) 
	MvmDebug << MvmClock << " TIMER " << ifGetName()
		 << " " << this << " reset to state " << state << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmTimer::print(MvmStream& ios)

{
    ios << "TIMER " << ifGetName() << " " << this << " scheduled at "
	<< getTime() << " (pri=" << getPrio() << ") ";

    if (waitingThread)
	ios << " for thread " << waitingThread->ifGetName();

    ios << '\n';
}

void MvmTimer::ifInit()

{
    const char *stateArray[5];
    stateArray[0] = "DEAD";
    stateArray[1] = "IDLE";
    stateArray[2] = "EXPIRED";
    stateArray[3] = "DISARMD";
    stateArray[4] = "ARMED";

    defineStates(sizeof(stateArray) / sizeof(stateArray[0]),stateArray);
    MvmTimed::ifInit();
}

int MvmTimer::stateIndex(int s)

{
    if (s < 2)
	return 0;

    return s - 7;
}

void MvmTimer::setGlobalTrace (int traceLevel)

{ globalTrace = traceLevel; }

void printTimerChain()

{
    MvmDebug << "TIMER CHAIN / " << MvmTimer::timerChain.getCount()
	     << " linked\n";

    MvmTimer* tim = (MvmTimer*)MvmTimer::timerChain.first();

    while (tim)
	{
	MvmDebug << "     ";
	tim->print(MvmDebug);
	tim = (MvmTimer*)tim->next();
	}

    MvmDebug.flush();
}
