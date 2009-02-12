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
 * Author(s): gt
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include "vm/resource.h"
#include "vm/manager.h"

int MvmResource::globalTrace = 0;

MvmResource::MvmResource (const char *_name,
			  unsigned _initCount,
			  InsertMode _pMode,
			  InsertMode _hMode,
			  int _fPreempt) :
    MvmSynchro(_name),
    owners(_hMode),
    fPreempt(_fPreempt)
{
    pendList.setMode(_pMode);
    oCount = _initCount;
    setState(oCount ? ON : OFF);

#ifdef CONFIG_XENO_MVM_DEBUG
    if(globalTrace > 1)
	MvmDebug << "RESOURCE " << ifGetName() << " " << this
		 << " created with " << _initCount << " units\n";
#endif // CONFIG_XENO_MVM_DEBUG
}

MvmResource::~MvmResource () {}

void MvmResource::post ()

{
    if (fPreempt)
	owners.remove(MvmThread::currentThread);

    switch (state)
	{
	case OFF:

	    setState(ON);

	case ON:

	    oCount++;

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		MvmDebug << MvmClock << " RESOURCE "
			 << ifGetName() << " " << this << " posted by "
			 << MvmThread::currentThread->ifGetName()
			 <<	" / " << oCount	<< " posted\n";
#endif // CONFIG_XENO_MVM_DEBUG
	    break;

	case PENDED:

	    {
	    MvmThread *thread = pendList.get();

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug << MvmClock << " RESOURCE "
			 << ifGetName() << " " << this << " posted to pending "
			 << thread->ifGetName() << " / " << pendList.getCount()
			 << " pending\n";

		if (globalTrace > 1)
		    print(MvmDebug);
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    if (pendList.getCount() == 0)
		setState(OFF);

	    if (fPreempt)
		owners.put(thread);

	    thread->resume(this);
	    break;
	    }

	default:

	    MvmManager::This->fatal("MvmResource::post() - invalid resource state");
	}

    if (postHook)
	postHook->fire(0);
}

void MvmResource::pend ()

{
    if (fPreempt)
	owners.remove(MvmThread::currentThread);    

    switch (state)
	{
	case ON:

	    if (fPreempt)
		owners.put(MvmThread::currentThread);    

	    if (--oCount == 0)
		setState(OFF);

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		MvmDebug << MvmClock << " RESOURCE "
			 << ifGetName() << " " << this << " pended by "
			 << MvmThread::currentThread->ifGetName() << " / "
			 << oCount << " posted\n";
#endif // CONFIG_XENO_MVM_DEBUG
	    break;

	case OFF:

	    setState(PENDED);

	case PENDED:

	    {
	    MvmThread *thread = MvmThread::currentThread;
		
	    if (fPreempt)
		{
		owners.insert(thread,thread->prio());
		thread = owners.get();
		}

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug << MvmClock << " RESOURCE " <<
		    ifGetName() << " " << this << " pended by "
			 << thread->ifGetName() << " / "
			 <<	pendList.getCount() << " pending\n";

		if (globalTrace > 1)
		    print(MvmDebug);
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    pendList.insert(thread,thread->prio());

	    if (thread == MvmThread::currentThread)
		thread->pend(this);
	    else
		thread->preempt();
	    }

	    break;

	default:

	    MvmManager::This->fatal("MvmResource::pend() - invalid resource state");
	}
  
    if (pendHook)
	pendHook->fire(0);
}

void MvmResource::print (MvmStream& ios)

{
    ios	<< "RESOURCE " << ifGetName() << " " << this
	<< " state " << (int) state << " / " << getOCount()
	<< " posted, " << pendList.getCount() << " pending\n";

    if (state == PENDED)
	{
	MvmThreadIterator it(pendList);
	MvmThread *thread;

	while ((thread = it.next()) != NULL)
	    {
	    ios << "     ";
	    thread->print(ios);
	    }
	}

    ios.flush();
}

MvmStatObj *MvmResource::setStatistics (MvmStatisticType type)

{
    if (type == STAT_MEAN)
	{
	char buf[64];
	sprintf(buf,"RESOURCE %p MEAN",this);

	MvmIntegrator* ti = new MvmIntegrator(buf,
					      MvmManager::warmupTime,
					      MvmManager::finishTime,
					      MvmManager::samplingPeriod);
	ti->add(oCount);
	addPendHook(new MvmIntegratorDec(this, ti));
	addPostHook(new MvmIntegratorInc(this, ti));

	return ti;
	}

    MvmManager::This->warning("MvmResource::setStatistics() - statistics not available");

    return NULL;
}

void MvmResource::setGlobalTrace (int traceLevel)

{ globalTrace = traceLevel; }
