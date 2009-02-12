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
#include <stdarg.h>
#include "vm/queue.h"
#include "vm/manager.h"

int MvmQueue::globalTrace = 0;

MvmInfo::MvmInfo (int p, int t) :
    PLink(p)
{
    idTraf = t;
    tStart = MvmClock;
    qLoc = 0;
}

MvmInfo::MvmInfo (const MvmInfo& io) :
    PLink(io._prio)
{
    idTraf = io.idTraf;
    tStart = MvmClock;
    qLoc = 0;
}

MvmInfo *MvmInfo::clone ()

{ return new MvmInfo(*this); }

MvmInfo *MvmInfo::copy ()

{
    MvmInfo* io = clone();
    io->tStart = tStart;
    return io;
}

void MvmInfo::print (MvmStream& ios)

{
    ios << "INFO OBJECT " << this << " prio " << _prio
	<< " traf " << idTraf << " tStart " << tStart
	<< " in " << qLoc << '\n';
}

void MvmInfo::free ()

{
    qLoc->remove(this);
    qLoc = NULL;
}

MvmQueue::MvmQueue (const char *_name,
		    InsertMode _om,
		    unsigned _nmax,
		    InsertMode _pm) :
    MvmSynchro(_name), PList(_om)
{
    pendList.setMode(_pm);
    countMax = _nmax;

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 1)
	MvmDebug << "QUEUE " << this << " created with mode "
		 << (int)_om << " and max " << _nmax << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
}

MvmQueue::MvmQueue (InsertMode om,
		    unsigned nmax,
		    InsertMode pm) :
    PList(om)
{
    pendList.setMode(pm);
    countMax = nmax;

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 1)
	MvmDebug << "QUEUE " << this << " created with mode "
		 << (int)om << " and max " << nmax << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
}

MvmQueue::MvmQueue() :
    PList(FIFO)
{
    pendList.setMode(FIFO);
    countMax = MVM_QUEUE_MAXMSG;

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 1)
	MvmDebug << "QUEUE " << this << " created with mode "
		 << (int)FIFO << " and max " << MVM_QUEUE_MAXMSG << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmQueue::post (MvmInfo * io)

{
    // keep postHook on stack to avoid using a dandling pointer if
    // the awakened thread destroys this MvmQueue.
    MvmDaemon *pHook = postHook;

    if (io == NULL)
	MvmManager::This->fatal("MvmQueue::post() - null message posted");

    if (io->getQueue())
	{
	MvmManager::This->warning("MvmQueue::post() - re-hosting message");
	io->free();
	}

    switch (state)
	{
	case OFF:

	    setState(ON);

	case ON:

	    if (count == countMax)
		setState(POSTED);

	case POSTED:

	    while (count >= countMax)
		{
		pendList.append(MvmThread::currentThread);

#ifdef CONFIG_XENO_MVM_DEBUG
		if (globalTrace > 0)
		    {
		    MvmDebug << MvmClock << " QUEUE " << ifGetName()
			     << " " << this << " full, posted "	<< io << " by "
			     << MvmThread::currentThread->ifGetName() << " / "
			     << pendList.getCount() << " posting\n";

		    if (globalTrace > 1)
			print(MvmDebug);
		    }
#endif // CONFIG_XENO_MVM_DEBUG

		MvmThread::currentThread->pend(this);
		}

	    PList::put((PLink *)io);
	    io->setQueue(this);

	    if (pHook)
		pHook->fire(0);

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug << MvmClock << " QUEUE " << ifGetName()
			 << " " << this << " posted " << io	<< " by "
			 << MvmThread::currentThread->ifGetName() << " / " 	
			 << getOCount() << " posted\n";

		if (globalTrace > 1)
		    print(MvmDebug);
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    break;

	case PENDED:

	    {
	    PList::put((PLink *) io);
	    io->setQueue(this);

	    MvmThread *th = pendList.get();

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug << MvmClock << " QUEUE " << ifGetName()
			 << " " << this << " posted " << io << " by "
			 << MvmThread::currentThread->ifGetName() << " to pending "
			 << th << " / " << pendList.getCount() << " pending\n";

		if (globalTrace > 1)
		    print(MvmDebug);
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    if (pendList.getCount() == 0)
		setState(ON);

	    if (pHook)
		pHook->fire(0);

	    th->immediateResume(this);
	    break;
	    }

	default:

	    MvmManager::This->fatal("MvmQueue::post() - invalid queue state");
	}
}

void MvmQueue::postFront (MvmInfo *io)

{
    MvmDaemon *pHook = postHook;

    if (io == NULL)
	MvmManager::This->fatal("MvmQueue::postFront() - null message posted");

    if (io->getQueue())
	{
	MvmManager::This->warning("MvmQueue::postFront() - re-hosting message");
	io->free();
	}

    switch (state)
	{
	case OFF:

	    setState(ON);

	case ON:

	    if (count == countMax)
		setState(POSTED);

	case POSTED:

	    while (count >= countMax)
		{
		pendList.append(MvmThread::currentThread);

#ifdef CONFIG_XENO_MVM_DEBUG
		if (globalTrace > 0)
		    {
		    MvmDebug << MvmClock << " QUEUE " << ifGetName()
			     << " " << this << " full, posted " << io << " by "
			     << MvmThread::currentThread->ifGetName() << " / "
			     << pendList.getCount() << " posting\n";

		    if (globalTrace > 1)
			print(MvmDebug);
		    }
#endif // CONFIG_XENO_MVM_DEBUG

		MvmThread::currentThread->pend(this);
		}

	    PList::prepend((PLink *) io);
	    io->setQueue(this);

	    if (pHook)
		pHook->fire(0);

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug << MvmClock << " QUEUE " << ifGetName()
			 << " " << this << " posted " << io	<< " by "
			 << MvmThread::currentThread->ifGetName() << " / " 	
			 << getOCount() << " posted\n";

		if (globalTrace > 1)
		    print(MvmDebug);
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    break;

	case PENDED:

	    {
	    PList::prepend((PLink *) io);
	    io->setQueue(this);
	    MvmThread *th = pendList.get();

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug 	<< MvmClock << " QUEUE " << ifGetName()
				<< " " << this << " posted " << io << " by "
				<< MvmThread::currentThread->ifGetName() << " to pending "
				<< th << " / " << pendList.getCount() << " pending\n";

		if (globalTrace > 1)
		    print(MvmDebug);
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    if (pendList.getCount() == 0)
		setState(ON);

	    if (pHook)
		pHook->fire(0);

	    th->immediateResume(this);
	    break;
	    }

	default:
	    MvmManager::This->fatal("MvmFlag::postFront() - invalid queue state");
	}
}

void MvmQueue::pend ()

{
    switch (state)
	{
	case OFF:

	    setState(PENDED);

	case PENDED:

	    pendList.insert(MvmThread::currentThread,
			    MvmThread::currentThread->prio());
	    
#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug << MvmClock << " QUEUE " << ifGetName()
			 << " " << this << " pended by "
			 << MvmThread::currentThread->ifGetName()
			 << " / " << pendList.getCount() << " pending\n";

		if (globalTrace > 1)
		    print(MvmDebug);
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    MvmThread::currentThread->pend(this);

	default:

	    break;
	}

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	{
	MvmDebug << MvmClock << " QUEUE " << ifGetName()
		 << " " << this  << " pended by "
		 << MvmThread::currentThread->ifGetName() << " returns "
		 << (MvmInfo *)PList::first() << " / " << getOCount()
		 << " posted\n";

	if (globalTrace > 1)
	    print(MvmDebug);
	}
#endif // CONFIG_XENO_MVM_DEBUG

    if (state == POSTED)
	{
	MvmThread * th = pendList.get();
	th->resume(this);

	if (pendList.getCount() == 0)
	    setState(ON);
	}
}

MvmInfo *MvmQueue::accept ()

{
    MvmInfo *info;

    if (pendHook && PList::first())
	pendHook->fire(0);

    info = (MvmInfo *) PList::get();

    if (info && count == 0 && pendList.getCount() == 0)
	setState(OFF);

    if (info)
	info->setQueue(0);

    return info;
}

void MvmQueue::remove (MvmInfo *io)

{
    if (io)
	{
	if (pendHook && isLinked(io))
	    pendHook->fire(0);
	
	PList::remove(io);

	if (count == 0 && pendList.getCount() == 0)
	    setState(OFF);

	io->setQueue(0);
	}
}

MvmInfo *MvmQueue::get ()

{
    MvmInfo *info;

    pend();

    if (pendHook)
	pendHook->fire(0);

    info = (MvmInfo *)PList::get();

    if (!info)
	MvmManager::This->fatal("MvmQueue::get() - stale message");

    if (info && count == 0 && pendList.getCount() == 0)
	setState(OFF);

    info->setQueue(0);

    return info;
}

unsigned MvmQueue::getOCount () const

{ return count; }

void MvmQueue::print (MvmStream& ios)

{
    ios << "QUEUE " << ifGetName() << " " << this << " state "
	<< (int) state << " / " << getOCount() << " posted, "
	<< pendList.getCount() << " pending\n";

    switch (state)
	{
	case OFF:

	    break;

	case ON:
	case POSTED:

	    for (MvmInfo *io= (MvmInfo *)first();
		 io; io= (MvmInfo *)io->next())
		{
		ios << "     ";
		io->print(ios);
		}
	    
	    if (state == ON)
		break;

	case PENDED:
	    
	    {
	    MvmThreadIterator it(pendList);
	    MvmThread *thread;

	    while ((thread = it.next()) != NULL)
		{
		ios << "     ";
		thread->print(ios);
		}

	    break;
	    }

	default:

	    MvmManager::This->fatal("MvmQueue::print() - invalid queue state");
	}

    ios.flush();
}
		
MvmStatObj *MvmQueue::setStatistics (MvmStatisticType type)

{
    if (type == STAT_MEAN)
	{
	char n[64];
	sprintf(n,"QUEUE %p MEAN",this);

	MvmIntegrator *ti = new MvmIntegrator(n,
					      MvmManager::warmupTime,
					      MvmManager::finishTime,
					      MvmManager::samplingPeriod);
	ti->add(count);
	addPendHook(new MvmIntegratorDec(this,ti));
	addPostHook(new MvmIntegratorInc(this,ti));

	return ti;
	}

    MvmManager::This->warning("MvmQueue::setStatistics() - statistics not available");

    return NULL;
}

void MvmQueue::setGlobalTrace (int traceLevel)

{ globalTrace = traceLevel; }
