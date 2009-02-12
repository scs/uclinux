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
#include <stdarg.h>
#include "vm/synchro.h"
#include "vm/manager.h"
#include "vm/monitor.h"

MvmSynchro::MvmSynchro (const char *_name) :
    MvmObject(_name,NULL,0,MvmMonitor::This)
{
    state = OFF;
    postHook = pendHook = NULL;
}

MvmSynchro::~MvmSynchro()

{
    if (pendList.getCount())
	{
	MvmManager::This->warning("MvmSynchro::~MvmSynchro() - deleted object still pended");
	alert();
	}
}

void MvmSynchro::alert()

{
    MvmThread *thread;

    while ((thread = pendList.get()) != NULL)
	thread->resume(this);
}

void MvmSynchro::forget (MvmThread *thread)

{
    pendList.remove(thread);	// null-effect if not linked

    if (thread->pendSynchro == this)
	thread->pendSynchro = NULL;

    if (pendList.getCount() == 0 && state == PENDED)
	setState(OFF);
}

int MvmSynchro::remember (MvmThread *thread)

{
    switch ((MvmSynchroState) state)
	{
	case ON:

	    return 1;

	case OFF:

	    setState(PENDED);

	case PENDED:

	    pendList.insert(thread,thread->prio());
	    break;

	case POSTED:
	default:

	    MvmManager::This->fatal("MvmSynchro::remember() - invalid synchro state");
	}

    return 0;
}

void MvmSynchro::pend ()

{
    switch((MvmSynchroState) state)
	{
	case POSTED:
	case ON:

	    return;

	case OFF:

	    setState(PENDED);

	case PENDED:

	    pendList.insert(MvmThread::currentThread,
			    MvmThread::currentThread->prio());
	    MvmThread::currentThread->pend(this);
	    break;

	default:

	    MvmManager::This->fatal("MvmSynchro::pend() - invalid synchro state");
	}
}

void MvmSynchro::addPendHook (MvmDaemon* doit)

{
    if (!pendHook)
	pendHook = doit;
    else
	pendHook = pendHook->addDaemon(doit);
}

void MvmSynchro::addPostHook (MvmDaemon* doit)

{
    if (!postHook)
	postHook = doit;
    else
	postHook = postHook->addDaemon(doit);
}

void MvmSynchro::ifInit ()

{
    const char *stateArray[5];
    stateArray[0] = "DEAD";
    stateArray[1] = "PENDED";
    stateArray[2] = "OFF";
    stateArray[3] = "ON";
    stateArray[4] = "POSTED";

    defineStates(sizeof(stateArray) / sizeof(stateArray[0]),stateArray);
    MvmObject::ifInit();
}

int MvmSynchro::stateIndex (int s)

{
    if (s < 2)
	return 0;

    return s - 3;
}

SynchroGroup::SynchroGroup (MvmSynchro *so, ...) :
    MvmSynchro(NULL)
{
    va_list ap;

    va_start(ap,so);

    for (MvmSynchro *s = so; s; s = va_arg(ap,MvmSynchro *))
	append(s);

    va_end(ap);
}

void SynchroGroup::forget (MvmThread *thread)

{
    MvmSynchroIterator it(synchList);
    MvmSynchro *so;

    while ((so = it.pop()) != NULL)
	so->forget(thread);
}
