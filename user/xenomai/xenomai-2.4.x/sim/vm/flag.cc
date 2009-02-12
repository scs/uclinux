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
#include "vm/flag.h"
#include "vm/manager.h"

int MvmFlag::globalTrace = 0;

MvmFlag::MvmFlag (const char *_name,
		  MvmSynchroState _ss) :
    MvmSynchro(_name)
{
    setState(_ss);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 1)
	MvmDebug << "FLAG " << ifGetName() << " " << this
		 << " created with state " << (int) state
		 << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
}

MvmFlag::MvmFlag () :
    MvmSynchro(NULL)
{
    setState(OFF);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 1)
	MvmDebug << "FLAG " << ifGetName() << " " << this
		 << " created with state " << (int) state
		 << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmFlag::post ()

{
    if (state == PENDED)
	{
	int nfires = 0;

	if (postHook)
	    nfires = postHook->fire(nfires);

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " FLAG "
		     << ifGetName() << " " << this << " posted by " 
		     << MvmThread::currentThread->ifGetName() << " / "
		     << pendList.getCount() << " pending\n";

	    if (globalTrace > 1)
		print(MvmDebug);
	    }
#endif // CONFIG_XENO_MVM_DEBUG

	alert();
	}

    setState(ON);
}

void MvmFlag::reset ()

{
    if (state == ON)
	setState(OFF);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	MvmDebug << MvmClock << " FLAG " << ifGetName()
		 << " " << this  << " reset by "
		 << MvmThread::currentThread->ifGetName() << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmFlag::pend ()

{
    switch (state)
	{
	case ON:

	    return;

	case OFF:

	    setState(PENDED);

	case PENDED:

	    if (pendHook)
		pendHook->fire(0);

	    pendList.append(MvmThread::currentThread);

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug << MvmClock << " FLAG "
			 << ifGetName() << " " << this << " pended by " 
			 << MvmThread::currentThread->ifGetName() << " / "
			 << pendList.getCount() << " pending\n";

		if (globalTrace > 1)
		    print(MvmDebug);
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    MvmThread::currentThread->pend(this);
	    return;

	default:

	    MvmManager::This->fatal("MvmFlag::pend() - invalid flag state");
	}
}

void MvmFlag::print (MvmStream& ios)

{
    ios	<< "FLAG " << ifGetName() << " " << this << " state "
	<< (int) state << " / " << pendList.getCount()
	<< " pending\n";

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

void MvmFlag::setGlobalTrace (int traceLevel)

{ globalTrace = traceLevel; }
