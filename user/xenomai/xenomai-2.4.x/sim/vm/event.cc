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
#include "vm/event.h"
#include "vm/monitor.h"

int MvmEvent::globalTrace = 0;

MvmEvent::MvmEvent (MvmDaemon *handler, MvmEvent *buddy)

{
    ifSetHidden();
    state = LOW;
    handlers = handler;
    _next = buddy;
}

int MvmEvent::signal (int s)

{
    int nfires = 0;

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0) 
	MvmDebug << MvmClock << "EVENT " << ifGetName()
		 << " " << this << " state " << state
		 << " signaled " << s << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

    if (s == HIGH && state == LOW)
	{
	setState(s);

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0) 
	    MvmDebug << MvmClock << "EVENT " << ifGetName()
		     << " " << this << " fires " << handlers << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	if (handlers)
	    nfires = handlers->fire(nfires);
	}
    else
	setState(s);

    if (_next)
	nfires += _next->signal(s);

    return nfires;
}

void MvmEvent::addHandler (MvmDaemon *doit)

{
    handlers = doit->addDaemon(handlers);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 1) 
	MvmDebug << "EVENT " << ifGetName() << " " << this
		 << " armed with handler " << doit << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
}

MvmDaemon *MvmEvent::remHandler (MvmDaemon *didit)

{
    if (!didit)
	{
	didit = handlers;

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 1) 
	    MvmDebug << "EVENT " << ifGetName() << " " << this
		     << " disarmed of all handlers " 
		     << " starting with " << didit << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	handlers = NULL;
	
	return didit;
	}

    didit = handlers->isLinked(didit);

    if (didit)
	{
	handlers = handlers->remDaemon(didit);

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 1) 
	    MvmDebug << "EVENT " << ifGetName() << " " << this
		     << " disarmed of handler " << didit << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
	}

    return didit;
}

void MvmEvent::addEvent (MvmEvent *e)

{
    if (e)
	{
	MvmEvent *eve = this;

	while (eve->_next)
	    eve = eve->_next;

	eve->_next = e; 

	while (e)
	    {
#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 1) 
		MvmDebug << "EVENT " << e << " added to " << this << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	    e = e->_next;
	    }
	}
}

MvmEvent *MvmEvent::remEvent (MvmEvent *e)

{
    if (!e)
	return this;

    if (e == this)
	{
	e = e->_next;
	this->_next = 0;

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 1) 
	    MvmDebug << "EVENT " << this << " removed from " << this
		     << " return " << e << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	return e;
	}

    MvmEvent *eve = this;

    while (eve && (eve->_next != e))
	eve = eve->_next;

    if (eve)
	{
	eve->_next = e->_next;

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 1) 
	    MvmDebug << "EVENT " << e << " removed from " << this
		     << " after " << eve << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	e->_next = 0;
	}

    return this;
}

MvmEvent *MvmEvent::isLinked (MvmEvent *e) const

{
    if (this == e)
	return e;

    MvmEvent *eve = this->_next;

    while (eve && (eve != e))
	eve = eve->_next;

    return eve;
}

void MvmEvent::ifInit ()

{
    const char *stateArray[3];
    stateArray[0] = "DEAD";
    stateArray[1] = "LOW";
    stateArray[2] = "PENDED";

    defineStates(sizeof(stateArray) / sizeof(stateArray[0]),stateArray);
    MvmObject::ifInit();
}

int MvmEvent::stateIndex (int s)

{ return s < 2 ? 0 : s - 1; }

void MvmEvent::setGlobalTrace (int traceLevel)

{ globalTrace = traceLevel; }

MvmStateEvent::MvmStateEvent (int on, int off, MvmDaemon *doit, MvmEvent *eve)
    : MvmEvent(doit,eve)
{
    onEvent = on;
    offEvent = off;
}

int MvmStateEvent::signal (int s)

{
    int nfires = 0;

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0) 
	MvmDebug << MvmClock << " STATE EVENT " << this
		 << " state " << state << " signaled " << s << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

    if (s == onEvent && state == LOW)
	{
	setState(HIGH);

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0) 
	    MvmDebug << MvmClock << " STATE EVENT "
		     << ifGetName() << " " << this << " fires "
		     << handlers << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	nfires = handlers->fire(nfires);
	}
    else if (s == offEvent)
	setState(LOW);

    if (_next)
	nfires += _next->signal(s);

    return nfires;
}
