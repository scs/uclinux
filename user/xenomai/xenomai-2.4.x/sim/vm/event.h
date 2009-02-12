/* -*- C++ -*-
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

#ifndef _mvm_event_h
#define _mvm_event_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/object.h"
#include "vm/daemon.h"

enum MvmEventStates {
    LOW =2,
    HIGH
};

class MvmEvent : public MvmObject {

protected:

    MvmEvent *_next;

    MvmDaemon *handlers;

    static int globalTrace;

public:

    static void setGlobalTrace(int traceLevel);

    MvmEvent(MvmDaemon *handler,
	     MvmEvent *buddy =0);

    void link(MvmEvent *event) {
	_next = event;
    }

    MvmEvent *isLinked(MvmEvent *event) const;

    MvmEvent *next() {
	return _next;
    }

    void addHandler(MvmDaemon *handler);

    MvmDaemon *remHandler(MvmDaemon *handler =0);

    void addEvent(MvmEvent *event);

    MvmEvent *remEvent(MvmEvent *event);

    MvmDaemon *isArmed(MvmDaemon *handler) const {
	return (MvmDaemon *)handlers->isLinked(handler);
    }

    virtual int signal(int s);

    virtual void ifInit();

    virtual int stateIndex(int n);
};

class MvmStateEvent : public MvmEvent {

    friend class MvmObject;

protected:

    int onEvent,
	offEvent;

public:

    MvmStateEvent(int onState,
		  int offState,
		  MvmDaemon *handler,
		  MvmEvent *event =0);

    virtual int signal(int);
};

#endif // !_mvm_event_h
