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

#ifndef _mvm_timer_h
#define _mvm_timer_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/clock.h"
#include "vm/manager.h"
#include "vm/timed.h"
#include "vm/thread.h"
#include "vm/stream.h"

enum MvmTimerStates {
    EXPIRED =9,
    DISARMED,
    ARMED
};

class MvmTimerManager : public MvmThread {

    friend class MvmManager;

protected:

    MvmTimerManager();

    virtual void body();

public:

    static MvmTimerManager * This;
};

class MvmTimer : public MvmTimed {

    friend class MvmTimerManager;

protected:

    static int globalTrace;

    MvmThread *waitingThread;

public:

    static MvmSchedSlave timerChain;
	
    static void setGlobalTrace(int traceLevel);

    MvmTimer(const char *name,
	     ITime timeout,
	     MvmThread *wthread =0,
	     int pflags =0);

    MvmTimer(const char *name,
	     MvmThread *wthread,
	     int pflags =0);

    MvmTimer(const char *name =0,
	     int pflags =0);

    virtual ~MvmTimer();

    void set(ITime time);

    void reset();

    void print(MvmStream&);

    virtual void activate();

    virtual void ifInit();

    virtual int stateIndex(int state);
};

MakeGList(MvmTimer);

extern void printTimerChain();

#endif // !_mvm_timer_h
