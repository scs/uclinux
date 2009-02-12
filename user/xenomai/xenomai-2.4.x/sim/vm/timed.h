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
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvm_timed_h
#define _mvm_timed_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/object.h"

class MvmTimed;
class MvmScheduler;
class MvmThread;

enum TimedStates {
    TS_IDLE =8,
    TS_PENDING,
    TS_PREEMPTED,
    TS_RUNNING
};

class MvmTimed : public MvmObject, public PLink {

    friend class MvmScheduler;

protected:

    MvmScheduler *sched;

    ITime schedTime;

public :

    MvmTimed(const char *name,
	     MvmScheduler *sched,
	     int pflags =0);

    ITime getTime() const {
	return schedTime;
    }

    void  setTime(ITime it) {
	schedTime = it;
    }

    void  insert(ITime it) {
	delay(it);
    }

    virtual void activate() =0;

    virtual void suspend();

    virtual void resume();

    virtual void delay(ITime);

    virtual void ifInit();
};

MakePList(MvmTimed);

class MvmCallout : public LinkedObject {

    friend class MvmScheduler;

protected:

    MvmThread *boundThread;
	
public:

    MvmCallout(MvmThread *boundThread =0);

    virtual void process() =0;
};

MakeGList(MvmCallout);

class MvmListener : public MvmCallout {

protected:

    fd_set waitSet;

    fd_set readySet;

    int waitCount;

    int dropCount;

    int testDropCount() {
	int n = --dropCount;
	if (!n) dropCount = 8;
	return n;
    }

    virtual void process();

public:

    MvmListener(int fd =-1);

    MvmListener(fd_set *waitSet);

    const fd_set& getWaitSet() const {
	return waitSet;
    }

    int getWaitCount() const {
	return waitCount;
    }

    const fd_set& getReadySet() const {
	return readySet;
    }

    void addFildes(int fd);

    void removeFildes(int fd);

    int poll(fd_set *readySet, struct timeval *tv);

    int poll(fd_set *readySet);
};

class MvmScheduler : public MvmTimedPList {

    friend class MvmThread;

protected:

    MvmTimed *activeObject;

    MvmCalloutGList callouts;

public:

    MvmScheduler();

    virtual ~MvmScheduler() {}

    MvmTimed *exchange();

    void insert(MvmTimed *object);

    void insert(MvmTimed *object,
		ITime time);

    int isActive(MvmTimed *object) const {
	return (object == activeObject);
    }

    MvmTimed *getActiveObject() {
	return activeObject;
    }

    void addCallout(MvmCallout *callout,
		    MvmThread *boundThread =0);

    void removeCallout(MvmCallout *callout);

    virtual MvmTimed *schedule();
};

MakeList(MvmTimed);

class MvmSchedSlave : public MvmScheduler {

protected:

    MvmScheduler *master;

    MvmTimed *manager;

    ITime tNext;

public:

    MvmSchedSlave(MvmScheduler *master =0,
		  MvmTimed *manager =0);

    virtual ~MvmSchedSlave() {}

    void setMaster(MvmScheduler *s) {
	master = s;
    }

    void setManager(MvmTimed *mg) {
	manager = mg;
    }

    void setTNext(ITime tn) {
	tNext = tn;
    }

    virtual MvmTimed *schedule();
};

#endif // !_mvm_timed_h
