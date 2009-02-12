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

#ifndef _mvm_queue_h
#define _mvm_queue_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vm/thread.h"
#include "vm/synchro.h"

#define MVM_QUEUE_MAXMSG ((int)2147483647)

class MvmStatObj;
class MvmQueue;

class MvmInfo : public PLink {

    friend class MvmQueue;

protected:

    ITime tStart;

    int idTraf;

    MvmQueue *qLoc;

    void setQueue(MvmQueue *q) {
	qLoc = q;
    }

public:

    MvmInfo(int pri =0,
	    int traffic =0);

    MvmInfo(const MvmInfo&);

    virtual MvmInfo *clone();

    MvmInfo *copy();

    MvmQueue *getQueue() const {
	return qLoc;
    }

    void setTraf(int _idTraf) {
	idTraf = _idTraf;
    }

    int getTraf() const {
	return idTraf;
    }

    ITime getTime() const {
	return tStart;
    }

    void free();

    virtual void print(MvmStream&);
};

class MvmQueue : public MvmSynchro, public PList {

protected:

    unsigned countMax;

    static int globalTrace;

public :

    static void setGlobalTrace(int traceLevel);

    MvmQueue(const char *name,
	     InsertMode imode,
	     unsigned maxMsg =MVM_QUEUE_MAXMSG,
	     InsertMode pmode =FIFO);

    MvmQueue(InsertMode imode,
	     unsigned maxMsg =MVM_QUEUE_MAXMSG,
	     InsertMode pmode =FIFO);

    MvmQueue();

    void post(MvmInfo *msg);

    void postFront(MvmInfo *msg);

    void put(MvmInfo *msg) {
	post(msg);
    }

    MvmInfo *get();

    MvmInfo *accept();

    MvmInfo *first() const {
	return (MvmInfo *)PList::first();
    }

    MvmInfo *last() const {
	return (MvmInfo *)PList::last();
    }

    void remove(MvmInfo *msg);

    unsigned getOCount() const;

    inline unsigned getOMax(void) const {
	return countMax;
    }

    MvmStatObj *setStatistics(MvmStatisticType stype =STAT_MEAN);

    virtual void print(MvmStream&);

    virtual void pend();
};

#define MakeMvmQueue(TYPE) \
class name2(TYPE,MvmQueue) : public MvmQueue \
{ \
public: \
	name2(TYPE,MvmQueue)(InsertMode m, \
			     int n =MVM_QUEUE_MAXMSG, \
			     InsertMode om =FIFO) : \
	MvmQueue(m,n,om) {} \
	name2(TYPE,MvmQueue)(void) : MvmQueue() {} \
\
	TYPE*	get()	{ return (TYPE*) MvmQueue::get(); } \
	TYPE*	accept()	{ return (TYPE*) MvmQueue::accept(); } \
	TYPE*   first() const { return (TYPE *)MvmQueue::first(); } \
	TYPE*   last() const { return (TYPE *)MvmQueue::last(); } \
}
	
#endif // !_mvm_queue_h
