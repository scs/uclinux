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

#ifndef _mvm_daemon_h
#define _mvm_daemon_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/clock.h"

class MvmDaemon : public LinkedObject {

protected:

    static int globalTrace;

    MvmDaemon *_next;

    int _prio;

    int nFires;

    virtual void body() {
    }

public:

    static void setGlobalTrace(int traceLevel);

    MvmDaemon(int __prio =0) {
	_next = 0;
	_prio = __prio;
	nFires = 0;
    }

    int fire(int ord);

    MvmDaemon *addDaemon(MvmDaemon *devil);

    MvmDaemon *remDaemon(MvmDaemon *devil);

    MvmDaemon *isLinked(MvmDaemon *devil) const;

    MvmDaemon *next() const {
	return _next;
    }
};

MakeGList(MvmDaemon);

class MvmIntegrator;
class MvmObject;

class MvmIntegratorInc : public MvmDaemon {

protected:

    MvmIntegrator *integ;

    MvmObject *sysObj;

    virtual void body();

public:

    MvmIntegratorInc(MvmObject *, MvmIntegrator *);
};

class MvmIntegratorDec : public MvmDaemon {

protected:

    MvmIntegrator *integ;

    MvmObject *sysObj;

    virtual void body();

public:

    MvmIntegratorDec(MvmObject *, MvmIntegrator *);
};

#endif // !_mvm_daemon_h
