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

#ifndef _mvm_synchro_h
#define _mvm_synchro_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vm/thread.h"
#include "vm/event.h"

enum MvmSynchroState {
    PENDED =4,
    OFF,
    ON,
    POSTED
};

class MvmSynchro : public MvmObject {

friend class MvmThread;

protected:

    MvmThreadGList pendList;

    MvmDaemon *pendHook;

    MvmDaemon *postHook;

    int remember(MvmThread *thread);

public:

    MvmSynchro(const char *name =0);

    virtual ~MvmSynchro();

    int getPCount() const {
	return pendList.getCount();
    }

    void addPendHook(MvmDaemon *daemon);

    void remPendHook(MvmDaemon *daemon) {
	if (pendHook)
	    pendHook = pendHook->remDaemon(daemon);
    }

    void addPostHook(MvmDaemon *daemon);

    void remPostHook(MvmDaemon *daemon) {
	if (postHook)
	    postHook = postHook->remDaemon(daemon);
    }

    void setWaitMode(InsertMode _mode) {
	pendList.setMode(_mode);
    }

    InsertMode getWaitMode() const {
	return pendList.getMode();
    }

    virtual void inquire() {
    }

    virtual void alert();

    virtual void forget(MvmThread *thread);

    virtual void ifInit();

    virtual void pend();

    virtual int stateIndex(int);
};

MakeGList(MvmSynchro);

class SynchroGroup : public MvmSynchro {

protected:

    MvmSynchroGList synchList;

public:

    SynchroGroup(MvmSynchro *so, ...);

    SynchroGroup() {
    }

    void append(MvmSynchro *so) {
	synchList.append(so);
    }

    operator GList&() {
	return synchList;
    }

    virtual void forget(MvmThread *thread);
};

#endif // !_mvm_synchro_h
