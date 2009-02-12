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

#ifndef _mvm_object_h
#define _mvm_object_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/tclist++.h"
#include "vmutils/statobj.h"

enum MvmObjectStates {
    DEAD,
    SRAW
};

enum MvmStatisticType {
    STAT_NUM,
    STAT_MEAN,
    STAT_DTIME
};

class MvmObject : public MvmStateDiagram {

protected:

    u_long oid;		// Unique object id.

    int state;

    CString group;

    static u_long objectStamps;

public :

    MvmObject(const char *name =0,
	      const char *group =0,
	      int pflags =0,
	      MvmConnector *connector =NULL,
	      int logSize =NSTVALUEDEF);

    u_long getOid() const {
	return oid;
    }

    int setState(int state);

    int getState() const {
	return state;
    }

    const char *getStateLabel() const {
	return getStateName(state);
    }

    virtual int stateIndex(int state);

    virtual const char *getCurveName();
};

MakeGList(MvmObject);

#define MAX_THREAD_ENTRYLEN    64

struct MvmThreadExportMsg : public MvmInterfaceExportMsg {

    u_long threadID;	// i.e. MvmObject::oid

    char threadEntry[MAX_THREAD_ENTRYLEN];
	
    MvmThreadExportMsg(MvmObject *_object,
		       const char *_threadEntry) :
	MvmInterfaceExportMsg(MVM_IFACE_THREAD_ID,
			      _object->ifGetName()) {
	threadID = _object->getOid();
	if (_threadEntry)
	    scopy(threadEntry,_threadEntry,MAX_THREAD_ENTRYLEN-1);
	else
	    *threadEntry = '\0';
    }
};

#define MVM_PLUGIN_NAME_LEN 128

struct MvmDashboardExportMsg : public MvmInterfaceExportMsg {

    // Tcl/Tk plugin information i.e. {prefix privateinfo}
    char plugInfo[MVM_PLUGIN_NAME_LEN];

    MvmDashboardExportMsg(const char *name,
			  const char *prefix,
			  const char *privateInfo) :
	MvmInterfaceExportMsg(MVM_IFACE_DASHBOARD_ID,name) {

	TclList tclist(prefix);

	if (privateInfo)
	    tclist.append(TclList(privateInfo));

	scopy(plugInfo,tclist,MVM_PLUGIN_NAME_LEN-1);
    }
};

#endif // !_mvm_object_h
