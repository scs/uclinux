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
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvm_trace_h
#define _mvm_trace_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <stdarg.h>
#include "vmutils/hash++.h"
#include "vmutils/object.h"
#include "vm/display.h"

class MvmTraceInterface;
class MvmTrace;
class TclList;

struct MvmTraceDef {

    const char *callName;
    const char *callFamily;
};

struct MvmErrorDef {

    const char *errorName;
    int errorCode;
};

// flags for manager's trace mode
#define MVM_TRACE_NONE       0x0
#define MVM_TRACE_DISPLAY    0x1
#define MVM_TRACE_ACTIVE     0x2
#define MVM_TRACE_STEP       0x4
#define MVM_TRACE_ERRORS     0x8
#define MVM_TRACE_DONTFILTER 0x10
#define MVM_TRACE_ALERTS     0x20
#define MVM_TRACE_RUNBITS    (MVM_TRACE_STEP|MVM_TRACE_DISPLAY)
#define MVM_TRACE_CALLOUTS   0x100

// flags for writeTrace()
#define MVM_TRACE_NORMAL     0x0
#define MVM_TRACE_ALERT      0x1
#define MVM_TRACE_HIGHLIGHT  0x2
#define MVM_TRACE_RED        0x100
#define MVM_TRACE_BLUE       0x200
#define MVM_TRACE_YELLOW     0x400
#define MVM_TRACE_GREEN      0x800

class MvmTraceManager : public MvmDashboard {

protected:

    int traceMode;

    MvmContext tracedFocus;

    CString outBuf;
	
    void sendInfoBlock();

    void resetTraces();

    void resetStates();

    virtual void configureTraces(MvmInterfaceInfoMsg *info);

    static void formatInterfaceInfo(MvmTrace **callTable,
				    TclList& tclist);

public:

    static MvmTraceManager *This;
	
    static HashTable ifaceTable;

    MvmTraceManager(const char *name);

    MvmTrace **addInterface(const char *name,
			    int maxTraceDef,
			    const MvmTraceDef *traceDefTable,
			    int maxErrorDef,
			    const MvmErrorDef *errorDefTable);

    int isTracing() const {
	return (traceMode & MVM_TRACE_RUNBITS);
    }

    int getMode() const {
	return traceMode;
    }

    void clrTracing() {
	traceMode &= ~MVM_TRACE_RUNBITS;
    }

    int testContext(XenoThread *thread);

    const MvmContext& getFocus() const {
	return tracedFocus;
    }

    void logEvent(XenoThread *thread);

    void writeTrace(int flags,
		    const char *format,
		    va_list ap);

    virtual void ifInit();

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *mbuf,
			   int msize);
};

struct MvmTraceManagerExportMsg : public MvmDashboardExportMsg {

    MvmTraceManagerExportMsg(MvmTraceManager *_manager) :
	MvmDashboardExportMsg(_manager->ifGetName(),
			      "MvmTracer",
			      NULL) {
    }
};

class MvmTrace {

    friend class MvmTracePoint;

protected:

    const char *name,
	*group;

    CString outBuf;

    int state;

    HashTable *errorTable;
	
public:

    MvmTrace(const char *name,
	     const char *group,
	     HashTable *errorTable);

    const char *getGroup() const {
	return group;
    }

    const char *getName() const {
	return name;
    }

    int getState() const {
	return state;
    }

    void setState(int mask) {
	state |= mask;
    }

    void clrState(int mask) {
	state &= ~mask;
    }

    int testState(int mask) const {
	return (state & mask);
    }

    void trace(const char *format, va_list ap);
};

#endif // !_mvm_trace_h
