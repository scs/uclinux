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
 * Author(s): rpm
 * Contributor(s):
 *
 * Partly rewritten for XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <stdlib.h>
#include "vmutils/tclist++.h"
#include "vm/monitor.h"
#include "vm/manager.h"
#include "vm/thread.h"
#include "vm/trace.h"

HashTable MvmTraceManager::ifaceTable(32);

MvmTraceManager *MvmTraceManager::This = NULL;

// MvmTraceManager -- an object holding a list of trace interfaces
// defined in the simulation. A trace interface holds a description of
// the calls used to access simulated services.

MvmTraceManager::MvmTraceManager (const char *_name) :
    MvmDashboard(_name,"MvmTracer")
{
    This = this;
    traceMode = MVM_TRACE_NONE;
}

MvmTrace **MvmTraceManager::addInterface (const char *name,
					  int maxTraceDef,
					  const MvmTraceDef *traceDefTable,
					  int maxErrorDef,
					  const MvmErrorDef *errorDefTable)
{
    if (!MvmMonitor::This)
	return NULL;

    MvmTrace **callTable = (MvmTrace **)ifaceTable.find(name);

    if (callTable)
	return callTable;
	
    HashTable *errorTable;
    
    if (errorDefTable)
	{
	errorTable = new HashTable(maxErrorDef);

	for (int n = 0; n < maxErrorDef; n++)
	    errorTable->enter(errorDefTable[n].errorCode,
			      errorDefTable[n].errorName);
	}
    else
	errorTable = NULL;

    callTable = new MvmTrace *[maxTraceDef + 1];

    for (int n = 0; n < maxTraceDef; n++)
	callTable[n] = new MvmTrace(traceDefTable[n].callName,
				    traceDefTable[n].callFamily,
				    errorTable);

    callTable[maxTraceDef] = NULL;

    ifaceTable.enter(name,callTable);
    
    return callTable;
}

void MvmTraceManager::ifInit ()

{
    MvmTraceManagerExportMsg tmem(this);
    ifExport(&tmem,sizeof(tmem));
}

void MvmTraceManager::ifProcess (int mtype,
				 const MvmInterfaceMsg *mbuf,
				 int msize)
{
    if (mtype == MVM_IFACE_DASHBOARD_INFO)
	sendInfoBlock();
    else if (mtype == MVM_IFACE_DASHBOARD_CONFIGURE)
	configureTraces((MvmInterfaceInfoMsg *)mbuf);
}

void MvmTraceManager::sendInfoBlock ()

{
    // Export information about the interfaces declared
    // to the manager.
    
    HashScanner parser(ifaceTable);
    const char *interfaceName;
    MvmTrace **callTable;
    TclList tclist;
	
    while ((interfaceName = parser.forward((void **)&callTable)) != NULL)
	{
	TclList _tclist, __tclist;
	_tclist.append(interfaceName);
	formatInterfaceInfo(callTable,__tclist);
	_tclist.append(__tclist);
	tclist.append(_tclist);
	}

    ifInfo(MVM_IFACE_DASHBOARD_INFO,tclist.get(),tclist.length());
}

void MvmTraceManager::formatInterfaceInfo (MvmTrace **callTable,
					   TclList& tclist)
{
    MvmTrace **callPtr = callTable;
    TclList _tclist;

    const char *currGroup = (*callPtr)->getGroup();
    _tclist.append((*callPtr)->getName());

    while (*++callPtr)
	{
	if (strcmp((*callPtr)->getGroup(),currGroup))
	    {
	    TclList __tclist(currGroup);
	    __tclist.append(_tclist);
	    tclist.append(__tclist);
	    _tclist.clear();
	    currGroup = (*callPtr)->getGroup();
	    }

	_tclist.append((*callPtr)->getName());
	}

    if (_tclist.length() > 0)
	{
	TclList __tclist(currGroup);
	__tclist.append(_tclist);
	tclist.append(__tclist);
	}
}

void MvmTraceManager::configureTraces (MvmInterfaceInfoMsg *info)

{
    TclList tclist(info->data,strlen(info->data));
    TclListParser parser(tclist);

    const char *cmd = parser.next();

    if (strcmp(cmd,"configure") == 0)
	{
	// first of all, reset all traces state
	resetTraces();

	// reset previous trace options
	traceMode &= ~(MVM_TRACE_CALLOUTS|\
		       MVM_TRACE_ERRORS|\
		       MVM_TRACE_DONTFILTER);

	TclListParser _parser(parser.next());
	const char *option;

	while ((option = _parser.next()) != NULL)
	    {
	    if (strcmp(option,"callouts") == 0)
		traceMode |= MVM_TRACE_CALLOUTS;
	    else if (strcmp(option,"errorbrk") == 0)
		traceMode |= MVM_TRACE_ERRORS;
	    else if (strcmp(option,"nofiltering") == 0)
		traceMode |= MVM_TRACE_DONTFILTER;
	    }
	
	// determine which traces are to be toggled to "active" state.
	const char *args;
	
	while ((args = parser.next()) != NULL)
	    {
	    TclListParser __parser(args);
	    const char *iname = __parser.next();
	    const char *settings = __parser.next();

	    MvmTrace **callTable = (MvmTrace **)ifaceTable.find(iname);

	    if (callTable) // should be!
		{
		TclListParser ___parser(settings);
		const char *call;

		while ((call = ___parser.next()) != NULL)
		    {
		    int callID = atoi(call);
		    callTable[callID]->setState(MVM_TRACE_ACTIVE);
		    }
		}
	    }
	}
    else
	{
	// Step/Release simulation with tracing enabled

	resetStates();
	
	const char *focus = parser.next();

	if (strcmp(focus,"system") == 0)
	    tracedFocus.type = XSystemContext;
	else
	    {
	    // must be "thread" focus -- its handle is passed
	    // in the focus string.
	    tracedFocus.type = XThreadContext;
	    tracedFocus.internalID = (u_long)atol(focus);
	    }

	traceMode |= MVM_TRACE_DISPLAY;
	
	if (strcmp(cmd,"step") == 0)
	    traceMode |= MVM_TRACE_STEP;
	}
}

void MvmTraceManager::resetTraces ()

{
    HashScanner scanner(ifaceTable);
    MvmTrace **callTable;
	
    while (scanner.forward((void **)&callTable))
	{
	MvmTrace **callPtr = callTable;

	while (*callPtr)
	    {
	    (*callPtr)->clrState(MVM_TRACE_ACTIVE|MVM_TRACE_DISPLAY);
	    callPtr++;
	    }
	}
}

int MvmTraceManager::testContext (XenoThread *thread)

{
    if (tracedFocus.type == XSystemContext ||
	MvmManager::This->findThread(tracedFocus) == thread)
	return traceMode;

    return MVM_TRACE_NONE;
}

void MvmTraceManager::logEvent (XenoThread *thread) // FIXME
{
    // Assume that all events trapped here are thread-related events

    if (!(traceMode & MVM_TRACE_CALLOUTS) ||
	!(testContext(thread) & MVM_TRACE_RUNBITS))
	return;

    outBuf.overwrite("@callout@");
    outBuf += MvmClock.format("> ");

#if 0
    CString coSourceName;

    coSourceName = thread->getCoSource()->ifGetName();

    switch (event)
	{
	case XTStartEvent:

	    outBuf.cformat("Starting %s from %s",
			   thread->ifGetName(),
			   (const char *)
			   coSourceName);
	    break;
		
	case XTSuspendEvent:

	    outBuf.cformat("Suspending %s from %s",
			   (const char *)
			   thread->ifGetName(),
			   (const char *)
			   coSourceName);
	    break;
		
	case XTDeleteEvent:

	    outBuf.cformat("Deleting %s from %s",
			   thread->ifGetName(),
			   (const char *)
			   coSourceName);
	    break;

	case XTSwitchEvent:

	    outBuf.cformat("Switching %s => %s",
			   (const char *)
			   coSourceName,
			   thread->ifGetName());
	    break;
	}
#endif

    outBuf.appendChar('\n');

    ifInfo(MVM_IFACE_DASHBOARD_OUTPUT,outBuf,outBuf.len());
}

void MvmTraceManager::resetStates ()

{
    HashScanner scanner(ifaceTable);
    MvmTrace **callTable;
	
    while (scanner.forward((void **)&callTable))
	{
	MvmTrace **callPtr = callTable;

	while (*callPtr)
	    {
	    if ((traceMode & MVM_TRACE_DONTFILTER) ||
		(*callPtr)->testState(MVM_TRACE_ACTIVE))
		(*callPtr)->setState(MVM_TRACE_DISPLAY);
	    else
		(*callPtr)->clrState(MVM_TRACE_DISPLAY);

	    callPtr++;
	    }
	}
}

void MvmTraceManager::writeTrace (int flags,
				  const char *format,
				  va_list ap)
{
    if (!MvmMonitor::This)
	{
	if (flags & MVM_TRACE_ALERT)
	    MvmManager::This->warning(NULL,format,ap);

	return;
	}

    if (flags & MVM_TRACE_ALERT)
	outBuf.overwrite("@alert");
    else if (flags & MVM_TRACE_HIGHLIGHT)
	outBuf.overwrite("@highlight");
    else
	outBuf = nilString;

    if (!outBuf.isEmpty())
	{
	if (flags & MVM_TRACE_RED)
	    outBuf += "-red@";
	else if (flags & MVM_TRACE_YELLOW)
	    outBuf += "-yellow@";
	else if (flags & MVM_TRACE_GREEN)
	    outBuf += "-green@";
	else if (flags & MVM_TRACE_BLUE)
	    outBuf += "-cyan@";
	else
	    outBuf.appendChar('@');
	}

    outBuf += MvmClock.format("> ");
    outBuf.cvformat(format,ap);
    outBuf.appendChar('\n');
    ifInfo(MVM_IFACE_DASHBOARD_OUTPUT,outBuf,outBuf.len());

    if ((flags & MVM_TRACE_ALERT) &&
	MvmManager::This->testFlags(MVM_ALRTBRK))
	MvmMonitor::This->stopSimulation(MVM_STOP_TRACE);
}

// MvmTrace -- an object which implements the trace formatting
// routine for a given call.

MvmTrace::MvmTrace (const char *_name,
		    const char *_group,
		    HashTable *_errorTable)
{
    name = _name;
    group = _group;
    state = MVM_TRACE_NONE;
    errorTable = _errorTable;
}

void MvmTrace::trace (const char *format, va_list ap)

{
    outBuf = emptyString; // Reuse allocated memory.
    outBuf += MvmClock.format("> ");
    outBuf += getName();

    MvmTraceManager::This->ifInfo(MVM_IFACE_DASHBOARD_OUTPUT,
				  outBuf,
				  outBuf.len());
}
