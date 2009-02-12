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
 * The original code is CarbonKernel - Real-time Operating System Simulator,
 * released April 15, 2000. The initial developer of the original code is
 * Realiant Systems (http://www.realiant.com).
 *
 * Description: C++ part of the Xenoscope debugger.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#include <xeno_config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include "vmutils/toolshop.h"
#include "debugger.h"
#include "workspace.h"
#include "monitor.h"
#include "gdbhelper.h"

#define GetThreads      1
#define GetCtlCode      2
#define HoldSimulation  3
#define StepOver        4
#define StepInto        5
#define StepOut         6
#define ContSimulation  7
#define StopDebug       8
#define CacheWindowIn   9
#define BuildLocalInfo  10
#define GetSpecs        11
#define GetUserPath     12
#define SetDebugFilter  13

static struct dbcodes {

    const char *codeString;
    int op;

} DBCodes[] = {
    { "DEBUGTRAP_BREAK", MVM_CREG_PBREAK|MVM_CREG_DEBUG },
    { "WATCHPOINT_BREAK", MVM_CREG_PBREAK|MVM_CREG_WATCH },
    // Must be last
    { "SYSTEM_SCOPE", MVM_CREG_SYSTEM_SCOPE },
    { "THREAD_SCOPE", MVM_CREG_THREAD_SCOPE },
    { 0, 0 }
};

Debugger::Debugger (Workspace *_workspace,
		    Monitor *_monitor) :
    TkContext(_workspace)
{
    workspace = _workspace;
    monitor = _monitor;

    handleEvent("GetSpecs",GetSpecs);
    handleEvent("GetThreads",GetThreads);
    handleEvent("GetCtlCode",GetCtlCode);
    handleEvent("HoldSimulation",HoldSimulation);
    handleEvent("StepOver",StepOver);
    handleEvent("StepInto",StepInto);
    handleEvent("StepOut",StepOut);
    handleEvent("ContSimulation",ContSimulation);
    handleEvent("CacheWindowIn",CacheWindowIn);
    handleEvent("BuildLocalInfo",BuildLocalInfo);
    handleEvent("GetUserPath",GetUserPath);
    handleEvent("SetDebugFilter",SetDebugFilter);

    if (getPipeOutDev() < 0)
	fatal("cannot create FIFO\n");

    callTkProc("Debugger:initialize","&C &S",
	       _workspace,
	       pipeOutDev.gets());

    helperAttach(TkContext::getInterp());
}

Debugger::~Debugger () {

    helperDetach(TkContext::getInterp());
}

void Debugger::notify (TkEvent event,
		       int argc,
		       char *argv[],
		       TkClientData clientData)
{
    switch (event)
	{
	case GetSpecs:

	    tkGetSpecs();
	    break;

	case GetThreads:

	    tkGetThreads();
	    break;

	case GetCtlCode:

	    tkGetCtlCode(argv[1],argc > 2 ? argv[2] : NULL);
	    break;

	case HoldSimulation:

	    monitor->holdSimulation();
	    break;

	case StepOver:

	    tkStep(argv[1],MVM_IFACE_DEBUG_STEPOVER);
	    break;

	case StepInto:

	    tkStep(argv[1],MVM_IFACE_DEBUG_STEPINTO);
	    break;

	case StepOut:

	    tkStep(argv[1],MVM_IFACE_DEBUG_STEPOUT);
	    break;

	case ContSimulation:

	    monitor->releaseSimulation();
	    break;

	case StopDebug:

	    tkStopDebug();
	    break;

	case CacheWindowIn:

	    workspace->cacheWindowIn(argv[1],argv[2]);
	    break;

	case BuildLocalInfo:

	    tkBuildLocalInfo(argv[1]);
	    break;

	case GetUserPath:
	    
	    {
	    CString path(argv[1]);
	    TclList tclist(path.getAbbrevPath());
	    setTkResult("&L",&tclist);
	    break;
	    }

	case SetDebugFilter:

	    tkSetDebugFilter(argv[1]);
	    break;
	}
}

void Debugger::editBreakpoints () {

    callTkProc("Debugger:editBreakpoints");
}

void Debugger::editWatchpoints () {

    callTkProc("Debugger:editWatchpoints");
}

void Debugger::tkStopDebug ()

{
    // Send a QUIT message to ensure the child will exit as expected
    // -- some implementations really need this. However, this could
    // have no effect if the simulator is really messed up.
    monitor->ifSend(MVM_IFACE_MONITOR_QUIT);
    callTkProc("Debugger:stop");
}

void Debugger::tkGetSpecs ()

{
    TclList tclist;
    monitor->fetchSpecs(tclist);
    setTkResult("&L",&tclist);
}

void Debugger::tkGetThreads ()

{
    TclList tclist;
    monitor->fetchThreads(tclist);
    setTkResult("&L",&tclist);
}

void Debugger::tkGetCtlCode (const char *codeString,
			     const char *scopeString)
{
    for (int n = 0; DBCodes[n].codeString; n++)
	{
	if (!strcmp(DBCodes[n].codeString,codeString))
	    {
	    int flags = DBCodes[n].op;

	    if (scopeString)
		{
		while (DBCodes[++n].codeString)
		    {
		    if (!strcmp(DBCodes[n].codeString,scopeString))
			{
			flags |= DBCodes[n].op;
			break;
			}
		    }
		}

	    setTkResult("&D",flags);

	    return;
	    }
	}

    setTkResult("?");
}

void Debugger::tkStep (TclList focus, int mtype)

{
    TclListParser scan(TclListParser(focus).next());
    MvmContext context;
    int flags = 0;
    const char *e;

    e = scan.next();
    
    if (strcmp(e,"asynch") == 0)
	{
	flags |= MVM_CREG_TRACE_ASYNCH;
	e = scan.next();
	}

    if (strcmp(e,"system") == 0)
	context.type = XSystemContext;
    else
	{
	context.type = XThreadContext;
	context.internalID = (u_long)atol(scan.next());
	}

    // Step commands are relayed by the monitor...
    MvmStepMsg dsm(context,flags);
    monitor->ifSend(mtype,&dsm,sizeof(dsm));
    // Now, let the simulation run and wait for
    // it to stop by itself when the step condition
    // is met...
    monitor->releaseSimulation();
}

void Debugger::tkBuildLocalInfo (const char *locals)

{
    TclListParser parser(locals);
    TclList display, _display;
    const char *def;

    while ((def = parser.next()) != NULL)
	{
	TclListParser _parser(def);
	const char *name = _parser.next();
	_display.set("native");
	_display.append(name);
	_display.append("local");
	_display.append(name);
	display.append(_display);
	}

    setTkResult("&L",&display);
}

void Debugger::tkSetDebugFilter (const char *filterString)

{
    int filter = 0;

    while (*filterString)
	{
	switch (*filterString++)
	    {
	    case '0':
		filter |= MVM_KTRACE;
		break;
	    case '1':
		filter |= MVM_ITRACE;
		break;
	    case '2':
		filter |= MVM_UTRACE;
		break;
	    }
	}

    MvmSetFilterMsg sfm(filter);
    monitor->ifSend(MVM_IFACE_DEBUG_SETFILTER,&sfm,sizeof(sfm));
}

int Debugger::getPipeOutDev ()

{
    pipeOutDev = tosh_mktemp(NULL,"pipe");

    if (mkfifo(pipeOutDev,0600) < 0)
	return -1;

    return 0;
}

void Debugger::cleanup ()

{
    if (!pipeOutDev.isVoid())
	unlink(pipeOutDev);
}
