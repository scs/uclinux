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
 * Description:  C++ part of the Xenoscope workspace.
 *
 * Author(s): rpm
 * Contributor(s): ym
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#include <xeno_config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "vmutils/toolshop.h"
#include "workspace.h"
#include "debugger.h"
#include "monitor.h"
#include "inspector.h"

Workspace *TheWorkspace = NULL;

#define CreateProject        1
#define OpenProject          2
#define CloseProject         3
#define HoldSimulation       4
#define ContSimulation       5
#define KillSimulation       6
#define InspectSimulation    7
#define VisitFile            8
#define DisplayPlotter       9
#define SetSimulationSpeed   10
#define AddTimer             11
#define SwitchTimer          12
#define KillTimer            13
#define GetVersionInfo       14
#define GetUserPath          15
#define CacheWindowIn        16
#define GetInspectorStatus   17
#define CanonicalizePath     18
#define DisplayErrorLog      19
#define EditBreakpoints      20
#define EditWatchpoints      21
#define SetTimeUnit          22

// Workspace -- the main object class implementing the user desktop
// actions. A workspace may be built in master mode, allowing a debug
// session to be started, projects to be created, changed and
// selected, or in slave mode, which only permits to monitor the
// simulation. The latter mode is dedicated for use along with an
// external debugger controlling the simulation process which in turn
// starts the Xenoscope to access the inspector and other monitoring
// tools.  Note: this ctor() must not refer to the configuration
// database which has not been attached yet, either directly or
// indirectly (through Tcl routines).

Workspace::Workspace (const char *_errorLogFile,
		      int _selfExitMode,
		      int _slavePort) :
    TkContext(NULL)
{
    selfExitMode = _selfExitMode;
    slavePort = _slavePort;
    lastRetMsgNum = 0;
    errorLogFile = _errorLogFile;

    handleEvent("HoldSimulation",HoldSimulation);
    handleEvent("ContSimulation",ContSimulation);
    handleEvent("InspectSimulation",InspectSimulation);
    handleEvent("VisitFile",VisitFile);
    handleEvent("DisplayPlotter",DisplayPlotter);
    handleEvent("CreateProject",CreateProject);
    handleEvent("OpenProject",OpenProject);
    handleEvent("CloseProject",CloseProject);
    handleEvent("KillSimulation",KillSimulation);
    handleEvent("SetSimulationSpeed",SetSimulationSpeed);
    handleEvent("AddTimer",AddTimer);
    handleEvent("SwitchTimer",SwitchTimer);
    handleEvent("KillTimer",KillTimer);
    handleEvent("GetVersionInfo",GetVersionInfo);
    handleEvent("GetUserPath",GetUserPath);
    handleEvent("CacheWindowIn",CacheWindowIn);
    handleEvent("GetInspectorStatus",GetInspectorStatus);
    handleEvent("CanonicalizePath",CanonicalizePath);
    handleEvent("DisplayErrorLog",DisplayErrorLog);
    handleEvent("EditBreakpoints",EditBreakpoints);
    handleEvent("EditWatchpoints",EditWatchpoints);
    handleEvent("SetTimeUnit",SetTimeUnit);

    callTkProc("Workspace:initialize","&D &S",
	       _selfExitMode,
	       _errorLogFile);

    monitor = new Monitor(this);
    inspector = new Inspector(this,monitor);

    if (slavePort < 0)
	debugger = new Debugger(this,monitor);
    else
	debugger = NULL;
}

void Workspace::cleanup ()

{
    if (!errorLogFile.isEmpty())
	unlink(errorLogFile);

    if (debugger)
	debugger->cleanup();
}

const char *Workspace::getErrorLog (CString& log)

{
    FILE *fp = fopen(errorLogFile,"r");

    // Send a portion of the log file, starting at message
    // #lastRetMsgNum to the tail of the log file. Only text lines
    // that start with the word "Xenoscope:" are counted as messages
    // in order to support multi-lines warnings/fatals.

    if (fp)
	{
	char buf[BUFSIZ];
	int msgNum = 0;

	while (fgets(buf,sizeof(buf),fp))
	    {
	    if (!strncmp(buf,"Xenoscope:",10))
		msgNum++;

	    if (msgNum > lastRetMsgNum)
		log += buf;
	    }

	lastRetMsgNum = msgNum;
	fclose(fp);
	}

    return log;
}

int Workspace::attachSimulation () {

    return monitor->attachSimulation(slavePort);
}

void Workspace::loadDebug () {
    
    callTkProc("Workspace:loadDebug");
}

void Workspace::loadSimulation () {
    
    callTkProc("Workspace:startSimulation");
}

void Workspace::cacheWindowIn (const char *window,
			       const char *label) {

    callTkProc("Workspace:cacheWindowIn","&S &S",window,label);
}

void Workspace::cacheWindowOut (const char *window) {

    callTkProc("Workspace:cacheWindowOut","&S",window);
}

// Workspace::releaseNotified() - simulation has been
// released by the monitor.

void Workspace::releaseNotified ()

{
    if (!Monitor::standaloneRun)
	debugger->callTkProc("Debugger:listen");
}

// Workspace::releaseNotified() - simulation has exited.

void Workspace::exitNotified ()

{
    lastRetMsgNum = 0;

    // Tje Xenoscope must exit immediately after the channel is closed
    // if asked to do so.

    if (doSelfExit())
	// Warning: do not bypass exit processing by calling _exit()
	// We need atexit() handlers to be fired here...
	exit(0);
}

void Workspace::notify (TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData)
{
    switch (event)
	{
	case HoldSimulation:

	    monitor->holdSimulation();
	    break;

	case ContSimulation:

	    monitor->releaseSimulation();
	    break;

	case KillSimulation:

	    tkKillSimulation();
	    break;

	case InspectSimulation:

	    tkInspectSimulation(argv[1]);
	    break;

	case GetInspectorStatus:

	    tkGetInspectorStatus(argc > 0 ? argv[1] : NULL);
	    break;

	case VisitFile:

	    tkVisitFile(argc > 0 ? argv[1] : NULL); // argv[1] may be null
	    break;

	case DisplayPlotter:

	    tkDisplayPlotter();
	    break;

	case SetSimulationSpeed:

	    monitor->setSpeed(atoi(argv[1]));
	    break;

	case AddTimer:
	case SwitchTimer:
	case KillTimer:

	    tkHandleTimer(event,argv[1],argc > 2 ? argv[2] : NULL);
	    break;

	case CacheWindowIn:

	    cacheWindowIn(argv[1],argv[2]);
	    break;

	case GetVersionInfo:

	    tkGetVersionInfo();
	    break;

	case GetUserPath:
	    
	    {
	    CString path(argv[1]);
	    TclList tclist(path.getAbbrevPath());
	    setTkResult("&L",&tclist);
	    break;
	    }

	case CanonicalizePath:

	    {
	    CString path(argv[1]);
	    TclList tclist(path.canonicalize());
	    setTkResult("&L",&tclist);
	    break;
	    }

	case DisplayErrorLog:

	    monitor->displayErrorLog();
	    break;

	case EditBreakpoints:

	    debugger->editBreakpoints();
	    break;

	case EditWatchpoints:

	    debugger->editWatchpoints();
	    break;

	case SetTimeUnit:

	    setDefaultETimeUnit(argv[1]);
	    break;
	}
}

void Workspace::printFile (const char *fileName) {

    callTkProc("Workspace:print","&S",
	       tosh_getcanonpath(fileName));
}

void Workspace::tkKillSimulation ()

{
    if (Monitor::standaloneRun)
	monitor->killSimulation();
    else
	debugger->tkStopDebug();
}

void Workspace::tkInspectSimulation (const char *autoDisplay) {

    inspector->showUp(autoDisplay);
}

void Workspace::tkGetInspectorStatus (const char *objectPath) {

    inspector->getDashboardStatus(objectPath);
}

void Workspace::tkDisplayPlotter () {

    monitor->showPlotter();
}

void Workspace::tkVisitFile (const char *fileName)

{
    if (debugger)
	debugger->callTkProc("Debugger:visitFile","&S",fileName);
}

void Workspace::tkHandleTimer (int op,
			       const char *texpr,
			       const char *type)
{
    ITime t;

    if (!t.scan(texpr))
	return; // invalid time expr.

    if (op == AddTimer)
	{
	monitor->addTimer(t,type && !!strcmp(type,"-absolute"));
	setTkResult("&G",t.getValAddr());
	}
    else if (op == KillTimer)
	monitor->killTimer(t);
    else if (op == SwitchTimer)
	monitor->switchTimer(t);
}

void Workspace::tkGetVersionInfo () {

    setTkResult("&S &S",MVM_VERSION_STRING,CONFIG_XENO_MVM_BUILD_STRING);
}

void fatal (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    fprintf(stderr,"Xenoscope: ");
    vfprintf(stderr,format,ap);
    fprintf(stderr,"\n");
    va_end(ap);
    exit(3);
}

void warning (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    fprintf(stderr,"Xenoscope: ");
    vfprintf(stderr,format,ap);
    fprintf(stderr,"\n");
    va_end(ap);
}
