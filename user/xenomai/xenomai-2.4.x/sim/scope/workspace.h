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
 * The original code is CarbonKernel - Real-time Operating System Simulator,
 * released April 15, 2000. The initial developer of the original code is
 * Realiant Systems (http://www.realiant.com).
 *
 * Description: Interface to the workspace class.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _workspace_h
#define _workspace_h
#include <time.h>
#include "vmutils/version.h"
#include "bridge.h"

class Debugger;
class Monitor;
class Inspector;

class Workspace : public TkContext {

protected:

    Debugger *debugger;

    Monitor *monitor;

    Inspector *inspector;

    int slavePort;

    CString errorLogFile;

    int lastRetMsgNum;

    int selfExitMode;

public:

    Workspace(const char *errorLogFile,
	      int selfExitMode,
	      int slavePort =-1);

    Inspector *getInspector() {
	return inspector;
    }

    Monitor *getMonitor() {
	return monitor;
    }

    void cacheWindowIn(const char *window,
		       const char *label);

    void cacheWindowOut(const char *window);

    void releaseNotified();

    void exitNotified();

    void printFile(const char *fileName);

    void cleanup();

    const char *getErrorLog(CString& log);

    int doSelfExit() const {
	return selfExitMode;
    }

    void loadDebug();

    void loadSimulation();

    int attachSimulation();

    // Tk routing

    void tkKillSimulation();

    void tkInspectSimulation(const char *autoDisplay);

    void tkGetInspectorStatus(const char *objecPath);

    void tkVisitFile(const char *fileName);

    void tkDisplayPlotter();

    void tkHandleTimer(int op,
		       const char *texpr,
		       const char *type);

    void tkGetVersionInfo();

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);
};

void fatal(const char *format, ...);

void warning(const char *format, ...);

extern Workspace *TheWorkspace;

#endif // !_workspace_h
