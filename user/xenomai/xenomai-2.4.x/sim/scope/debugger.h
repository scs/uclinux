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
 * Description: Interface to the Debugger class.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _debugger_h
#define _debugger_h
#include "bridge.h"

class Workspace;
class Monitor;

class Debugger : public TkContext {

protected:

    Workspace *workspace;

    Monitor *monitor;

    CString pipeOutDev;

    int getPipeOutDev();

public:

    static char *wantedGdbPath;

    Debugger(Workspace *workspace,
	     Monitor *monitor);

    virtual ~Debugger();

    void editBreakpoints();

    void editWatchpoints();

    void cleanup();

    // Tk routing

    void tkStopDebug();

    void tkGetSpecs();

    void tkGetThreads();

    void tkGetCtlCode(const char *codeString,
		      const char *scopeString);

    void tkStep(TclList focus, int mtype);

    void tkSetDebugFilter(const char *filterString);

    void tkBuildLocalInfo(const char *locals);

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);
};

#endif // !_debugger_h
