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
 * Description: Interface to the Inspector class.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _inspector_h
#define _inspector_h

#include "bridge.h"

class Monitor;
class Inspector;
class Workspace;
class MvmDashboardExportMsg;

class Dashboard : public MvmInterface, public TkContext {

    friend class Inspector;

protected:

    Inspector *inspector;

    CString tclPrefix;

    TclList iconPath;

    const char *getProcName(const char *method);

    static CString formatBuf;

    int attach(const char *name,
	       const char *privateInfo);
public:

    Dashboard(const MvmDashboardExportMsg *dem,
	      const char *tclPrefix,
	      Inspector *inspector);

    virtual ~Dashboard();

    const char *getPrefix() const {
	return tclPrefix;
    }

    void tkGetDashboardInfo(const char *query);

    void tkConfigureDashboard(const char *settings);

    void tkGetThreads();

    void tkReleaseSimulation();

    void tkHoldSimulation();

    void tkGetSimulationState();

    void tkTriggerDashboard(const char *arg);

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *gpm,
			   int msize);
};

MakeGList(Dashboard);

class Inspector : public TkContext {

    friend class Dashboard;

protected:

    Workspace *workspace;
    Monitor *monitor;
    DashboardGList dashboards;

public:

    Inspector(Workspace *workspace,
	      Monitor *monitor);

    Monitor *getMonitor() {
	return monitor;
    }

    Workspace *getWorkspace() {
	return workspace;
    }

    void showUp(const char *autoDisplay);

    void tkResetAll();

    void tkInspectDashboard(const char *objectPath);

    void tkGetOptionValue(const char *optName);

    const char *getDashboardStatus(const char *objectPath);

    Dashboard *createInterface(const MvmDashboardExportMsg *dem);

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);
};

#endif // !_inspector_h
