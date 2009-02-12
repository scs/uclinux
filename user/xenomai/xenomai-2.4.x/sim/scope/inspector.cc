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
 * Description:  C++ part of the Xenoscope simulation inspector.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#include <xeno_config.h>
#include <stdlib.h>
#include "workspace.h"
#include "monitor.h"
#include "debugger.h"
#include "inspector.h"

#define ResetAll         1
#define CacheWindowIn    100
#define CacheWindowOut   101
#define InspectDashboard 102
#define GetOptionValue   103

CString Dashboard::formatBuf;

// Inspector - the object interfaces controller. This object
// holds the graphical counterparts of active simulation
// objects exporting a control interface.
// IMPORTANT NOTE: The inspector must still work without
// any help from the debugger object! However, it relies
// on the MONITOR object.

Inspector::Inspector (Workspace *_workspace,
		      Monitor *_monitor) :
    TkContext(_workspace)
{
    workspace = _workspace;
    monitor = _monitor;
    handleEvent("ResetAll",ResetAll);
    handleEvent("CacheWindowIn",CacheWindowIn);
    handleEvent("CacheWindowOut",CacheWindowOut);
    handleEvent("InspectDashboard",InspectDashboard);
    handleEvent("GetOptionValue",GetOptionValue);
    callTkProc("Inspector:initialize");
}

void Inspector::showUp (const char *autoDisplay)

{ callTkProc("Inspector:popup","&S",autoDisplay); }

const char *Inspector::getDashboardStatus (const char *objectPath)

{
    callTkProc("Inspector:getDashboardStatus","&S",objectPath); 
    return getTkStringResult();
}

void Inspector::notify (TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData)
{
    switch (event)
	{
	case ResetAll:

	    tkResetAll();
	    break;

	case CacheWindowIn:

	    workspace->cacheWindowIn(argv[1],argv[2]);
	    break;

	case CacheWindowOut:

	    workspace->cacheWindowOut(argv[1]);
	    break;

	case GetOptionValue:

	    tkGetOptionValue(argv[1]);
	    break;
	}
}

Dashboard *Inspector::createInterface (const MvmDashboardExportMsg *dem)

{
    TclListParser parser(dem->plugInfo);
    const char *tclPrefix = parser.next();
    const char *tclPrivate = parser.next();
    Dashboard *oi = new Dashboard(dem,tclPrefix,this);

    // Run the object's attachment proc. Tcl proc <prefix>:attach()
    // should return the new object description in a Tcl list (i.e
    // {{hierarchy} icon}) The "private" argument may be null as some
    // plug-ins may have no local information.

    if (oi->attach(dem->name,tclPrivate) > 0)
	// Declare the new object to the inspector.
	callTkProc("Inspector:addDashboard","&C &L &S",
		   (TkContext *)oi,
		   &oi->iconPath,
		   tclPrefix);
    return oi;
}

void Inspector::tkResetAll ()

{
    callTkProc("Inspector:reset");
    // Note: object removal in Dashboard dtor() will silently
    // lead to a null-effect as destroy() unlinks the object from the
    // list before calling its destructor.
    dashboards.destroy();
}

void Inspector::tkInspectDashboard (const char *objectPath)

{ callTkProc("Inspector:popup","&S",objectPath); }


void Inspector::tkGetOptionValue (const char *optName)

{
    workspace->callTkProc("Workspace:getOptionValue","&S",optName);
    setTkResult("&D",getTkIntResult());
}

// Dashboard - the graphical counterpart of simulation objects
// exporting a control interface. The graphical behavior for such
// object is obtained through an autonomous TCL/TK plugin. "plugInfo"
// parameter is composed as <subpath>/<prefix>/<private> where:
// * <subpath> is a sub-directory inside the CarbonKernel's Tcl repository,
// * <prefix> is a substring leading all procedures names for the object,
// * <private> is a private data list passed from the simulation object
//   to its graphical counterpart.

#define GetDashboardInfo   0
#define GetThreads         1
#define ConfigureDashboard 2
#define ReleaseSimulation  3
#define HoldSimulation     4
#define GetSimulationState 5
#define TriggerDashboard   6

Dashboard::Dashboard (const MvmDashboardExportMsg *_dem,
		      const char *_tclPrefix,
		      Inspector *_inspector) :
    MvmInterface(_dem,_inspector->getMonitor()),
    TkContext(_inspector)
{
    tclPrefix = _tclPrefix;
    inspector = _inspector;
    handleEvent("GetDashboardInfo",GetDashboardInfo);
    handleEvent("GetThreads",GetThreads);
    handleEvent("ConfigureDashboard",ConfigureDashboard);
    handleEvent("ReleaseSimulation",ReleaseSimulation);
    handleEvent("HoldSimulation",HoldSimulation);
    handleEvent("CacheWindowIn",CacheWindowIn);
    handleEvent("CacheWindowOut",CacheWindowOut);
    handleEvent("GetSimulationState",GetSimulationState);
    handleEvent("InspectDashboard",InspectDashboard);
    handleEvent("TriggerDashboard",TriggerDashboard);
    handleEvent("GetOptionValue",GetOptionValue);
    inspector->dashboards.append(this);
}

Dashboard::~Dashboard ()

{
    inspector->dashboards.remove(this);
    inspector->callTkProc("Inspector:removeDashboard","&C &L &S",
			  (TkContext *)this,
			  &iconPath,
			  (const char *)tclPrefix);
    callTkProc(getProcName("detach"));
}

int Dashboard::attach (const char *name,
			     const char *privateInfo)
{
    // PrivateInfo is guaranteed to be a TclList -- pass it as a raw
    // string to the formatter.
    callTkProc(getProcName("attach"),"&S &R",name,privateInfo,-1);
    return getTkListResult(iconPath);
}

void Dashboard::notify (TkEvent event,
			      int argc,
			      char *argv[],
			      TkClientData clientData)
{
    switch (event)
	{
	case GetDashboardInfo:

	    tkGetDashboardInfo(argv[1]);
	    break;

	case GetThreads:

	    tkGetThreads();
	    break;

	case ConfigureDashboard:

	    tkConfigureDashboard(argv[1]);
	    break;

	case ReleaseSimulation:

	    inspector->getMonitor()->releaseSimulation();
	    break;

	case HoldSimulation:

	    inspector->getMonitor()->holdSimulation();
	    break;

	case CacheWindowIn:

	    inspector->getWorkspace()->cacheWindowIn(argv[1],argv[2]);
	    break;

	case CacheWindowOut:

	    inspector->getWorkspace()->cacheWindowOut(argv[1]);
	    break;

	case GetSimulationState:

	    tkGetSimulationState();
	    break;

	case InspectDashboard:

	    inspector->tkInspectDashboard(argv[1]);
	    break;

	case TriggerDashboard:

	    tkTriggerDashboard(argv[1]);
	    break;

	case GetOptionValue:

	    inspector->tkGetOptionValue(argv[1]);
	    break;
	}
}

const char *Dashboard::getProcName (const char *method)

{
    return formatBuf.format("%s:%s",
			    (const char *)tclPrefix,
			    method);
}

void Dashboard::ifProcess (int mtype,
				 const MvmInterfaceMsg *gpm,
				 int msize)
{
    const MvmInterfaceInfoMsg *info =
	(const MvmInterfaceInfoMsg *)gpm;

    if (mtype == MVM_IFACE_DASHBOARD_INFO)
	// Pretend that data strings are always Tcl lists in this
	// context. So we do not need to translate them unlike we have
	// to do with "raw" outputs.
	callTkProc(getProcName("update"),
		   "&S &S",
		   ifGetName(),
		   info->data);
    else if (mtype == MVM_IFACE_DASHBOARD_OUTPUT)
	{
	const char *data = info->data;
	TclList dtkl, atkl;
	     
	// If the output string is prefixed by a special '@'
	// character, assume that an attribute terminated by another
	// '@' sign is following. This attribute is expected to be
	// understood by the target Tcl output proc exported by this
	// object.
	     
	if (*data == '@')
	    {
	    const char *attributes = ++data;

	    while (*data != '@')
		data++;

	    atkl.append(attributes,data - attributes);
	    data++;
	    }

	// Output buffer must be translated into a Tcl list to have
	// conflicting chars being quoted as needed (e.g. [], " and so
	// on).
	     
	dtkl.append(data,-1);

	callTkProc(getProcName("output"),
		   "&S &L &L",
		   ifGetName(),
		   &dtkl,
		   &atkl);
	}
}

void Dashboard::tkGetDashboardInfo (const char *query)

{
    // Request information about this object to the simulator through
    // the interface. This message will be directed to the proper
    // object exporting this control interface -- which is expected to
    // answer back within a short time through the same channel with
    // the same message identifier associated to meaningful data about
    // this object's current state.
    // (i.e. Dashboard::ifProcess() will process it).
    ifInfo(MVM_IFACE_DASHBOARD_INFO,query);
}

void Dashboard::tkGetThreads ()

{
    TclList tclist;
    inspector->getMonitor()->fetchThreads(tclist);
    setTkResult("&L",&tclist);
}

void Dashboard::tkConfigureDashboard (const char *settings)

{
    // Request an object reconfiguration to the simulator through the
    // interface. This message will be directed to the proper object
    // exporting this control interface.
    ifInfo(MVM_IFACE_DASHBOARD_CONFIGURE,settings);
}

void Dashboard::tkGetSimulationState ()

{
    inspector->getMonitor()->callTkProc("Monitor:getState");
    setTkResult("&S",getTkStringResult());
}

void Dashboard::tkTriggerDashboard (const char *arg)

{
    if (!arg) arg = "";
    ifInfo(MVM_IFACE_DASHBOARD_TRIGGER,arg);
}
