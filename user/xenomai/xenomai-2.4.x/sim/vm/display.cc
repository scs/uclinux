/*
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 2001,2002 Philippe Gerum.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <string.h>
#include <unistd.h>
#include "vm/monitor.h"
#include "vm/display.h"

MvmDashboard::MvmDashboard (const char *_name,
			    const char *_prefix,
			    const char *_privateInfo,
			    struct mvm_displayctx *_displayContext,
			    void (*_objCtlRoutine)(struct mvm_displayctx *ctx,
						   int op,
						   const char *arg)) :
    MvmInterface(_name,MvmMonitor::This,0)
{
    prefix = _prefix;
    privateInfo = _privateInfo;
    displayContext = _displayContext;
    objCtlRoutine = _objCtlRoutine;
}

void MvmDashboard::ifInit ()

{
    if (!prefix.isEmpty())
	{
	MvmDashboardExportMsg dem(ifGetName(),prefix,privateInfo);
	ifExport(&dem,sizeof(dem));
	}
}

void MvmDashboard::ifProcess (int mtype,
			      const MvmInterfaceMsg *gpm,
			      int msize)
{
    switch (mtype)
	{
	case MVM_IFACE_DASHBOARD_INFO:

	    dynamicExpose();
	    break;
		
	case MVM_IFACE_DASHBOARD_CONFIGURE:

	    dynamicConfigure((MvmInterfaceInfoMsg *)gpm);
	    break;

	case MVM_IFACE_DASHBOARD_TRIGGER:

	    dynamicTrigger((MvmInterfaceInfoMsg *)gpm);
	    break;

	default:

	    MvmInterface::ifProcess(mtype,gpm,msize);
	    break;
	}
}

MvmGraph::MvmGraph (const char *_name,
		    const char *_group,
		    const char *const *_sarray) :
    MvmObject(_name,_group,0,MvmMonitor::This)
{
    int nstates = 0;

    while (_sarray[nstates] != NULL)
	nstates++;

    defineStates(nstates,_sarray); // nstates may be zero
}

void MvmGraph::ifSignal (int signo)

{
    if (signo == MVM_IFACE_SIGBREAK)
	MvmMonitor::This->stopSimulation(MVM_STOP_GRAPH);
}
