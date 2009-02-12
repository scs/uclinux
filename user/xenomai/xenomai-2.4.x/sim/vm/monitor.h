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
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvm_monitor_h
#define _mvm_monitor_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/clock.h"
#include "vmutils/interface.h"
#include "vm/thread.h"
#include "vm/timer.h"
#include "vm/daemon.h"
#include "vm/flag.h"
#include "vm/queue.h"
#include "vm/pipe.h"

class MvmTimer;

class MvmMonitor : public MvmThread, public MvmBackend {

protected:

    enum MvmRunMode {
	Running,
	Stopped
    };

    MvmPipe *tcpChannel;

    MvmRunMode runMode;

    int stopCondition;

    MvmTimerGList timers;

    void setRunMode(MvmRunMode mode);

    void sendSimulatedTime();

    void handleTimerOp(int op,
		       ITime time);

    virtual void timeout(MvmTimer *timer);

    virtual void body();

    void dbStepOver(MvmStepMsg *dsm);

    void dbStepInto(MvmStepMsg *dsm);

    void dbStepOut(MvmStepMsg *dsm);

    static void applyContext(MvmContext context,
			     int flags,
			     void (XenoThread::*mf)(int));

public:

    static MvmMonitor *This;

    static CString currentFocus;

    static void exportFocus(const char *focus);

    MvmMonitor(MvmPipe *tcpChannel);

    virtual void ifInit();

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *mbuf,
			   int msize);

    virtual void send(int mtype,
		      MvmInterfaceMsg *gpm =0,
		      int msize =0);

    void contSimulation();

    void stopSimulation(int stopCondition);

    void holdSimulation();

    void terminate();

    void notifyColdInitOk();

    void notifyReadyState();
};

#endif // !_mvm_monitor_h
