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
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include "vm/monitor.h"
#include "vm/manager.h"
#include "vm/trace.h"

CString MvmMonitor::currentFocus;

MvmMonitor *MvmMonitor::This = NULL;

MvmMonitor::MvmMonitor (MvmPipe *_tcpChannel) :
    MvmThread("MvmMonitor",MVM_IFACE_HIDDEN,16384)
{
    tcpChannel = _tcpChannel;
    stopCondition = MVM_STOP_USER;
    ifSetConnector(this);
    // Simulation will run until the first instrumented
    // source statement is reached.
    setRunMode(Running);
    exportFocus("init 0 0 0 0");
    prioritize(1);
}

void MvmMonitor::ifInit ()

{
    // Ask the monitor to create a graphical counterpart
    // to the dialog manager.
    MvmMonitorExportMsg dpex(ifGetName(),MvmManager::execTime);
    ifExport(&dpex,sizeof(dpex));
}

void MvmMonitor::ifProcess (int mtype,
			    const MvmInterfaceMsg *mbuf,
			    int msize)
{
    if (mtype == MVM_IFACE_MONITOR_QUIT)
	exit(0);

    if (MvmManager::fDone)
	return;

    // Note: the hog manager is disabled during single-stepping,
    // and re-enabled when the simulation stops (whatever
    // stop condition was met).

    switch (mtype)
	{
	case MVM_IFACE_MONITOR_STOP :

	    stopSimulation(MVM_STOP_USER);
	    return;

	case MVM_IFACE_MONITOR_CONTINUE :

	    setRunMode(Running);
	    return;

	case MVM_IFACE_DEBUG_STEPOVER :

	    dbStepOver((MvmStepMsg *)mbuf);
	    MvmHog::This->disable();
	    return;
	
	case MVM_IFACE_DEBUG_STEPINTO :

	    dbStepInto((MvmStepMsg *)mbuf);
	    MvmHog::This->disable();
	    return;

	case MVM_IFACE_DEBUG_STEPOUT :

	    dbStepOut((MvmStepMsg *)mbuf);
	    MvmHog::This->disable();
	    return;

	case MVM_IFACE_MONITOR_SET_SPEED :

	    {
	    MvmSetSpeedMsg *ssm = (MvmSetSpeedMsg *)mbuf;

	    if (ssm->speed > 0) // 0 is invalid
		MvmHog::This->setHogFactor(MVM_IFACE_FULLSPEED - ssm->speed);

	    break;
	    }

	case MVM_IFACE_MONITOR_TIME :

	    sendSimulatedTime();
	    break;

	case MVM_IFACE_TIMER_ADD:
	case MVM_IFACE_TIMER_KILL:
	case MVM_IFACE_TIMER_SWITCH:

	    {
	    MvmTimeMsg *tsm = (MvmTimeMsg *)mbuf;
	    handleTimerOp(mtype,tsm->time);
	    break;
	    }

	case MVM_IFACE_DEBUG_SETFILTER:

	    {
	    MvmSetFilterMsg *sfm = (MvmSetFilterMsg *)mbuf;
	    MvmManager::This->setDebugFilter(sfm->filter);
	    break;
	    }
	}
}

void MvmMonitor::body ()

{
    // register this thread for I/O notification
    MvmThread::runChain.addCallout(tcpChannel,this);

    // inform the monitor that we've reached the warm state
    MvmWarmStateMsg dwm(MvmManager::This->getFatalCount(),
		      MvmManager::This->getWarningCount());

    ifSend(MVM_IFACE_MONITOR_WARM,&dwm,sizeof(dwm));

    // Export interface objects created during the initialization
    // phase.

    MvmInterfaceIterator itp(MvmConnector::allInterfaces);
    MvmInterface *iface;

    while ((iface = itp.next()) != NULL)
	{
	if (iface->ifIsExportable() && !iface->ifIsExported())
	    {
	    iface->ifSetConnector(this);
	    iface->ifInit();
	    }
	}

    // very end of the initialization phase
    notifyReadyState();

    // enter main loop
    int mid, msize;
    void *mbuf;

    for (;;)
	{
	if (runMode != Running)
	    {
	    MvmHoldMsg shm;
	    shm.stopCondition = stopCondition;
	    ifSend(MVM_IFACE_MONITOR_HELD,&shm,sizeof(shm));
	    holdSimulation();
	    continue;
	    }

	mid = tcpChannel->poll(&mbuf,&msize);

	if (mid == MVM_PIPE_WOULDBLOCK)
	    {
	    // Suspend until scheduler detects any input pending
	    // on the Xenoscope channel.
	    suspend();
	    continue;
	    }
	
	if (mid == MVM_PIPE_LINKDOWN)
	    exit(0);

	dispatch(mid,(const MvmInterfaceMsg *)mbuf,msize);
	}
}

void MvmMonitor::notifyColdInitOk ()

{
    MvmSystemInfoMsg sim;	// FIXME

    strcpy(sim.osName,"xenomai");
    strcpy(sim.threadTypeName,"thread");

    ifSend(MVM_IFACE_MONITOR_COLD,&sim,sizeof(sim));
}

void MvmMonitor::notifyReadyState ()

{
    ifSend(MVM_IFACE_MONITOR_READY);

    // Wait for an explicit ack from the front-end

    for (;;)
	{
	void *mbuf;
	int msize;

	int mid = tcpChannel->recv(&mbuf,&msize);

	if (mid == MVM_PIPE_LINKDOWN)
	    exit(0);

	if (mid == MVM_IFACE_MONITOR_READY)
	    break;

	dispatch(mid,(const MvmInterfaceMsg *)mbuf,msize);
	}

    MvmManager::This->finishPreamble();
}

// MvmMonitor::stopSimulation() awakes the monitor making it entering
// a held state. This state is applied by
// MvmMonitor::holdSimulation(). This method should be called by any
// thread requesting the monitor to block the simulation. The
// front-end then gets informed of the held state.

void MvmMonitor::stopSimulation (int _stopCondition)

{
    if (runMode != Stopped)
	{
	stopCondition = _stopCondition;
	setRunMode(Stopped);
	immediateResume();
	}
}

void MvmMonitor::contSimulation () {

    setRunMode(Running);
}

void MvmMonitor::holdSimulation ()

{
    sendSimulatedTime();

    MvmTraceManager::This->clrTracing();
    
    if (MvmManager::This->testFlags(MVM_TRACED))
	{
	MvmHog::This->enable();
	allXenoThreads.apply(&XenoThread::cancelStep);
	exportFocus(MvmManager::This->getContextString());
	MvmManager::breakpoint();
	}

    int msize, mid;
    void *mbuf;
    
    while (runMode == Stopped)
	{
	mid = tcpChannel->recv(&mbuf,&msize);

	if (mid == MVM_PIPE_LINKDOWN)
	    MvmManager::This->finish(0);

	dispatch(mid,(const MvmInterfaceMsg *)mbuf,msize);

	if (mid == MVM_IFACE_MONITOR_STOP)
	    break;
	}
}

void MvmMonitor::send (int mid, MvmInterfaceMsg *gpm, int msize) {
    tcpChannel->send(mid,gpm,msize);
}

void MvmMonitor::sendSimulatedTime ()

{
    MvmTimeMsg tm;
    tm.time = MvmClock;
    ifSend(MVM_IFACE_MONITOR_TIME,&tm,sizeof(tm));
}

void MvmMonitor::terminate ()

{
    ifSend(MVM_IFACE_MONITOR_FINISHED);
    setRunMode(Stopped);
    for (;;) holdSimulation();
}

void MvmMonitor::setRunMode (MvmRunMode mode)

{ runMode = mode; }

void MvmMonitor::handleTimerOp (int op, ITime time)

{
    ITime dt = time - MvmClock;
    
    if (dt <= ZEROTIME)
	// silently ignore preposterous requests
	return;
    
    MvmTimerIterator it(timers);
    MvmTimer *timer;

    // first of all, search for an existing timer
    // having the same scheduling time than the
    // argument one.
    
    while ((timer = it.next()) != NULL)
	{
	if (timer->getTime() == time)
	    break;
	}

    if (timer)
	{
	switch (op)
	    {
	    case MVM_IFACE_TIMER_KILL:
	    
	    	timers.remove(timer);
		delete timer;
		break;

	    case MVM_IFACE_TIMER_SWITCH:
		
		if (timer->getState() == ARMED)
		    // timer was armed -- deactivate it.
		    timer->reset();
		else
		    // timer was idle or disarmed -- activate it.
		    timer->set(dt);
		
		break;

	    case MVM_IFACE_TIMER_ADD:
		
	    	// duplicate timer -- ensure the pre-existing one
		// is active.

		if (timer->getState() != ARMED)
		    timer->set(dt);
		
	    	break;
	    }
	}
    else if (op == MVM_IFACE_TIMER_ADD)
	{
	// Timer must be found for operations other than ADD
	// (i.e. SWITCH or KILL). If not, just ignore the request.
	// Otherwise, create a new timer which will fire the
	// MvmMonitor::timeout() method when it expires. If the
	// activation time is zero, an idle timer is created which
	// will need to be switched on by a later SWITCH operation
	// (using ZEROTIME as a special case is harmless as a
	// blocked state is always enforced by the front-end at
	// the beginning of the simulation process --
	// i.e. MvmClock == ZEROTIME -- thus, specifying a
	// zero-scheduled timer never makes sense).

	if (time == ZEROTIME)
	    // create an idle timer
	    timers.append(new MvmTimer(NULL,this));
	else
	    // create an active timer
	    timers.append(new MvmTimer(NULL,dt,this));
	}
}

void MvmMonitor::timeout (MvmTimer *timer)

{
    timers.remove(timer);
    delete timer;
    stopSimulation(MVM_STOP_TIMER);
}

// MvmMonitor::dbStepOver() plans for the simulation to step
// over the next instruction for the designated context then stop.

void MvmMonitor::dbStepOver (MvmStepMsg *dsm) {

    applyContext(dsm->context,
		 dsm->flags,
		 &XenoThread::stepOver);
}

// MvmMonitor::dbStepInto() plans for the simulation to step
// into the next instruction for the designated context then stop.

void MvmMonitor::dbStepInto (MvmStepMsg *dsm) {

    applyContext(dsm->context,
		 dsm->flags,
		 &XenoThread::stepInto);
}

// MvmMonitor::dbStepOver() plans for the simulation to step
// out the current function executed by the selected context
// then stop.

void MvmMonitor::dbStepOut (MvmStepMsg *dsm)

{
    XenoThread *thread;

    if (dsm->context.type == XSystemContext)
	thread = MvmManager::This->getRunningThread();
    else
	thread = MvmManager::This->findThread(dsm->context); // Never NULL.
    
    thread->stepOut();
}

// MvmMonitor::applyContext() applies a member function to a set of
// simulation threads, selected on a given focus. "System" focus
// applies the function to all known threads. "Thread" focus applies
// the function only to the designated thread.

void MvmMonitor::applyContext (MvmContext context,
			       int flags,
			       void (XenoThread::*mf)(int))
{
    XenoThread *thread;
    
    if (context.type == XSystemContext)
	{
	XenoThreadIterator it(allXenoThreads);

	while ((thread = it.next()) != NULL)
	    (thread->*mf)(flags);
	}
    else
	{
	thread = MvmManager::This->findThread(context);
	(thread->*mf)(flags);
	}
}

void MvmMonitor::exportFocus (const char *focus)

{
    currentFocus = focus;
    MVM_CR_FOCUS = currentFocus;
}
