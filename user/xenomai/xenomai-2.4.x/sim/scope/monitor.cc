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
 * Description:  C++ part of the Xenoscope monitor.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#include <xeno_config.h>
#include <stdlib.h>
#include <signal.h>
#include "vmutils/toolshop.h"
#include "plotter.h"
#include "workspace.h"
#include "monitor.h"
#include "inspector.h"

int Monitor::standaloneRun = 0;

int Monitor::slaveMode = 0;

// IMPORTANT NOTE: the MONITOR must work without
// any help from the debugger object -- but it surely
// provides support to it!

#define RegisterChannel   0
#define UnregisterChannel 1
#define PollChannel       2
#define PollTime          3
#define CacheWindowIn     4

Monitor::Monitor (Workspace *_workspace) :
    TkContext(_workspace)
{
    ifSetConnector(this);
    workspace = _workspace;
    tcpChannel = NULL;
    plotter = NULL;
    slaveMode = 0;
    simIsRunning = 0;
    prefetchBuf = new char[POLL_PREFETCH_BUFSIZE];
    handleEvent("RegisterChannel",RegisterChannel);
    handleEvent("UnregisterChannel",UnregisterChannel);
    handleEvent("PollChannel",PollChannel);
    handleEvent("PollTime",PollTime);
    handleEvent("CacheWindowIn",CacheWindowIn);
    linkTkVar("Monitor:standaloneRun",&standaloneRun);
    linkTkVar("Monitor:slaveMode",&slaveMode);
    callTkProc("Monitor:initialize");
}

Monitor::~Monitor ()

{
    if (tcpChannel)
	delete tcpChannel;

    delete[] prefetchBuf;
}

void Monitor::notify (TkEvent event,
		      int argc,
		      char *argv[],
		      TkClientData clientData)
{
    switch (event)
	{
	case RegisterChannel:

	    tkRegisterChannel(argv[1]);
	    break;

	case UnregisterChannel:

	    tkUnregisterChannel();
	    break;

	case PollChannel:

	    tkPollChannel();
	    break;

	case PollTime:

	    tkPollTime();
	    break;

	case CacheWindowIn:

	    workspace->cacheWindowIn(argv[1],argv[2]);
	    break;
	}
}

int Monitor::attachSimulation (int slavePort)

{
    slaveMode = 1;
    // Prevent from being interrupted when the user
    // depresses ^C in the debugger termal zone for
    // instance.
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,&sa,NULL);
    callTkProc("Monitor:attachSimulation","&D",slavePort);
    return getTkIntResult();
}

void Monitor::killSimulation () {

    callTkProc("Monitor:tcpDown");
}
			       
void Monitor::setSpeed (int value)

{
    MvmSetSpeedMsg sm;
    sm.speed = value;
    ifSend(MVM_IFACE_MONITOR_SET_SPEED,&sm,sizeof(sm));
}

void Monitor::displayErrorLog () {

    callTkProc("Monitor:displayErrorLog");
}

// Monitor::tkRegisterChannel() fetches the O/S handle associated
// to the socket connected to the client simulation process.
// This handle will be used to perform binary I/O from
// the C++ interface. However, the notification stuff is left to
// TCL through its "fileevent" facility.
// The statistic objects plotter is built and destroyed along
// with the channel.

void Monitor::tkRegisterChannel (const char *tclName)

{
    tcpChannel = new TkChannel(tclName);
    plotter = new StatPlotter(this);
}

// Monitor::tkUnregisterChannel() close the current TCP
// end-point.

void Monitor::tkUnregisterChannel ()

{
    if (tcpChannel)
	{
	delete tcpChannel;
	tcpChannel = NULL;
	delete plotter;
	plotter = NULL;
	threadList.destroy();
	workspace->exitNotified();
	}
}

// Monitor::tkPollChannel() is called from the TCL code to process the
// incoming messages from the registered socket each time any
// available input is detected on the client connection.

void Monitor::tkPollChannel ()

{
    int mid, msize;
    void *mbuf;

    // The notifier is released each 64 messages to
    // allow user interaction -- from times to times :-)
    
    for (int loop = 0; loop < 64; loop++)
	{
	mid = tcpChannel->poll(&mbuf,&msize);

	if (mid == Tkio_wouldblock)
	    return;

	if (mid == Tkio_linkdown)
	    {
	    childDeath();
	    return;
	    }

	// Optimize time-graphs and state-diagrams drawing using
	// a prefetch of point updates on the channel --
	
	if (mid == MVM_IFACE_TIMEGRAPH_POINT ||
	    mid == MVM_IFACE_SDIAGRAM_POINT)
	    {
	    int fetchMax = POLL_PREFETCH_BUFSIZE / msize;
	    int pmid = mid, psize = 0, usize = msize;

	    do
		{
		memcpy(prefetchBuf + psize,mbuf,msize);
		psize += msize;
		mid = tcpChannel->poll(&mbuf,&msize);
		}
	    while (--fetchMax > 0 && mid == pmid);

	    qsort(prefetchBuf,psize / usize,usize,&sortPrefetch);

	    dispatch(pmid,(const MvmInterfaceMsg *)prefetchBuf,psize);

	    if (mid == Tkio_wouldblock)
		return;

	    if (mid == Tkio_linkdown)
		{
		childDeath();
		return;
		}
	    }

	dispatch(mid,(const MvmInterfaceMsg *)mbuf,msize);
	}
}

int Monitor::sortPrefetch (const void *e1, const void *e2)

{
    // Sort messages in the prefetching buffer according
    // to their destination handles... Keep arrival order
    // of messages of same type by testing on the sequence
    // number.
    MvmInterfaceMsg *m1 = (MvmInterfaceMsg *)e1;
    MvmInterfaceMsg *m2 = (MvmInterfaceMsg *)e2;

    if (m1->handle != m2->handle)
	return m1->handle < m2->handle ? -1 : 1;

    return m1->seqNum < m2->seqNum ? -1 : 1;
}

int Monitor::dispatch (int mtype, const void *mbuf, int msize)

{
    int done;

    if (!mbuf || msize == 0)
	{
	// bodyless messages are assumed to be directed to the
	// monitor object...
	ifProcess(mtype,NULL,0);
	done = 1;
	}
    else
	{
	done = MvmFrontend::dispatch(mtype,mbuf,msize);

	if (!done)
	    done = plotter->dispatch(mtype,mbuf,msize);
	}

    return done;
}

// Monitor:tkPollTime() is indirectly invoked by TCL
// on a periodical time basis to send a time information
// request to the simulator. A MVM_IFACE_MONITOR_TIME
// message is expected back through the channel along with
// the current simulated time at the moment the initial
// message has been processed.

void Monitor::tkPollTime ()

{ ifSend(MVM_IFACE_MONITOR_TIME); }

void Monitor::send (int mtype, MvmInterfaceMsg *gpm, int msize)

{
    // On behalf of a few -but regular- contexts, we may be called
    // after the channel has been deactivated -- this case is trapped
    // here to prevent exception cases to be defined elsewhere.
    if (tcpChannel)
	tcpChannel->send(mtype,gpm,msize);
}

MvmInterface *Monitor::createDisplay (const MvmInterfaceExportMsg *gpex,
				      int msize)
{
    MvmInterface *object = NULL;

    switch (gpex->type)
	{
	case MVM_IFACE_MONITOR_ID:

	    // This object is actually the graphical counterpart of
	    // the simulation monitor. Subsequent messages sent on
	    // this protocol channel will be dispatched to the
	    // Monitor::ifProcess() callback. The monitor is also
	    // its own front-end pilot. From now, object exports may
	    // take place...

	    return this;

	case MVM_IFACE_THREAD_ID:

	    {
	    const MvmThreadExportMsg *tem;
	    tem = (const MvmThreadExportMsg *)gpex;
	    ThreadDescriptor *tdesc = new ThreadDescriptor(this,tem);
	    threadList.append(tdesc);
	    callTkProc("Monitor:registerThread","&U &S",
		       tem->threadID,
		       tem->name);
	    object = tdesc;
	    break;
	    }

	case MVM_IFACE_DASHBOARD_ID:

	    {
	    const MvmDashboardExportMsg *dem;
	    dem = (const MvmDashboardExportMsg *)gpex;
	    object = workspace->getInspector()->createInterface(dem);
	    break;
	    }
	}
    
    return object;
}

void Monitor::destroyDisplay (MvmInterface *object)

{
    int objectType = object->ifGetType();

    if (objectType == MVM_IFACE_DASHBOARD_ID)
	{
	delete object;
	return;
	}

    // Threads are special objects -- each thread deletion
    // must be broadcast as an application global event.
    
    if (objectType == MVM_IFACE_THREAD_ID)
	{
	ThreadDescriptor *tdesc = (ThreadDescriptor *)object;

	threadList.remove(tdesc);

	callTkProc("Monitor:unregisterThread","&U &S",
		   tdesc->info.threadID,
		   tdesc->info.name);

	delete object;
	}
}

void Monitor::ifProcess (int mtype,
			 const MvmInterfaceMsg *mbuf,
			 int msize)
{
    switch (mtype)
	{
	case MVM_IFACE_MONITOR_COLD:

	    {
	    MvmSystemInfoMsg *sim = (MvmSystemInfoMsg *)mbuf;
	    sysinfo = *sim;
	    callTkProc("Monitor:coldNotified");
	    break;
	    }

	case MVM_IFACE_MONITOR_WARM:

	    {
	    MvmWarmStateMsg *dwm = (MvmWarmStateMsg *)mbuf;
	    callTkProc("Monitor:warmNotified","&D",dwm->fatalCount);
	    break;
	    }
	
	case MVM_IFACE_MONITOR_READY:

	    {
	    callTkProc("Monitor:readyNotified");
	    ifSend(MVM_IFACE_MONITOR_READY); // ack
	    break;
	    }

	case MVM_IFACE_MONITOR_HELD:

	    {
	    simIsRunning = 0;
	    MvmHoldMsg *shm = (MvmHoldMsg *)mbuf;
	    plotter->holdNotified();
	    callTkProc("Monitor:holdNotified","&D",shm->stopCondition);
	    break;
	    }

	case MVM_IFACE_MONITOR_FINISHED:

	    callTkProc("Monitor:finishNotified");
	    break;

	case MVM_IFACE_MONITOR_TIME:

	    {
	    lastTimeStamp = PDATA(mbuf,MvmTimeMsg)->time;
	    plotter->timeNotified(lastTimeStamp);
	    callTkProc("Monitor:timeNotified","&S",lastTimeStamp.format());
	    break;
	    }

	case MVM_IFACE_ERRLOG_UPDATE:

	    {
	    CString log;
	    TclList tclist(workspace->getErrorLog(log));
	    callTkProc("Monitor:errorNotified","&L",&tclist);
	    break;
	    }

	case MVM_IFACE_RESUME_REQUEST:

	    releaseSimulation();
	    break;
	}
}

// Monitor::fetchThreads() returns a list of known threads; the
// returned list looks like this:
// { {threadID threadName threadEntry} ... }

void Monitor::fetchThreads (TclList& tclist)

{
    ThreadDescriptorIterator it(threadList);
    ThreadDescriptor *tdesc;

    while ((tdesc = it.next()) != NULL)
	{
	TclList _tclist;
	_tclist.append(tdesc->info.threadID);
	_tclist.append(tdesc->info.name);
	_tclist.append(tdesc->info.threadEntry);
	tclist.append(_tclist);
	}
}

void Monitor::fetchSpecs (TclList& tclist)

{
    TclList _tclist;
    _tclist.set(sysinfo.threadTypeName);
    tclist.append(_tclist);
}

void Monitor::showPlotter () {
    plotter->popup();
}

void Monitor::releaseSimulation ()

{
    simIsRunning = 1;
    ifSend(MVM_IFACE_MONITOR_CONTINUE);
    plotter->releaseNotified();
    callTkProc("Monitor:releaseNotified");
    workspace->releaseNotified();
}

void Monitor::holdSimulation ()

{ ifSend(MVM_IFACE_MONITOR_STOP); }

void Monitor::addTimer (ITime& t, int isRelative)

{
    MvmTimeMsg tsm;
    if (isRelative) t += lastTimeStamp;
    tsm.time = t;
    ifSend(MVM_IFACE_TIMER_ADD,&tsm,sizeof(tsm));
}

void Monitor::killTimer (ITime t)

{
    MvmTimeMsg tsm;
    tsm.time = t;
    ifSend(MVM_IFACE_TIMER_KILL,&tsm,sizeof(tsm));
}

void Monitor::switchTimer (ITime t)

{
    MvmTimeMsg tsm;
    tsm.time = t;
    ifSend(MVM_IFACE_TIMER_SWITCH,&tsm,sizeof(tsm));
}

void Monitor::childDeath ()

{ callTkProc("Monitor:childDeath"); }

// ThreadDescriptor - a class holding thread information
// exported by the simulation process.

ThreadDescriptor::ThreadDescriptor (Monitor *_monitor,
				    const MvmThreadExportMsg *_tem) :
    MvmInterface(_tem,_monitor),
    info(*_tem)
{}

// StatPlotter - the simulation statistics plotter, displaying
// object state diagrams, histograms and numerous curves exported
// by the simulator.

#define ReleaseBackend   200	// not to conflict with
#define HoldBackend      201	// TkPlotterFrame events
#define StartDisplay     202
#define GetTempFile      203
#define PrintFile        204
#define GetBackendState  205

StatPlotter::StatPlotter (Monitor *_monitor) :
    TkPlotterFrame("Execution Graphs",
		   CString().format("Xenoscope %s",
				    MVM_VERSION_STRING))
{
    monitor = _monitor;

    handleEvent("ReleaseBackend",ReleaseBackend);
    handleEvent("HoldBackend",HoldBackend);
    handleEvent("StartDisplay",StartDisplay);
    handleEvent("GetTempFile",GetTempFile);
    handleEvent("PrintFile",PrintFile);
    handleEvent("GetBackendState",GetBackendState);
    
    TkPlotterSettings sdSettings;
    timePlotter = addTimeCurvePlotter("State diagrams",
				      sdSettings);
}

// The plotter owns the objects it plots. Thus,
// destroy the statistic objects when the plotter
// is destroyed.

StatPlotter::~StatPlotter ()

{
    trySaveSession();
    objects.destroy();
}

// StatPlotter::send() relays the plotter requests to
// the simulation through the monitor's channel.

void StatPlotter::send (int mtype, MvmInterfaceMsg *gpm, int msize)

{ monitor->send(mtype,gpm,msize); }

MvmInterface *StatPlotter::createDisplay (const MvmInterfaceExportMsg *gpex,
					  int msize)
{
    MvmInterface *object = TkPlotterFrame::createDisplay(gpex,msize);

    if (object)
	objects.append(object);

    return object;
}

int StatPlotter::dispatch (int mtype, const void *mbuf, int msize)

{
    if (mtype != MVM_IFACE_SDIAGRAM_POINT &&
	mtype != MVM_IFACE_TIMEGRAPH_POINT)
	return TkPlotterFrame::dispatch(mtype,mbuf,msize);
    
    // "mbuf" contents are sorted according to the destination
    // objects -- the "mbuf" area looks like this:
    // <pointMsg{handle=h1}> x n1 (bundle for h1, n1 msgs)
    // <pointMsg{handle=h2}> x n2 (bundle for h2, n2 msgs)
    // <pointMsg{handle=hn}> x nn (bundle for hn, nn msgs)
    // -- thus we just need to call the right object in turn
    // for the message bundle it has just received.
    
    int usize;

    if (mtype == MVM_IFACE_TIMEGRAPH_POINT)
	usize = sizeof(MvmTimeGraphPointMsg);
    else
	usize = sizeof(MvmStateDiagramPointMsg);

    const char *prefetchBuf = (const char *)mbuf;
    MvmInterfaceMsg *hgpm = (MvmInterfaceMsg *)mbuf;
    int done = 0;
    int nmsg = msize / usize;
    
    do
	{
	prefetchBuf += usize;
	MvmInterfaceMsg *gpm = (MvmInterfaceMsg *)prefetchBuf;
	
	if (--nmsg <= 0 || hgpm->handle != gpm->handle)
	    {
	    MvmInterface *object = (MvmInterface *)handles.find(hgpm->handle);

	    if (object)
		{
		object->ifProcess(mtype,hgpm,prefetchBuf - (char *)hgpm);
		done = 1;
		}

	    hgpm = gpm;
	    }
	}
    while (nmsg > 0);

    return done;
}

ITime StatPlotter::getCurrentTime () const {

    return monitor->getCurrentTime();
}

void StatPlotter::notify (TkEvent event,
			  int argc,
			  char *argv[],
			  TkClientData clientData)
{
    switch (event)
	{
	case ReleaseBackend:

	    monitor->releaseSimulation();
	    break;

	case HoldBackend:

	    monitor->holdSimulation();
	    break;

	case StartDisplay:
		
	    monitor->getWorkspace()->cacheWindowIn(getTkName(),"Graphs");
	    break;

	case GetTempFile:

	    setTkResult("&S",tosh_mktemp(NULL,"plot"));
	    break;

	case PrintFile:

	    monitor->getWorkspace()->printFile(argv[1]);
	    break;

	case GetBackendState:

	    setTkResult("&S",
			monitor->isSimulatorRunning()
			? "running" : "idle");
	    break;

	default:

	    // Message won't be processed at this level;
	    // forward it to the generic frame object.
	    TkPlotterFrame::notify(event,argc,argv,clientData);
	    break;
	}
}
