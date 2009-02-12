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
 * Description: Interface to the monitor class.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _monitor_h
#define _monitor_h
#include "vmutils/object.h"
#include "plotter.h"

#define POLL_PREFETCH_BUFSIZE 1024

class Workspace;
class Monitor;
class StatPlotter;

struct ThreadDescriptor : public MvmInterface {

    MvmThreadExportMsg info;

    ThreadDescriptor (Monitor *monitor,
		      const MvmThreadExportMsg *tem);
};

MakeGList(ThreadDescriptor);

class Monitor : public TkContext,
		public MvmInterface,
                public MvmFrontend {

		protected:

    Workspace *workspace;

    TkChannel *tcpChannel;

    ThreadDescriptorGList threadList;

    StatPlotter *plotter;

    char *prefetchBuf;

    ITime lastTimeStamp;

    int simIsRunning;

    MvmSystemInfoMsg sysinfo;

    static int sortPrefetch(const void *e1,
			    const void *e2);

    void childDeath();

		public:

    Monitor(Workspace *workspace);

    virtual ~Monitor();

    static int standaloneRun;

    static int slaveMode;

    void fetchSpecs(TclList& tkl);

    void fetchThreads(TclList& tkl);

    Workspace *getWorkspace() {
    	return workspace;
    }

    int attachSimulation(int slavePort);

    void killSimulation();
		
    void releaseSimulation();

    void holdSimulation();

    void setSpeed(int value);

    void displayErrorLog();

    void listenConnection();

    void showPlotter();

    void addTimer(ITime& t,
		  int isRelative);
		
    void killTimer(ITime t);

    void switchTimer(ITime t);

    ITime getCurrentTime() const {
    return lastTimeStamp;
    }

    int isSimulatorRunning() const {
    return simIsRunning;
    }

    void tkRegisterChannel(const char *tclName);

    void tkUnregisterChannel();

    void tkPollChannel();

    void tkPollTime();

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);

    // Protocol virtuals

    virtual MvmInterface *createDisplay(const MvmInterfaceExportMsg *gpex,
					int msize);

    virtual void destroyDisplay(MvmInterface *object);

    virtual void send(int mtype,
		      MvmInterfaceMsg *gpm =0,
		      int msize =0);

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *mbuf,
			   int msize);

    virtual int dispatch(int mtype,
			 const void *mbuf,
			 int msize);
};

class StatPlotter : public TkPlotterFrame {

 protected:

    Monitor *monitor;

    MvmInterfaceGList objects;

    TkTimeCurvePlotter *timePlotter;

    TkHistoPlotter *histoPlotter;
	
 public:

    StatPlotter(Monitor *monitor);

    virtual ~StatPlotter();

    void timeNotified(ITime time) {
    timePlotter->timeUpdate(time);
    }

    virtual MvmInterface *createDisplay(const MvmInterfaceExportMsg *gpex,
					int msize);

    virtual int dispatch(int mtype,
			 const void *mbuf,
			 int msize);

    virtual void send(int mtype,
		      MvmInterfaceMsg *gpm =0,
		      int msize =0);

    virtual ITime getCurrentTime() const;

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);
};

#endif // !_monitor_h
