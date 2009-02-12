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
 * The original code is FROGS - A Free Object-oriented General-purpose
 * Simulator, released November 10, 1999. The initial developer of the
 * original code is Realiant Systems (http://www.realiant.com).
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvmutils_interface_h
#define _mvmutils_interface_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <sys/types.h>
#include "vmutils/hash++.h"
#include "vmutils/list++.h"
#include "vmutils/string++.h"
#include "vmutils/tclist++.h"
#include "vmutils/clock.h"

#define MVM_IFACE_FULLSPEED 10

#define PDATA(p,mclass) ((mclass *)(p))

typedef int MvmInterfaceSignal;

typedef int MvmInterfaceObjectType;

typedef char MvmInterfaceObjectName[80];

#define MVM_IFACE_SIGBREAK 1

typedef unsigned MvmInterfaceHandle;

#define MVM_IFACE_NONE      0x0
#define MVM_IFACE_DISPLAYED 0x1
#define MVM_IFACE_ZOMBIE    0x2
#define MVM_IFACE_HIDDEN    0x4
#define MVM_IFACE_EXPORTED  0x8
#define MVM_IFACE_ANON      0x10
#define MVM_IFACE_AVAIL     0x20

enum MvmConnectorType {

    MvmMasterConnector,
    MvmSlaveConnector
};

class MvmInterface;
class MvmConnector;
class MvmBackend;
class MvmFrontend;
struct MvmInterfaceMsg;
struct MvmInterfaceExportMsg;

struct MvmInterfaceBreakPoint : public Link {

    double threshold;

    MvmInterfaceBreakPoint(double _threshold) {
	threshold = _threshold;
    }
};

MakeList(MvmInterfaceBreakPoint);

class MvmInterface : public LinkedObject {

    friend class MvmConnector;
    friend class MvmBackend;
    friend class MvmFrontend;

protected:

    char *iName;

    int iType;

    MvmConnector *iConnector;

    unsigned iStatus;

    // local handle for back-end, remote handle for front-end

    MvmInterfaceHandle iHandle;

    MvmInterfaceBreakPointList ifBP;

public:

    MvmInterface(const char *name =0,
		 MvmConnector *connector =0,
		 int pflags =0);

    MvmInterface(const MvmInterfaceExportMsg *gpex,
		 MvmConnector *connector);

    MvmInterface(MvmInterface& src);

    virtual ~MvmInterface();

    MvmInterfaceHandle ifGetHandle() const {
	return iHandle;
    }

    int ifGetType() const {
	return iType;
    }

    void ifSetConnector(MvmConnector *iConnector);

    void ifSend(int mtype,
		MvmInterfaceMsg *gpm =0,
		int msize =0);

    void ifSetName(const char *name);

    const char *ifGetName() const {
	return iName;
    }

    MvmInterfaceBreakPointList& ifGetBPList() {
	return ifBP;
    }

    int ifIsDisplayed() const {
	return (iStatus & MVM_IFACE_DISPLAYED);
    }

    int ifIsConcealed() const {
	return !ifIsDisplayed();
    }

    int ifIsHidden() const {
	return (iStatus & MVM_IFACE_HIDDEN);
    }

    int ifIsExportable() const {
	return !ifIsHidden();
    }

    int ifIsUnnamed() const {
	return (iStatus & MVM_IFACE_ANON);
    }

    int ifIsNamed() const {
	return !ifIsUnnamed();
    }

    void ifSetDisplayed() {
	iStatus |= MVM_IFACE_DISPLAYED;
    }

    void ifSetConcealed() {
	iStatus &= ~MVM_IFACE_DISPLAYED;
    }

    void ifSetHidden() {
	iStatus |= MVM_IFACE_HIDDEN;
	iStatus &= ~MVM_IFACE_ANON;
    }

    void ifSetExportable() {
	iStatus &= ~MVM_IFACE_HIDDEN;
    }

    void ifSetZombie() {
	iStatus |= MVM_IFACE_ZOMBIE;
    }

    int ifIsZombie() const {
	return (iStatus & MVM_IFACE_ZOMBIE);
    }

    int ifIsAlive() const {
	return !ifIsZombie();
    }

    int ifIsExported() const {
	return (iStatus & MVM_IFACE_EXPORTED);
    }

    int ifTestStatus(unsigned mask) const {
	return (iStatus & mask);
    }

    void ifSetStatus(unsigned mask) {
	iStatus |= mask;
    }

    void ifExport(MvmInterfaceExportMsg *gpex,
		  int msize);

    void ifDestroy();

    void ifDisplay();

    void ifConceal();

    void ifSetBreak(double threshold);

    void ifClrBreak(double threshold);

    void ifInfo(int mtype,
		const char *data,
		int size =-1);

    virtual void ifInit();

    virtual void ifSignal(MvmInterfaceSignal signo);

    virtual void ifProcess(int mtype,
			   const MvmInterfaceMsg *gpm,
			   int msize);
};

MakeGList(MvmInterface);

class MvmConnector {

    friend class MvmInterface;

protected:

    MvmConnectorType type;

    HashTable handles;

    u_long seqNum;

public:

    static MvmInterfaceGList allInterfaces;

    MvmConnector(MvmConnectorType type);

    virtual ~MvmConnector() {}

    MvmInterface *search(MvmInterfaceHandle handle) {
	return (MvmInterface *)handles.find(handle);
    }

    void remap(MvmInterface *object,
	       MvmInterfaceHandle handle);

    virtual int dispatch(int mtype,
			 const void *mbuf,
			 int msize);

    virtual void send(int mtype,
		      MvmInterfaceMsg *gpm =0,
		      int msize =0) =0;
};

class MvmBackend : public MvmConnector {

    friend struct MvmInterfaceExportMsg;

private:

    static unsigned stamps;

public:

    MvmBackend() : MvmConnector(MvmMasterConnector) {
    }

    virtual ~MvmBackend() {}

    virtual int dispatch(int mtype,
			 const void *mbuf,
			 int msize);

    virtual void destroyObject(MvmInterface *object);
};

class MvmFrontend : public MvmConnector {

public:

    MvmFrontend() :
	MvmConnector(MvmSlaveConnector) {}

    virtual ~MvmFrontend() {}

    virtual int dispatch(int mtype,
			 const void *mbuf,
			 int msize);

    virtual MvmInterface *createDisplay(const MvmInterfaceExportMsg *gpex,
					int msize) =0;

    virtual void destroyDisplay(MvmInterface *object) =0;
};

// MESSAGES

struct MvmInterfaceMsg {

    // Referenced object handle
    // (local one from backend side, remote one
    // from frontend side)
    MvmInterfaceHandle handle;
    // Msg sequence #
    u_long seqNum;
};

struct MvmInterfaceExportMsg : public MvmInterfaceMsg {

    MvmInterfaceObjectName name;

    MvmInterfaceObjectType type;

    MvmInterfaceExportMsg(MvmInterfaceObjectType type,
			  const char *name);
};

struct MvmInterfaceDestroyMsg : public MvmInterfaceMsg {
};

struct MvmInterfaceDisplayMsg : public MvmInterfaceMsg {

    int okDisplay;

    MvmInterfaceDisplayMsg(int okDisplay);
};

struct MvmInterfaceBreakMsg : public MvmInterfaceMsg {

    double threshold;

    int okBreakOn;

    MvmInterfaceBreakMsg(double threshold, int okBreakOn);
};

struct MvmInterfaceInfoMsg : public MvmInterfaceMsg {

    char data[1];
};

#define MVM_IFACE_EXPORT	999990
#define MVM_IFACE_UNEXPORT	999991 // BackEnd => FrontEnd only
#define MVM_IFACE_DESTROY	999991 // FrontEnd => BackEnd only
#define MVM_IFACE_TOGGLE	999992
#define MVM_IFACE_BREAK_TOGGLE	999993

// Protocol object types
#define MVM_IFACE_TIMEGRAPH_ID  1
#define MVM_IFACE_HISTOGRAM_ID  2
#define MVM_IFACE_SDIAGRAM_ID   3
#define MVM_IFACE_SCALAR_ID     4
#define MVM_IFACE_MONITOR_ID    100
#define MVM_IFACE_DASHBOARD_ID  101
#define MVM_IFACE_THREAD_ID     102

#define MVM_IFACE_TIMEGRAPH_INIT   1100
#define MVM_IFACE_TIMEGRAPH_POINT  1101
#define MVM_IFACE_HISTOGRAM_HEAD   1102
#define MVM_IFACE_HISTOGRAM_INIT   1103
#define MVM_IFACE_SDIAGRAM_INIT	   1104
#define MVM_IFACE_SDIAGRAM_POINT   1105
#define MVM_IFACE_SCALAR_VALUE	   1106

// FrontEnd -> BackEnd messages
#define MVM_IFACE_MONITOR_SET_SPEED  2000
#define MVM_IFACE_MONITOR_STOP       2001
#define MVM_IFACE_MONITOR_CONTINUE   2002
#define MVM_IFACE_DASHBOARD_CONFIGURE   2003
#define MVM_IFACE_DASHBOARD_TRIGGER     2004
#define MVM_IFACE_TIMER_ADD          2005
#define MVM_IFACE_TIMER_KILL         2006
#define MVM_IFACE_TIMER_SWITCH       2007
#define MVM_IFACE_DEBUG_STEPOVER     3000
#define MVM_IFACE_DEBUG_STEPINTO     3001
#define MVM_IFACE_DEBUG_STEPOUT      3002
#define MVM_IFACE_DEBUG_SETFILTER    3003

// BackEnd -> FrontEnd general messages
#define MVM_IFACE_MONITOR_COLD         2100
#define MVM_IFACE_MONITOR_WARM         2101
#define MVM_IFACE_MONITOR_HELD         2102
#define MVM_IFACE_MONITOR_FINISHED     2103
#define MVM_IFACE_MONITOR_QUIT         2104
#define MVM_IFACE_ERRLOG_UPDATE        2105
#define MVM_IFACE_RESUME_REQUEST       2106

// BackEnd <-> FrontEnd bi-directional messages
#define MVM_IFACE_MONITOR_READY        2200
#define MVM_IFACE_MONITOR_TIME         2201
#define MVM_IFACE_DASHBOARD_INFO       2202
#define MVM_IFACE_DASHBOARD_OUTPUT     2203

// MESSAGES (pure data structs only, no virtual tables)

// System information

#define MAX_OS_NAMELEN         32
#define MAX_THREADTYPE_NAMELEN 16

struct MvmSystemInfoMsg : public MvmInterfaceMsg {

    // Short name of the real-time interface.
    char osName[MAX_OS_NAMELEN];

    // How the real-time threads are named by the real-time
    // interface (e.g. task, thread, process...).

    char threadTypeName[MAX_THREADTYPE_NAMELEN];
};

// Flags from control register dcr0 (MVM_CR_FLAGS)
#define MVM_CREG_SYSTEM_SCOPE    0x00	// focus on last active thread
#define MVM_CREG_THREAD_SCOPE    0x01	// focus on specific thread
#define MVM_CREG_PBREAK          0x10	// break state is pending
#define MVM_CREG_DEBUG           0x20	// break caused by a debug trap
#define MVM_CREG_WATCH           0x40	// break caused by a watchpoint
#define MVM_CREG_IBREAK          0x80	// initial break state is pending

enum MvmContextType {

    XIdleContext =0,
    XInitContext,
    XThreadContext,
    XCalloutContext,
    XIhdlrContext,
    XSystemContext
};

typedef struct MvmContext {

    int type;

    u_long internalID;

    MvmContext() {
	type = XIdleContext;
	internalID = 0;
    }

} MvmContext;

// Monitor messages

struct MvmMonitorExportMsg : public MvmInterfaceExportMsg {

    double simulationTime;

    MvmMonitorExportMsg(const char *_name, ITime _execTime) :
	MvmInterfaceExportMsg(MVM_IFACE_MONITOR_ID,_name) {
	simulationTime = _execTime;
    }
};

struct MvmWarmStateMsg : public MvmInterfaceMsg {

    int fatalCount,
	warningCount;

    MvmWarmStateMsg(int _fatalCount, int _warningCount) {
	fatalCount = _fatalCount;
	warningCount = _warningCount;
    }
};

struct MvmSetSpeedMsg : public MvmInterfaceMsg {

    int speed;
};

struct MvmTimeMsg : public MvmInterfaceMsg {

    double time;
};

struct MvmHoldMsg : public MvmInterfaceMsg {

#define MVM_STOP_USER   0
#define MVM_STOP_TIMER  1
#define MVM_STOP_GRAPH  2
#define MVM_STOP_TRACE  3
#define MVM_STOP_ERROR  4
#define MVM_STOP_DBTRAP 5
#define MVM_STOP_WATCH  6
    int stopCondition;
};

// StepOver/StepInto/StepOut debugger messages

struct MvmStepMsg : public MvmInterfaceMsg {

#define MVM_CREG_TRACE_ASYNCH 0x1
    int flags;

    MvmContext context;

    MvmStepMsg(MvmContext _context, int _flags =0) {
	context = _context;
	flags = _flags;
    }
};

struct MvmSetFilterMsg : public MvmInterfaceMsg {

#define MVM_KTRACE   0x1	// Trace kernel (i.e. Xenomai nucleus)
#define MVM_ITRACE   0x2	// Trace real-time interface layer
#define MVM_UTRACE   0x4	// Trace application code
    int filter;

    MvmSetFilterMsg(int _filter) {
	filter = _filter;
    }
};

#define MVM_OBJCTL_EXPOSE    1
#define MVM_OBJCTL_CONFIGURE 2
#define MVM_OBJCTL_TRIGGER   3

#ifndef name2
#define name2(a,b) a ## b
#endif // !name2

#define kdoor(f) name2(f,_kdoor_)
#define khook(f) name2(f,_khook_)
#define kisrt(f) name2(f,_kisrt_)
#define kdsrt(f) name2(f,_kdsrt_)
#define kroot(f) name2(f,_kroot_)
#define kcout(f) name2(f,_kcout_)
#define kidle(f) name2(f,_kidle_)
#define kinit(f) name2(f,_kinit_)
#define khide(f) name2(f,_khide_)

#endif // !_mvmutils_interface_h
