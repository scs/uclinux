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

#ifndef _mvm_manager_h
#define _mvm_manager_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vm/thread.h"
#include "vm/flag.h"
#include "vm/timer.h"

class MvmMonitor;
class MvmPipe;
class MvmIrqManager;
struct tosh_syminfo;

#define MVM_ALRTBRK  0x1	// Stop simulation on trace alerts
#define MVM_CSVMT    0x2	// Use conservative multi-threading
#define MVM_IMASTER  0x4	// Interface master - Xenoscope is slave
#define MVM_WARNBRK  0x8	// Stop simulation on warnings
#define MVM_NOTMCK   0x10	// Do not check for suspicious time locks
#define MVM_WNOCHECK 0x20	// Don't check for warning count
#define MVM_TRACED   0x40	// Under Xenoscope's debugger control
#define MVM_SIMREADY 0x80	// The simulated system is ready
#define MVM_CALLIDLE 0x100	// Call the idle state hook asap
#define MVM_VTIME    0x200	// Do not advance the clock on insn exec.

// Values passed by the instrumentation code
#define MVM_FRAME_ENTER 0x10	// Frame entry modifier
#define MVM_FRAME_EXIT  0x20	// Frame exit modifier
#define MVM_FRAME_EXIT2 0x40	// Frame exit with tail return modifier

// Beyond this count, a warning is turned into a fatal error.
#define MVM_MAX_WARNINGS 100
// Beyond this number of locked insns, a time-locked section is
// suspicious.
#define MVM_MAX_LCKINSNS 10000

#define MVM_ON_CALLOUT   1  // Running a hook
#define MVM_ON_IHANDLER  2  // On behalf of an interrupt handler
#define MVM_ON_ASYNCH    3  // MVM_ON_CALLOUT || MVM_ON_IHANDLER

class MvmManager : public MvmThread {

protected:

    const char *optScan;

    unsigned timeLocks,
	lockedInsns;

    ITime simexTick;

    double warp;
	       
    CString repository,
	configuration,
	projectFile;

    MvmFlag startSimulation,
	endSampling,
	endSimulation;

    CString runDir,
	errorLog;

    FILE *errorStream;

    int flags;

    int debugFilter;

    int monTcpPort;

    const char *optArg;

    int optIndex;

    int fatalCount,
	warningCount,
	exitCode;

    unsigned hogFactor;

    XenoThread *rootThread;

    void resetOpt();

    int getOpt(int argc,
	       char *argv[],
	       const char *options);

    int parseOpts(int& argc,
		  char *argv[]);

    void tick();

    virtual void body();

    virtual void timeout(MvmTimer *timer);

public:

    static MvmManager *This;

    static ITime warmupTime;

    static ITime finishTime;

    static ITime execTime;

    static int numSamples;

    static ITime samplingPeriod;

    static ITime samplingTime;

    static int fMonitored;

    static int fInfinite;

    static int fDone;

    static int fRunning;

    static const char *progPath;

    static struct tosh_syminfo *namelist;

    static void (*preamble)();

    static void (*breakpoint)();

    static void (*exception)(int xnum);

    static void (*trampoline)(void *tcbarg);

    static const char *(*threadmode)(void *tcbarg);

    static unsigned long long (*jiffies)(void);

    static int (*predicate)(int pred);

    static void (*idletime)(void);

#define MVM_CR_FLAGS (*MvmManager::dcr0)
    static int *dcr0;

#define MVM_CR_ID    (*MvmManager::dcr1)
    static u_long *dcr1;

#define MVM_CR_FOCUS (*MvmManager::dcr2)
    static const char **dcr2;

#define MVM_CR_IMASK (*MvmManager::dcr3)
    static int *dcr3;

    MvmManager(ITime simuTime,
	       ITime warmupTime,
	       int *argc =0,
	       char *argv[] =0,
	       int nsamples =1);

    static XenoThread *getRunningThread() {
	return XenoThread::runningThread;
    }

    static int onIdleP() {
	return (XenoThread::runningThread == This->rootThread);
    }

    int getTcpPort() const {
	return monTcpPort;
    }

    int getFatalCount() const {
	return fatalCount;
    }

    int getWarningCount() const {
	return warningCount;
    }

    int testFlags(int mask) const {
	return (flags & mask);
    }

    void setFlags(int mask) {
	flags |= mask;
    }

    void clrFlags(int mask) {
	flags &= ~mask;
    }

    void addDebugFilter(int filter) {
	debugFilter |= filter;
    }
    
    void setDebugFilter(int filter) {
	debugFilter = filter;
    }
    
    int testDebugFilter(int mask) const {
	return (debugFilter & mask);
    }

    int testTag(int tag) const {
	return testDebugFilter(MVM_KTRACE << (tag & 0x3));
    }

    XenoThread *getRootThread() {
	return rootThread;
    }

    static void setBreakState(int s =MVM_CREG_PBREAK) {
	MVM_CR_FLAGS |= s;
    }
	
    static void clrBreak() {
	MVM_CR_FLAGS = 0;
    }

    static int testBreak_1() {

	int b = MVM_CR_FLAGS;

	MVM_CR_FLAGS = 0;

	if (b & MVM_CREG_THREAD_SCOPE)
	    {
	    if (predicate(MVM_ON_ASYNCH) ||
		getRunningThread()->getOid() != MVM_CR_ID)
		return 0;
	    }

	return b;
    }

    static int testBreak(int s =MVM_CREG_PBREAK) {
	int b = (MVM_CR_FLAGS & s);
	return b ? testBreak_1() : 0;
    }

    void callIdle () {

	if (XenoThread::runningThread == rootThread &&
	    idletime &&
	    testFlags(MVM_CALLIDLE))
	    {
	    clrFlags(MVM_CALLIDLE);
	    idletime();
	    }
    }

    unsigned kdoor(lockTime)() {
	return ++timeLocks;
    }

    unsigned kdoor(unlockTime)() {
	if (timeLocks > 0 && --timeLocks == 0)
	    lockedInsns = 0;
	return timeLocks;
    }

    int timeLocked() const {
	return timeLocks > 0;
    }

    unsigned testLockInsns() {
	return (flags & MVM_NOTMCK) ? 0 : ++lockedInsns;
    }

    void zeroLockInsns() {
	lockedInsns = 0;
    }

    void setWarp (double _warp) {
	warp = _warp;
	simexTick = ITime(ETime(1.0 / exp(_warp),USec));
    }

    double getWarp () const {
	return warp;
    }

    ITime getMvmTick() const {
	return simexTick;
    }

    ITime getMvmFreq() const {
	return ITime(ETime(exp(warp),USec));
    }

    void finishPreamble();

    virtual const char *getContextString();

    void khook(traceInsn)(int tag);

    void khook(trackFrame)(int tag);

    XenoThread *findThread(const MvmContext& context);

    MvmContext getContext();

    void initialize(XenoThread *rootThread);

    virtual MvmMonitor *createMonitor();

    virtual void startTraceManager();

    virtual int run();

    virtual void finish(int exitCode);

    virtual void fatal(const char *format, ...);

    virtual void warning(const char *format, ...);

    virtual void kdoor(fatal)(const char *format,
			      va_list ap);

    virtual void kdoor(warning)(const char *format,
				va_list ap,
				int fCount =1);

    virtual void suspendSimulation();

    virtual void resumeSimulation();
};

class MvmHog : public MvmThread {

protected:

    unsigned hogFactor;

    virtual void body();

public:

    static MvmHog *This;
	
    MvmHog(unsigned hogFactor);

    void setHogFactor(unsigned factor);

    void disable();

    void enable();
};

#endif // !_mvm_manager_h
