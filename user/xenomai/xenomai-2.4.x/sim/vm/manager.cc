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
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>
#include <math.h>
#include <fcntl.h>
#include "vmutils/toolshop.h"
#include "vmutils/string++.h"
#include "vmutils/clock.h"
#include "vm/stream.h"
#include "vm/manager.h"
#include "vm/monitor.h"
#include "vm/event.h"
#include "vm/source.h"
#include "vm/timer.h"
#include "vm/trace.h"
#include "vm/interrupt.h"

ITime MvmManager::samplingPeriod,
    MvmManager::samplingTime,
    MvmManager::warmupTime,
    MvmManager::finishTime,
    MvmManager::execTime;

int MvmManager::fMonitored = 0,
    MvmManager::fInfinite = 0,
    MvmManager::fDone = 0,
    MvmManager::fRunning = 0;

int MvmManager::numSamples = 1;

const char *MvmManager::progPath = NULL;

struct tosh_syminfo *MvmManager::namelist = NULL;

void (*MvmManager::preamble)() = NULL;

void (*MvmManager::breakpoint)() = NULL;

void (*MvmManager::exception)(int) = NULL;

void (*MvmManager::trampoline)(void *) = NULL;

const char *(*MvmManager::threadmode)(void *) = NULL;

unsigned long long (*MvmManager::jiffies)(void) = NULL;

int (*MvmManager::predicate)(int) = NULL;

void (*MvmManager::idletime)(void) = NULL;

int *MvmManager::dcr0 = NULL;

u_long *MvmManager::dcr1 = NULL;

const char **MvmManager::dcr2 = NULL;

int *MvmManager::dcr3 = NULL;

MvmManager *MvmManager::This = NULL;

MvmHog *MvmHog::This = NULL;

static RETSIGTYPE cleanup (int sig)

{
    exit(0);
#if RETSIGTYPE != void
    return (RETSIGTYPE)0;
#endif
}

MvmManager::MvmManager (ITime _simuTime,
			ITime _warmupTime,
			int *_argc,
			char *_argv[],
			int _nsamples) :
    MvmThread(CString(_argv[0]).basename(),
	      MVM_IFACE_HIDDEN,
	      32768)
{
    This = this;
    progPath = _argc && _argv ? tosh_getselfpath(_argv[0]) : "";
    monTcpPort = -1;
    errorStream = stderr;
    fatalCount = 0;
    warningCount = 0;
    exitCode = 0;
    flags = 0;
    debugFilter = 0;
    hogFactor = 0;
    rootThread = NULL;
    setWarp(3.0);

    execTime = _simuTime;
    warmupTime = _warmupTime;
    numSamples = _nsamples;

    struct sigaction sa;
    sa.sa_handler = (SIGHANDLER_TYPE)cleanup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGHUP,&sa,NULL);
    sigaction(SIGPIPE,&sa,NULL);

    // Ensure stdout is unbuffered (stderr is not by convention).
    setvbuf(stdout,NULL,_IONBF,0);

    MVM_CR_FLAGS = 0;
    MVM_CR_ID = 0;
    MVM_CR_FOCUS = NULL;

    if (_argc && _argv)
	// override settings with command-line options
	parseOpts(*_argc,_argv);

    if (execTime == ZEROTIME || numSamples == 0)
	{
	fInfinite = 1;
	samplingPeriod = execTime;
	numSamples = 0;
	finishTime = ZEROTIME;
	}
    else
	{
	finishTime = warmupTime + execTime;
	samplingPeriod = (double)execTime / (double)numSamples;
	}

    startSimulation.reset();
    endSampling.reset();
    endSimulation.reset();

    MvmSource::sourceChain.setMaster(&MvmThread::runChain);
    new MvmSourceManager();
    MvmSource::sourceChain.setManager(MvmSourceManager::This);
    MvmTimer::timerChain.setMaster(&MvmThread::runChain);
    new MvmTimerManager;
    MvmTimer::timerChain.setManager(MvmTimerManager::This);

    warningCount = 0;
    timeLocks = 0;
    lockedInsns = 0;

    if (!fMonitored)
	// Ignore start break if running outside the the Xenoscope's
	// control.
	clrBreak();
    else if (testFlags(MVM_IMASTER))
	// Always hold simulation at the very beginning when
	// running in master mode.
	setBreakState(MVM_CREG_PBREAK);
}

void MvmManager::initialize (XenoThread *_rootThread)

{
    rootThread = _rootThread;

    if (!projectFile.isEmpty() &&
	projectFile.basename().match(".xeno") < 0 &&
	::access(projectFile,F_OK) < 0)
	// Infere the missing extension
	projectFile += ".xeno";
    
    if (!progPath)
	fatal("unable to determine current executable path");

    namelist = tosh_slurpsyms(progPath);

    // Perform the last initialization chores -- includes creating the
    // embedded monitor as needed.

    if (testFlags(MVM_IMASTER))
	errorLog = tosh_mktemp(NULL,"xeno");

    if (!errorLog.isEmpty() && errorLog != "-")
	{
	errorStream = fopen(errorLog,"w");

	if (!errorStream)
	    errorStream = stderr;
	}

    if (fMonitored)
	{
	MvmMonitor::This = createMonitor();

	if (MvmMonitor::This)
	    {
	    // Immediately export the dialog manager
	    MvmMonitor::This->ifInit();
	    hogFactor = 0;
	    }
	else
	    fMonitored = 0;
	}

    // Simulation overloader is available in both slave
    // & master modes
    new MvmHog(hogFactor);

    // Start the interrupt manager now that the main interface
    // connector is available (i.e. the monitor itself).
    new MvmIrqManager();

    startTraceManager();

    rootThread->ifSetConnector(MvmMonitor::This);
    rootThread->ifInit();
}

MvmMonitor *MvmManager::createMonitor ()

{
    // Default manager role is slave in the dialog, thus, connect to
    // the server socket bound to the monitor port.

    MvmPipe *tcpChannel = new MvmPipe;

    if (testFlags(MVM_IMASTER))
	{
	// Interface-master role -- establish a server socket bound to
	// a system-choosen port to which the Xenoscope will connect
	// to. Wait this connection for 30 secs before assuming an
	// error condition.
	
	monTcpPort = tcpChannel->bind();

	if (monTcpPort < 0)
	    {
	    delete tcpChannel;
	    fatal("cannot bind socket");
	    }

	char *av[8];

	av[0] = "xenoscope";
	av[1] = "-f";
	av[2] = projectFile.gets();
	av[3] = "-p";
	av[4] = strdup(CString(monTcpPort));
	av[5] = "-l";
	av[6] = errorLog.gets();
	av[7] = NULL;
		 
	if (tosh_spawn("xenoscope",av) < 0)
	    {
	    delete tcpChannel;
	    fatal("failed to start the Xenoscope");
	    }
	    
	if (tcpChannel->accept(30) != MVM_PIPE_SUCCESS)
	    {
	    delete tcpChannel;
	    fatal("no connection with the Xenoscope on port %d",monTcpPort);
	    }
	}
    else
	{
	// Interface-slave role -- connect to the server socket
	// defined by the Xenoscope.
	
	if (monTcpPort < 0)
	    return NULL;

	if (tcpChannel->connect(NULL,monTcpPort) != MVM_PIPE_SUCCESS)
	    {
	    delete tcpChannel;
	    fatal("cannot connect to the Xenoscope on port %d",monTcpPort);
	    }
	}

    return new MvmMonitor(tcpChannel);
}

void MvmManager::finishPreamble ()

{
    // If the Xenoscope controls the simulator, fire the preamble
    // hook to yield control back to the debug engine.

    if (testFlags(MVM_TRACED))
	// Run the simulation preamble hook.
	preamble();
}

void MvmManager::startTraceManager () {

    new MvmTraceManager("RT/Interfaces");
}

void MvmManager::resetOpt ()

{
    optIndex = 1;
    optScan = NULL;
}

int MvmManager::getOpt (int argc,
			char *argv[],
			const char *options)
{
    if (optScan && !*optScan)
	{
	optIndex++;
	optScan = NULL;
	}

    if (optIndex >= argc || !argv[optIndex])
	return EOF;

    if (!optScan)
	{
	if (argv[optIndex][0] != '-')
	    return '?';
	
	if (argv[optIndex][1] == '-' &&
	    argv[optIndex][2] == '\0')
	    {
	    optIndex++;
	    return EOF;
	    }

	optScan = &argv[optIndex][1];
	}

    int opt = *optScan++;
    const char *optInfo;

    if (!opt || !(optInfo = strchr(options,opt)))
	{
	optScan = NULL;
	return '?';
	}

    if (optInfo[1] == ':')
	{
	if (*optScan)
	    {
	    optArg = optScan;
	    optScan = strchr(optScan,'\0');
	    }
	else if (++optIndex < argc)
	    optArg = argv[optIndex];
	else
	    {
	    optScan = NULL;
	    opt = '?';
	    }
	}
    else
	optArg = NULL;
    
    return opt;
}

int MvmManager::parseOpts (int& argc, char *argv[])

{
    int c, extind, nopts, speed = 0;
    ITime dtick, timer;
    double warp;

    resetOpt();
    extind = 1;
    nopts = 0;

    while ((c = getOpt(argc,argv,"b:d:k:l:p:s:t:u:w:z:f:X:W:")) != EOF)
	{
	if (c == '?') // unknown option? save it for later
	    {
	    argv[extind++] = argv[optIndex++];
	    continue;
	    }

	switch (c)
	    {
	    case 'p' :

		monTcpPort = atoi(optArg);
		fMonitored = 1;
		break;

	    case 'u' :

		setDefaultETimeUnit(optArg);
		break;

	    case 'k' :

		if (dtick.scan(optArg))
		    setDisplayTick(dtick);
		break;

	    case 't' :

		execTime.scan(optArg);
		break;

	    case 'w' :

		warmupTime.scan(optArg);
		break;

	    case 's' :

		numSamples = atoi(optArg);
		break;

	    case 'd' :

		runDir = optArg;
		runDir.expand();
		break;

	    case 'l' :

		errorLog = optArg;
		errorLog.expand();
		break;

	    case 'z' :

		{
		speed = atoi(optArg);

		if (speed < 1 || speed > MVM_IFACE_FULLSPEED)
		    fatal("illegal speed value `%d' (1 <= speed <= %d)",
			  speed,
			  MVM_IFACE_FULLSPEED);

		hogFactor = (unsigned)(MVM_IFACE_FULLSPEED - speed);
		break;
		}

	    case 'W' :

		warp = atof(optArg);

		if (warp <= 0.0 || speed > 10.0)
		    fatal("illegal warp factor `%f', (0 <= warp <= 10)",
			  warp);

		setWarp(warp);
		break;

	    case 'b' :

		timer.scan(optArg);

		if (timer != NOW)
		    new MvmTimer(NULL,timer,this);

		break;

	    case 'f' :
		// Start the Xenoscope using an existing project --
		// we'll play the master role in the connection.
		// optArg must point to a valid project file. -f is
		// used to be consistent with the same Xenoscope
		// option which auto-loads a project file.
		fMonitored = 1;
		projectFile = optArg;
		setFlags(MVM_IMASTER);
		break;

	    case 'X' :	// Simulation flags prefix.

		for (const char *s = optArg; *s; s++)
		    {
		    switch (*s)
			{
			case 'a' :
			    // Break on trace alerts.
			    setFlags(MVM_ALRTBRK);
			    break;

			case 'b' :
			    // Break requested on entry - plan for the
			    // MvmMonitor to hold the simulation
			    // when the first traced context is reached.
			    setBreakState(MVM_CREG_IBREAK);
			    break;
	    
			case 'g' :
			    // Do not check for warning count.
			    setFlags(MVM_WNOCHECK);
			    break;

			case 'l' :
			    // Do not check for suspicious time locks.
			    setFlags(MVM_NOTMCK);
			    break;

			case 't' :
			    // Traced by the Xenoscope debugger.
			    setFlags(MVM_TRACED);
			    break;
	    
			case 'w' :
			    // Break on simulation warnings.
			    setFlags(MVM_WARNBRK);
			    break;

			case 'v' :
			    // Virtual time
			    setFlags(MVM_VTIME);
			    break;

			case '0':
			    addDebugFilter(MVM_KTRACE);
			    break;

			case '1':
			    addDebugFilter(MVM_ITRACE);
			    break;

			case '2':
			    addDebugFilter(MVM_UTRACE);
			    break;

			default:

			    fatal("unknown -X flag `%c' [abgltwv012]",*s);
			}
		    }

		break;
	    }

	nopts++;
	}

    argc = extind;

    return nopts;
}

void MvmManager::body ()

{
    delay(warmupTime);

    allMvmStatObjs.apply(&MvmStatObj::resetValues);

    if (fInfinite && samplingPeriod == ZEROTIME)
	// Blocking until somebody posts this flag
	endSimulation.pend();
    else
	{
	int currentSample = 0;
	
	do
	    {
	    samplingTime = MvmClock;
	    delay(samplingPeriod);
	    allMvmStatObjs.apply(&MvmStatObj::sample);
	    currentSample++;
	    }
	while (!fDone && (fInfinite || currentSample < numSamples));

	endSimulation.post();
	}

    allMvmStatObjs.apply(&MvmStatObj::result);
    endSampling.post();

    // The simulation manager should not be buried to allow the main
    // thread to access its data members without treading in freed
    // memory... So prevent any return to the life() procedure which
    // would cancel it by denying any further attempt to resume this
    // thread.

    for (;;)
	suspend();
}

// Note: MvmManager::run() must be run on behalf of the main thread.

int MvmManager::run ()

{
    if (MvmMonitor::This)
	MvmMonitor::This->notifyColdInitOk();

    fRunning = 1;

    if (MvmThread::currentThread != MvmThread::mainThread)
	fatal("simulation not started on behalf of the main thread");

    if (!runDir.isEmpty() && chdir(runDir) < 0)
	warning("cannot change directory to %s",(const char *)runDir);
    
    if (fMonitored)
	// Let the manager enter its pend state on the simulation end
	// flag before yielding the CPU -- i.e.  do not activate the
	// monitor using immediateResume(), otherwise, the manager
	// would have no chance to be registered as a waiter before
	// the other simulation threads start, thus would never regain
	// the CPU back to execute the epilog.
	MvmMonitor::This->resume();
    
    startSimulation.post();
    endSimulation.pend();
    fDone = 1;
    immediateResume();
    endSampling.pend();
    clrFlags(MVM_SIMREADY);

    if (fMonitored)
	MvmMonitor::This->terminate();

    return exitCode;
}

void MvmManager::finish (int _exitCode)

{
    // If already running on behalf of the main thread, exit() now...
    if (MvmThread::mainThread == MvmThread::currentThread)
	exit(_exitCode);

    // Otherwise, bump to the main thread to exit() properly (It has
    // been shown that exiting on behalf of other LWP context could
    // lead to unexpected results under Purify)
    exitCode = _exitCode;
    endSimulation.post();

    // Make MvmManager::run() regain control
    MvmThread::mainThread->immediateResume();
}

void MvmManager::kdoor(fatal) (const char *format,
			       va_list ap)
{
    const char *who = NULL;
    CString buf;

    // Note: error messages must begin with "Xenoscope:" to be
    // identified by the Xenoscope.

    who = MvmThread::currentThread->ifGetName();

    fprintf(errorStream,
	    "Xenoscope: %s: fatal in %s (time=%f): ",
	    ifGetName(),
	    who ? who : "<unknown>",
	    (double)MvmClock);
    
    buf.vformat(format,ap);
    fputs(buf,errorStream);
    fputc('\n',errorStream);
    fflush(errorStream);
    fatalCount++;

    if (MvmMonitor::This)
	{
	MvmMonitor::This->send(MVM_IFACE_ERRLOG_UPDATE);
	// Always raise a breakpoint on fatal errors.
	MvmMonitor::This->stopSimulation(MVM_STOP_ERROR);
	}
    
    finish(1);
}

void MvmManager::fatal (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    kdoor(fatal)(format,ap);
    va_end(ap);
}

void MvmManager::kdoor(warning) (const char *format,
				 va_list ap,
				 int fCount)
{
    const char *who = NULL;
    CString buf;

    // Note: error messages must begin with "Xenoscope:" to be
    // identified by the Xenoscope.

    who = MvmThread::currentThread->ifGetName();

    fprintf(errorStream,
	    "Xenoscope: %s: warning in %s (time=%f): ",
	    ifGetName(),
	    who ? who : "<unknown>",
	    (double)MvmClock);
    
    buf.vformat(format,ap);
    fputs(buf,errorStream);
    fputc('\n',errorStream);
    fflush(errorStream);

    if (fCount &&
	!testFlags(MVM_WNOCHECK) &&
	++warningCount > MVM_MAX_WARNINGS)
	fatal("too many warnings (> %d)",MVM_MAX_WARNINGS);

    if (MvmMonitor::This)
	{
	MvmMonitor::This->send(MVM_IFACE_ERRLOG_UPDATE);

	if (testFlags(MVM_WARNBRK))
	    // Raise a breakpoint if needed.
	    MvmMonitor::This->stopSimulation(MVM_STOP_ERROR);
	}
}

void MvmManager::warning (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    kdoor(warning)(format,ap);
    va_end(ap);
}

void MvmManager::suspendSimulation ()

{
    // This routine has no effect if not running under
    // monitor control.

    if (MvmMonitor::This)
	MvmMonitor::This->stopSimulation(MVM_STOP_USER);
}

void MvmManager::resumeSimulation ()

{
    // NOTE: The "resume" request is first relayed to the Xenoscope if
    // present, before it is sent back as a CONTINUE request to the
    // simulator. This allows the Xenoscope to be in a consistent
    // state after the simulator is resumed. This means that a
    // suspendSimulation() which immediately follows a
    // resumeSimulation() will probably lead to a null-effect, because
    // it will be processed locally by the simulator which is already
    // in a stopped state, before the initial continuation request is
    // received from the Xenoscope.

    if (MvmMonitor::This)
	// then, wait for the monitor to answer back with a
	// CONTINUE message
	MvmMonitor::This->send(MVM_IFACE_RESUME_REQUEST);
}

void MvmManager::timeout (MvmTimer *timer)

{
    if (fMonitored)
	MvmMonitor::This->stopSimulation(MVM_STOP_TIMER);
}

MvmContext MvmManager::getContext ()

{
    // The execution context identifier is a short handle describing
    // which kind of activity is currently running.
    // Six different contexts are defined:
    // on behalf of Xenomai's init code (before the pod is created)
    // on behalf of an interrupt handler
    // on behalf of a kernel callout
    // on behalf of a real-time thread
    // on idle time (i.e. root thread)

    MvmContext ctx;

    ctx.internalID = 0;

    if (!testFlags(MVM_SIMREADY))
	ctx.type = XInitContext;
    else if (MvmManager::predicate(MVM_ON_IHANDLER))
	ctx.type = XIhdlrContext;
    else if (MvmManager::predicate(MVM_ON_CALLOUT))
	ctx.type = XCalloutContext;
    else if (onIdleP())
	ctx.type = XIdleContext;
    else
	{
	ctx.type = XThreadContext;
	ctx.internalID = getRunningThread()->getOid();
	}

    return ctx;
}

const char *MvmManager::getContextString ()

{
    MvmContext ctx = getContext();
    XenoThread *thread;

    switch (ctx.type)
	{
	case XThreadContext:

	    thread = getRunningThread();
	    thread->getContextString();
	    break;

	case XIhdlrContext:

	    MvmIrqManager::This->getContextString();
	    break;

	case XIdleContext:

	    XenoThread::contextString.format("idle 0 %d %llu",
					     MVM_CR_IMASK,
					     jiffies());
	    break;

	case XCalloutContext:

	    XenoThread::contextString.format("callout 0 %d %llu",
					     MVM_CR_IMASK,
					     jiffies());
	    break;

	case XInitContext:

	    XenoThread::contextString.format("init 0 0 0");
	    break;
	}

    return XenoThread::contextString;
}

XenoThread *MvmManager::findThread (const MvmContext& context)

{
    if (context.type == XIhdlrContext)
	return MvmIrqManager::This;
    
    if (context.type == XCalloutContext)
	return getRunningThread();

    // If searching a thread context, find a match in the active
    // threads queue for the given internal identifier.

    if (context.type == XThreadContext)
	{
	XenoThreadIterator it(allXenoThreads);
	XenoThread *thread;

	while ((thread = it.next()) != NULL)
	    {
	    if (thread->getOid() == context.internalID)
		return thread;
	    }
	}

    return rootThread;
}

void MvmManager::tick ()

{
    if (!timeLocked())
	{
	if (!testFlags(MVM_VTIME))
	    XenoThread::currentThread->delay(simexTick);

	MvmIrqManager::This->dispatchIrq();
	callIdle();
	}
    else
	{
	// If a dynamic time lock is pending, do not advance
	// the simulation clock -- But before returning, check for
	// a suspicious locked section.

	if (testLockInsns() > MVM_MAX_LCKINSNS)
	    {
	    zeroLockInsns();
	    warning("suspicious time-locked section? (more than %d insns)",
		    MVM_MAX_LCKINSNS);
	    }
	}
}

void MvmManager::khook(traceInsn) (int tag)

{
    if (testFlags(MVM_TRACED) && testTag(tag))
	{
	XenoThread *thread = getRunningThread();

	if (thread->isTraced())
	    thread->frameTest();
	}

    int b = testBreak();

    if (b)
	// Check for a pending break condition. Note that no break
	// condition may be raised if running without monitoring.
	MvmMonitor::This->stopSimulation((b & MVM_CREG_DEBUG) ?
					 MVM_STOP_DBTRAP :
					 (b & MVM_CREG_WATCH) ?
					 MVM_STOP_WATCH :
					 MVM_STOP_USER);
    tick();
}

void MvmManager::khook(trackFrame) (int tag)

{
    getRunningThread()->trackFrame(tag);
    
    int b = testBreak();

    if (b)
	// Check for a pending breakpoint triggered by the last frame
	// tracking update.
	MvmMonitor::This->stopSimulation((b & MVM_CREG_DEBUG) ?
					 MVM_STOP_DBTRAP :
					 (b & MVM_CREG_WATCH) ?
					 MVM_STOP_WATCH :
					 MVM_STOP_USER);
}

// MvmHog - Simulation overloader

MvmHog::MvmHog (unsigned _hogFactor)
    : MvmThread("Hog manager",MVM_IFACE_HIDDEN)
{
    This = this;
    hogFactor = 1;
    setHogFactor(_hogFactor);
}

void MvmHog::body ()

{
    for (;;)
	{
	usleep(50000);
	delay((double)(getDtTick() * 75000.0) / (1 << hogFactor));
	}
}

void MvmHog::setHogFactor (unsigned factor)

{
    unsigned oldFactor = hogFactor;

    hogFactor = factor;

    if (oldFactor == 0 && factor > 0)
	resume();
    else if (oldFactor > 0 && factor == 0)
	suspend();
}

void MvmHog::disable ()

{
    if (hogFactor > 0)
	suspend();
}

void MvmHog::enable ()

{
    if (hogFactor > 0)
	resume();
}
