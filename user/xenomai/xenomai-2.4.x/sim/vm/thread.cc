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
 * The original code is FROGS - A Free Object-oriented General-purpose
 * Simulator, released November 10, 1999. The initial developer of the
 * original code is Realiant Systems (http://www.realiant.com).
 *
 * Author(s): tb, rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum. Pieces of CarbonKernel code
 * merged in.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include "vmutils/toolshop.h"
#include "vmutils/interface.h"
#include "vm/timer.h"
#include "vm/manager.h"
#include "vm/monitor.h"
#include "vm/interrupt.h"

#ifdef HAVE_GLIBC2_MALLOC

// Shut off the use of mmap() in glibc2 for large chunks since it
// wrecks MvmThread::checkMemory() behavior with pointers to data.
// (mmap'ed chunks are unknown to this layer -- we're only aware of
// the current break limit for the process) Setting MALLOC_MMAP_MAX_=0
// in the environment also works.

class __ThreadInitClass {

public:

    __ThreadInitClass() {
	mallopt(M_MMAP_MAX,0);
    }

} __ThreadInitObject;

#endif

MvmScheduler MvmThread::runChain;

MvmThread *volatile MvmThread::currentThread = NULL;

MvmThread *MvmThread::mainThread = NULL;

MvmUndertaker *MvmUndertaker::This = NULL;

CString XenoThread::contextString;

XenoThread *XenoThread::runningThread = NULL;

int XenoThread::schedLock = 0;

XenoThreadGList allXenoThreads;

XenoThreadGList allJoinableThreads;

XenoThreadGList allClientJoiners;

XenoThreadGList holdChain;

// MvmThread - Basic event-driven simulation thread.

MvmThread::MvmThread () :
    MvmTimed("Main thread",&runChain,MVM_IFACE_HIDDEN)
{
    stackBase = NULL;
    stackTop = NULL;
    stackGuard = NULL;
    stackSize = 0;
    setState(TS_RUNNING);
    bumpCaller = NULL;
    pendSynchro = NULL;
    timer = new MvmTimer(NULL,this);
    mainThread = this;
    setPrio(MVM_THREAD_BASEPRI);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	MvmDebug << "Main THREAD " << " @" << mainThread << " created\n";
#endif // CONFIG_XENO_MVM_DEBUG
}

MvmThread::MvmThread (const char *_name,
		      int _pflags,
		      unsigned _stackSize) :
    MvmTimed(_name,&runChain,_pflags)
{
    if (!mainThread)
	{
	currentThread = new MvmThread();
	new MvmUndertaker();
	}

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	MvmDebug << "THREAD " << _name << " @" << this << " created\n";
#endif // CONFIG_XENO_MVM_DEBUG

    timer = new MvmTimer(NULL,this);
    pendSynchro = NULL;
    bumpCaller = NULL;

    if (_stackSize < 8192)
	// min. stack size is 8k
	_stackSize = 8192;
    
    stackSize = ((_stackSize + 1023) & ~1023);
    stackBase = (caddr_t)malloc(stackSize + 1024);

    if (!stackBase)
	MvmManager::This->fatal("cannot allocate thread stack (%u bytes)",
				stackSize + 1024);

#ifdef HAVE_DOWNWARDING_STACK
    stackTop = stackBase + stackSize + 1024;
    stackGuard = stackBase + 1024;
#else  // HAVE_UPWARDING_STACK
    stackTop = stackBase;
    stackGuard = stackBase + stackSize;
#endif
    *((unsigned *)stackGuard) = 0xdeadbeef;

    // New thread must inherit its parent's priority in order to allow
    // the thread ctor() --executed on behalf of the creator's
    // context-- to return *before* the new thread's body is started
    // (we need the vtbl to be built here!)
    setPrio(currentThread->getPrio());
    sched->prepend(currentThread);
    setState(TS_RUNNING);
    spawn();
}

void MvmThread::life (void)

{
    // Yield control to our creator in order to let it
    // complete this object's ctor().
    currentThread->delay(ZEROTIME);

    // Trigger an automatic export as we know the
    // thread object is now fully built...
    
    if (currentThread->ifIsExportable() &&
	!currentThread->ifIsExported())
	currentThread->ifInit();
    
    currentThread->body();
    currentThread->cancel();
}

void MvmThread::spawn ()

{
    getcontext(&context.ucp);
    context.jumped = 0;
    context.ucp.uc_stack.ss_sp = stackBase;
    context.ucp.uc_stack.ss_size = stackSize;
    context.ucp.uc_stack.ss_flags = 0;
    context.ucp.uc_link = NULL;
    currentThread->context.jumped = 0;
    makecontext(&context.ucp,(void (*)(void))&life,0);
    MvmThread *_currentThread = currentThread;
    currentThread = this;
    swapcontext(&_currentThread->context.ucp,&context.ucp);
}

MvmThread::~MvmThread ()

{
    // This code assumes the undertaker is never canceled...

    if (currentThread != MvmUndertaker::This)
	MvmManager::This->fatal("deleted thread not canceled");

    if (pendSynchro)
	pendSynchro->forget(this);

    delete timer;

    if (stackSize > 0)
	free(stackBase);
}

void MvmThread::cancel ()

{
#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	MvmDebug << MvmClock << " THREAD " << ifGetName()
		 << " @" << this << " canceled\n";
#endif // CONFIG_XENO_MVM_DEBUG

    MvmUndertaker::This->bury(this);
}

void MvmThread::body () {
}

void MvmThread::activate ()

{
    if (currentThread)
	{
	if (do_save(&currentThread->context))
	    {
	    if (currentThread->bumpCaller)
		{
		MvmThread *bumpReturn = currentThread->bumpCaller;
		currentThread->bumpCaller = NULL;
		currentThread->bumpHandler();
		currentThread = bumpReturn;
		do_restore(&currentThread->context);
		}
	    
	    return;
	    }
	}
    
    ITime tt = getTime();
    
    if (tt < MvmClock)
	MvmManager::This->fatal("MvmThread::activate() - preposterous time value");
    
    MvmClock = tt;
    
#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	MvmDebug << MvmClock << " THREAD " << ifGetName()
		 << " @" << this << " activated " << " / currentThread = "
		 << currentThread << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
    
    currentThread = this;

    do_restore(&context);
}

void MvmThread::preempt ()

{
    if (state != TS_RUNNING)
	{
	MvmManager::This->warning("MvmThread::preempt() - thread not running");
	return;
	}

    setState(TS_PREEMPTED);
    schedTime -= MvmClock;

    if (this == currentThread)
	{
	if (onStackOverflow())
	    MvmManager::This->fatal("thread stack overflow");

	sched->schedule();

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " THREAD " << ifGetName()
		     << " @" << this << " resuming after preemption\n";
	    
	    if (globalTrace > 1)
		printRunChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG
	}
    else
	sched->remove(this);
}

void MvmThread::delay (ITime t)

{
    if (t < ZEROTIME)
	MvmManager::This->fatal("MvmThread::delay() - negative time value");

    if (state != TS_RUNNING)
	{
	MvmManager::This->warning("MvmThread::delay() - thread not running");
	return;
	}

    setTime(MvmClock + t);

    if (!sched->first() || sched->first()->getTime() > getTime())
	{
#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    MvmDebug << MvmClock << " THREAD " << ifGetName()
		     <<	" @" << this << " delayed of " << t << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	if (onStackOverflow())
	    MvmManager::This->fatal("thread stack overflow");

	// The system clock must be updated ***before*** the callouts are
	// invoked, as they may resume some threads (thus need an accurate
	// value of the simulation clock).
	MvmClock = getTime();

	runChain.callouts.apply(&MvmCallout::process);

	return;
	}

    sched->insert(this);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	{
	MvmDebug << MvmClock << " THREAD " << ifGetName()
		 << " @" << this << " delayed of " << t << '\n';

	if (globalTrace > 1)
	    printRunChain();
	}
#endif // CONFIG_XENO_MVM_DEBUG
    
    if (this == currentThread)
	{
	if (onStackOverflow())
	    MvmManager::This->fatal("thread stack overflow");

	sched->schedule();

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " THREAD " << ifGetName()
		     <<	" @" << this << " resuming after delay\n";

	    if (globalTrace > 1)
		printRunChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG
	}
}

void MvmThread::suspend ()

{
    switch(state)
	{
	case TS_RUNNING:

	    if (currentThread != this)
		sched->remove(this);

	case TS_PREEMPTED:
	case TS_PENDING:

	    setState(TS_IDLE);

	case TS_IDLE:

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (globalTrace > 0)
		{
		MvmDebug << MvmClock << " THREAD " << ifGetName()
			 <<	" @" << this << " suspended\n";

		if (globalTrace > 1)
		    printRunChain();
		}
#endif // CONFIG_XENO_MVM_DEBUG

	    break;
	}

    if (this == currentThread)
	{
	if (onStackOverflow())
	    MvmManager::This->fatal("thread stack overflow");

	sched->schedule();

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " THREAD " << ifGetName()
		     <<	" @" << this << " resuming after suspension\n";

	    if (globalTrace > 1)
		printRunChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG
	}
}

void MvmThread::pend (MvmSynchro *so)

{
    if (state != TS_RUNNING)
	return;

    if (currentThread != this)
	sched->remove(this);

    pendSynchro = so;
    
    setState(TS_PENDING);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	{
	MvmDebug << MvmClock << " THREAD " << ifGetName()
		 << " @" << this << " pended\n";

	if (globalTrace > 1)
	    printRunChain();
	}
#endif // CONFIG_XENO_MVM_DEBUG

    if (this == currentThread)
	{
	if (onStackOverflow())
	    MvmManager::This->fatal("thread stack overflow");

	sched->schedule();

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " THREAD " << ifGetName()
		     <<	" @" << this << " resuming after pending\n";

	    if (globalTrace > 1)
		printRunChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG
	}
}

void MvmThread::resume (MvmSynchro *so)

{
    sigSynchro = so;
    pendSynchro = NULL;

    switch (state)
	{
	case TS_PREEMPTED:

	    schedTime += MvmClock;
	    break;

	case TS_RUNNING:

	    if (currentThread != this)
		sched->remove(this);

	case TS_IDLE:
        case TS_PENDING:

	    schedTime = MvmClock;
	    break;

	default:

	    MvmManager::This->fatal("MvmThread::resume() - invalid thread"); 
	}

    if (this != currentThread || state != TS_RUNNING)
	sched->insert(this);

    setState(TS_RUNNING);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	{
	MvmDebug << MvmClock << " THREAD " << ifGetName()
		 << " @" << this << " resumed\n";

	if (globalTrace > 1)
	    printRunChain();
	}
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmThread::immediateResume (MvmSynchro *so)

{
    if (this == currentThread)
	return;

    sigSynchro = so;
    pendSynchro = NULL;

    switch(state)
	{
	case TS_PREEMPTED:

	    schedTime += MvmClock;
	    break;

	case TS_RUNNING:

	    sched->remove(this);

	case TS_IDLE:
	case TS_PENDING:

	    schedTime = MvmClock;
	    break;

	default:

	    MvmManager::This->fatal("MvmThread::immediateResume() - invalid thread"); 
	}

    sched->prepend(this);
    setState(TS_RUNNING);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	{
	MvmDebug << MvmClock << " THREAD " << ifGetName()
		 << " @" << this << " resumed immediately\n";

	if (globalTrace > 1)
	    printRunChain();
	}
#endif // CONFIG_XENO_MVM_DEBUG

    currentThread->yield();
}

void MvmThread::yield ()

{
    if (currentThread->onStackOverflow())
	MvmManager::This->fatal("thread stack overflow");

    sched->exchange();
}

MvmSynchro *MvmThread::waitUntil (MvmSynchro *so,  ITime dt)

{
    sigSynchro = NULL;
    pendSynchro = so;
    timer->set(dt);
    so->pend();

    if (timer->getState() == EXPIRED)
	{
	so->forget(this);
	return NULL;
	}
    else
	{
	timer->reset();
	return so;
	}
}

void MvmThread::wait (MvmSynchro *so)

{
    sigSynchro = NULL;
    pendSynchro = so;
    so->pend();
}

MvmSynchro *MvmThread::waitOr (SynchroGroup *sog)

{
    sigSynchro = NULL;

    MvmSynchroIterator it(*sog);
    MvmSynchro *so;
    
    while ((so = it.next()) != NULL)
	{
	if (so->remember(this))
	    break;
	}
    
    if (so)
	{
	it.reset();

	MvmSynchro *rso;

	while ((rso = it.next()) != so)
	    rso->forget(this);

	sigSynchro = so;

	return so;
	}

    pend(sog);
    
    it.reset();

    while ((so = it.next()) != NULL)
	so->forget(this);
    
    return sigSynchro;
}

MvmSynchro *MvmThread::waitOrUntil (SynchroGroup *sog, ITime dt)

{
    sigSynchro = NULL;

    MvmSynchroIterator it(*sog);
    MvmSynchro *so;
    
    while ((so = it.next()) != NULL)
	{
	if (so->remember(this))
	    {
	    sigSynchro = so;

	    MvmSynchro *rso;

	    it.reset();

	    while ((rso = it.next()) != so)
		rso->forget(this);

	    return sigSynchro;
	    }
	}

    timer->set(dt);

    pend(sog);

    it.reset();

    while ((so = it.next()) != NULL)
	so->forget(this);

    if (timer->getState() == EXPIRED)
	return NULL;

    timer->reset();

    return sigSynchro;
}

void MvmThread::xraise (MvmThreadContext& _context)

{
    if (this == currentThread)
	do_restore(&_context);

    memcpy(&context,&_context,sizeof(_context));
}

void MvmThread::timeout (MvmTimer *tm)

{
    if (state == TS_RUNNING && currentThread != this)
	sched->remove(this);

    MvmTimed::resume();

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	{
	MvmDebug << MvmClock << " THREAD " << ifGetName()
		 << " @" << this << " resumed on timeout\n";

	if (globalTrace > 1)
	    printRunChain();
	}
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmThread::print (MvmStream& ios)

{
    ios << "THREAD " << ifGetName() <<
	" @" << this << " state " << state << " pri " << getPrio();

    if (state == TS_RUNNING)
	ios << " scheduled at " << getTime() << " after "
	    << (MvmThread*)prev() << '\n';
}

void MvmThread::ifInit ()

{
    const char *stateArray[5];
    stateArray[0] = "DEAD";
    stateArray[1] = "IDLE";
    stateArray[2] = "PENDING";
    stateArray[3] = "PREEMPT";
    stateArray[4] = "RUNNING";
    defineStates(sizeof(stateArray) / sizeof(stateArray[0]),stateArray);
    MvmTimed::ifInit();
}

int MvmThread::stateIndex (int s)

{ return s < 2 ? 0 : s - 7; }

void MvmThread::prioritize (int incr)

{
    if (incr < -MVM_THREAD_BASEPRI)
	return;

    setPrio(MVM_THREAD_BASEPRI + incr);

    if (state == TS_RUNNING && this != currentThread)
	{
	sched->remove(this);
	sched->insert(this);
	}
}

void MvmThread::renice (int incr)

{
    prioritize(incr);

#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	MvmDebug << MvmClock << " THREAD " << ifGetName()
		 << " @" << this << " priority changed to " << getPrio() << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

    sched->insert(currentThread);

    if (sched->first() != currentThread)
	{
	if (onStackOverflow())
	    MvmManager::This->fatal("thread stack overflow");

	sched->schedule();
	}
    else
	sched->get();
}

// MvmThread::bumpInto() temporarily restores the thread's stack
// context to have a "bump handler" execute on behalf of it, without
// altering the run chain. The bump handler *must not* alter the
// overall scheduler state, including the creation or destruction of
// any thread. This call is provided for internal use only, especially
// for implementing a debugger.

void MvmThread::bumpInto ()

{
    if (currentThread == this)
	{
	// already on behalf of the right context -
	// call the bump handler directly.
	bumpHandler();
	return;
	}

    if (do_save(&currentThread->context))
	return;

    bumpCaller = currentThread;
    currentThread = this;
    do_restore(&context);
}

#ifdef CONFIG_XENO_MVM_DEBUG

int MvmThread::globalTrace = 0;

void MvmThread::setGlobalTrace (int traceLevel) {

    globalTrace = traceLevel;
}
#endif // CONFIG_XENO_MVM_DEBUG

extern int _etext, _edata, _end;

// Data, bss or heap

#define in_data_p(addr,len) ((char *)addr >= (char *)&_etext && \
			     (char *)addr + len < (char *)sbrk(0))
// Main text section
#define	in_text_p(addr,len) ((char *)addr < (char *)&_etext && \
		             (char *)addr + len < (char *)&_etext)

// MvmThread::checkMemory() tests whether a memory region belongs to
// the text, data, bss, heap or stack space of the current thread.
// This test does not encompass the shared objects.

int MvmThread::checkMemory (const void *addr,
			    unsigned length,
			    int type)
{
    if (!length) // always ok
	return 1;

    // TEXT ONLY

    if (type == MEMADDR_TEXT)
	return in_text_p(addr,length);

    // DATA or CONST

    if (in_data_p(addr,length) || onStack((caddr_t)addr))
	return 1;

    if (type == MEMADDR_READABLE)
	// Non-writable objects (e.g. strings) may be laid in the TEXT
	// section by the compiler to enforce constness.  Warning:
	// this test does not encompass the shared objects!
	return in_text_p(addr,length);

    return 0;
}

int MvmThread::onStack (const caddr_t addr) const

{
    // WARNING: This code does not work for the main thread.

#ifdef HAVE_DOWNWARDING_STACK
    return ((caddr_t)addr > stackGuard && (caddr_t)addr < stackTop);
#else  // HAVE_UPWARDING_STACK
    return ((caddr_t)addr < stackGuard && (caddr_t)addr >= stackBase);
#endif
}

void MvmUndertaker::body ()

{
    for (;;)
	{
	suspend();

	MvmThread *dead;

	while ((dead = morgue.get()) != NULL)
	    {
	    if (dead->getState() == TS_RUNNING)
		dead->sched->remove(dead);
	    
	    dead->setState(DEAD);
	    delete dead;
	    }
	}
}

void printRunChain ()

{
    MvmThread *th = (MvmThread *)MvmThread::runChain.first();

    MvmDebug << "*** RUN CHAIN: first @"
	     << th
	     << ", last @" << (MvmThread *)MvmThread::runChain.last()
	     << ", running @" << MvmThread::currentThread
	     << " (" << MvmThread::currentThread->ifGetName() << ")"
	     << "\n";

    while(th)
	{
	MvmDebug << "     ";
	th->print(MvmDebug);
	MvmDebug.flush();
	th = (MvmThread*)th->next();
	}

    MvmDebug << "***\n";
}

// XenoThread -- A Xenoscope-aware thread.

XenoThread::XenoThread (void *_tcbarg,
			void *_faddr,
			int _pflags,
			const char *_name) :
    MvmThread(_name,_pflags|MVM_THREAD_CLIENT,32768)
{
    tcbarg = _tcbarg;
    faddr = _faddr;
    imask = 0;
    started = 0;
    resetTracking();

    if (!ifTestStatus(MVM_THREAD_NOJOIN))
	allJoinableThreads.append(this);

    allXenoThreads.append(this);
}

XenoThread::XenoThread (const char *_name) :
    MvmThread(_name,MVM_IFACE_HIDDEN,32768)
{
    tcbarg = NULL;
    faddr = NULL;
    imask = 0;
    started = 0;
    resetTracking();
    allXenoThreads.append(this);
}

XenoThread::~XenoThread ()

{
    allXenoThreads.remove(this);

    if (ifTestStatus(MVM_THREAD_CLIENT) &&
	!ifTestStatus(MVM_THREAD_NOJOIN))
	{
	allJoinableThreads.remove(this);
	allClientJoiners.apply(&XenoThread::resume);
	}
}

void XenoThread::ifInit ()

{
    if (!ifIsExportable())
	return;

    const char *entryPoint = NULL;

    if (MvmManager::namelist)
	{
	struct tosh_symbol *symbol;

	symbol = tosh_searchsymtab2(MvmManager::namelist,
				    faddr,
				    TOSH_SYM_TEXT);
	if (symbol)
	    entryPoint = tosh_getcanonsym(symbol->name);
	}

    MvmThreadExportMsg tem(this,entryPoint);

    ifExport(&tem,sizeof(tem));
}

void XenoThread::trackFrame (int tag)

{
    if (tag & MVM_FRAME_EXIT2)
	{
	// Tail returning function -- i.e. the current function is
	// about to return an expression which contains a function
	// call -- update the frame level but do not trigger any break
	// condition to let the inner code decide of it.

	frameLevel--;
	
	if ((traceFlags & (MVM_STEP_INTO|MVM_STEP_OVER)) &&
	    trackedLevel > frameLevel)
	    trackedLevel = frameLevel;
	
	return;
	}

    if (tag & MVM_FRAME_EXIT)
	{
	frameLevel--;

	// If running a step over/into inside the exiting frame,
	// decrease the tracked level down to the caller's frame level
	// to ensure a stop condition will be met when the next
	// instruction from the calling function is reached. One
	// should note that frameTest() is not called if running
	// outside this context to prevent the break condition to be
	// triggered while exiting a step over a function call. If we
	// are stepping out, just check for a break condition after
	// the frame level has been updated.

	if (traceFlags & MVM_STEP_FLAGS)
	    {
	    if (traceFlags & MVM_STEP_OUT)
		{
		if (MvmManager::This->testTag(tag))
		    frameTest();
		}
	    else if (trackedLevel > frameLevel)
		{
		trackedLevel = frameLevel;

		if (MvmManager::This->testTag(tag))
		    frameTest();
		}
	    }
	}
    else
	{
	frameLevel++;

	if (MvmManager::This->testTag(tag))
	    {
	    if (MvmManager::This->testBreak(MVM_CREG_IBREAK))
		MvmManager::This->setBreakState();
	    else if (traceFlags & MVM_STEP_FLAGS)
		frameTest();
	    }
	}
}

void XenoThread::frameTest ()

{
    if (traceFlags & MVM_STEP_OUT)
	{
	if (frameLevel < trackedLevel)
	    {
	    traceFlags &= ~MVM_STEP_OUT;
	    MvmManager::setBreakState();
	    }
	}
    else
	{
	if (!(traceFlags & MVM_STEP_ASYNCH) &&
	    MvmManager::predicate(MVM_ON_ASYNCH))
	    return;

	if (traceFlags & MVM_STEP_OVER)
	    {
	    if (frameLevel <= trackedLevel || trackedLevel == 0)
		{
		traceFlags &= ~MVM_STEP_OVER;
		MvmManager::setBreakState();
		}
	    }
	else if (traceFlags & MVM_STEP_INTO)
	    {
	    if (frameLevel >= trackedLevel)
		{
		traceFlags &= ~MVM_STEP_INTO;
		MvmManager::setBreakState();
		}
	    }
	}
}

// XenoThread::bumpHandler() forces the internal debugging breakpoint
// to be hit in order to make the debug engine regain control. This is
// the 2nd part of a 3 steps protocol:
// - The debuggee (i.e. this simulation process) hits a breakpoint
// somewhere in the code (maybe the internal one) and control is
// passed to the debug engine;
// - The debug engine invokes the XenoThread::bumpInto() method for
// any simulation thread of interest through the mwm_switch() routine
// making the bump handler run and the internal breakpoint being hit
// (possibly recursively).
// From this point, the debug engine can query some information in the
// stack context of the target thread.
// - When done, the debug engine "continues" execution of the debuggee
// until it exits from the mwm_switch() routine. The PC should have
// been reset to the point the initial breakpoint left it.

void XenoThread::bumpHandler () {
    
    MvmManager::breakpoint();
}

void XenoThread::stepOver (int flags)

{
    traceFlags |= MVM_STEP_OVER;

    if (flags & MVM_CREG_TRACE_ASYNCH)
	traceFlags |= MVM_STEP_ASYNCH;
	
    trackedLevel = frameLevel;
}

void XenoThread::stepInto (int flags)

{
    traceFlags |= MVM_STEP_INTO;

    if (flags & MVM_CREG_TRACE_ASYNCH)
	traceFlags |= MVM_STEP_ASYNCH;
	
    trackedLevel = frameLevel;
}

void XenoThread::stepOut ()

{
    traceFlags |= MVM_STEP_OUT;
    trackedLevel = frameLevel;
}

void XenoThread::stepInherit (XenoThread *thread)

{
    traceFlags = thread->traceFlags;
    trackedLevel = frameLevel;
}

const char *XenoThread::getContextString ()

{
    contextString.format("thread %lu %d %llu %s",
			 oid,
			 imask,
			 MvmManager::jiffies(),
			 MvmManager::threadmode(tcbarg));

    return contextString;
}

void XenoThread::kroot(trampoline) (void *tcbarg) {

    MvmManager::trampoline(tcbarg);
}

void XenoThread::body ()

{
    if (do_save(&tryEnv))		// Restarting?
	MVM_CR_IMASK = imask;

    started = 1;
    runningThread = this;
    kroot(trampoline)(tcbarg);
}

void XenoThread::suspend ()

{
    // Current thread's imask is saved since Xenoscope's focus can be
    // switched back and forth to any existing threads, so we cannot
    // report the thread's interrupt level using MVM_CR_IMASK, which
    // merely gives the current (system-wide) masking value in the
    // context of the last executing thread only.
    // Testing whether a running thread is valid or not in this context
    // may seem weird, but it's needed -- really ! (the first
    // XenoThread is in fact suspended by a mere MvmThread before it
    // enters its body).

    if (runningThread == this && ifTestStatus(MVM_THREAD_CLIENT))
	runningThread->imask = MVM_CR_IMASK;

    holdChain.remove(this);
    MvmThread::suspend();

    if (MvmThread::currentThread == this)
	{
	runningThread = this;

	if (ifTestStatus(MVM_THREAD_CLIENT))
	    MVM_CR_IMASK = imask;
	}
}

void XenoThread::resume ()

{
    if (schedLock > 0)
	{
	holdChain.append(this);
#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " XENOTHREAD " << ifGetName()
		     << " @" << this << " held\n";
	    
	    if (globalTrace > 1)
		printRunChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG
	}
    else
	MvmThread::resume();
}

void XenoThread::delay (ITime t)

{
    if (runningThread == this && ifTestStatus(MVM_THREAD_CLIENT))
	imask = MVM_CR_IMASK;

    MvmThread::delay(t);

    if (MvmThread::currentThread == this)
	{
	if (ifTestStatus(MVM_THREAD_CLIENT))
	    MVM_CR_IMASK = imask;

	runningThread = this;
	}
}

void XenoThread::yield ()

{
    if (runningThread == this && ifTestStatus(MVM_THREAD_CLIENT))
	imask = MVM_CR_IMASK;

    MvmThread::yield();

    if (MvmThread::currentThread == this)
	{
	if (ifTestStatus(MVM_THREAD_CLIENT))
	    MVM_CR_IMASK = imask;

	runningThread = this;
	}
}

void XenoThread::lockSched ()

{
    if (schedLock++ == 0)
	{
	MvmThread *thread, *nthread;

	for (thread = (MvmThread *)runChain.first();
	     thread; thread = nthread)
	    {
	    nthread = (MvmThread *)thread->next();

	    if (thread->ifTestStatus(MVM_THREAD_CLIENT))
		{
		thread->MvmThread::preempt();
		holdChain.append(thread);
		}
	    }
#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " XENOTHREAD " << MvmThread::currentThread->ifGetName()
		     << " @" << MvmThread::currentThread << " locked scheduler\n";
	    
	    if (globalTrace > 1)
		printRunChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG
	}
}

void XenoThread::unlockSched ()

{
    if (--schedLock == 0)
	{
	XenoThread *thread;

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " XENOTHREAD " << MvmThread::currentThread->ifGetName()
		     << " @" << MvmThread::currentThread << " unlocking scheduler\n";
	    
	    if (globalTrace > 1)
		printRunChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG

	while ((thread = holdChain.get()) != NULL)
	    thread->MvmThread::resume();
	}
}

void XenoThread::joinClientThreads ()

{
    allClientJoiners.append(this);

    // Simulate the root thread activity by waiting for interrupts
    // from the MvmIrqManager. This is done by actually suspending the
    // simulated root thread :o). Each time the real-time subsystem is
    // idle, the virtual CPU is given to us (i.e. the root thread),
    // making the following loop resume from suspension.

    while (allJoinableThreads.getCount() > 1)
    {
	MVM_CR_IMASK = 0;
	MvmIrqManager::This->dispatchIrq();
	suspend();
    }

    allClientJoiners.remove(this);
}
