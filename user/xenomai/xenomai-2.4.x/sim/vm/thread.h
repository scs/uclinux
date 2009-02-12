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
 * Author(s): tb, rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvm_thread_h
#define _mvm_thread_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <sys/types.h>
#include <ucontext.h>
#include "vmutils/interface.h"
#include "vm/timed.h"
#include "vm/stream.h"

typedef struct MvmThreadContext {

    ucontext_t ucp;
    int jumped;

    MvmThreadContext() {
	jumped = 0;
    }
};

#define do_save(c) \
    ({ (c)->jumped = 0;	 \
       getcontext(&(c)->ucp); \
       (c)->jumped; })

#define do_restore(c) \
do { \
   (c)->jumped = 1;	  \
   setcontext(&(c)->ucp); \
} while(0)

// Flags to check for memory address validity for a given thread
#define MEMADDR_TEXT      1	// address in executable section
#define MEMADDR_WRITABLE  2	// object laid in writable memory
#define MEMADDR_READABLE  3	// const object from DATA or TEXT section

#define MVM_STEP_OVER    0x01
#define MVM_STEP_INTO    0x02
#define MVM_STEP_OUT     0x04
#define MVM_STEP_ASYNCH  0x08 // <= Cumulative with Over/Into

#define MVM_STEP_FLAGS (MVM_STEP_OVER|\
			MVM_STEP_INTO|\
			MVM_STEP_OUT|\
			MVM_STEP_ASYNCH)

#define MVM_THREAD_BASEPRI 100

#define MVM_THREAD_CLIENT  (MVM_IFACE_AVAIL << 0) // Not an internal thread
#define MVM_THREAD_NOJOIN  (MVM_IFACE_AVAIL << 1) // Thread is not joinable

class MvmThread;
class MvmSynchro;
class SynchroGroup;
class MvmTimer;

struct xnthread;

class MvmThread : public MvmTimed {

    friend class MvmUndertaker;
    friend class MvmSynchro;

private:

    MvmThreadContext context;

    caddr_t stackBase,
	stackTop,
	stackGuard;

    unsigned stackSize;

    MvmTimer *timer;

    MvmSynchro *pendSynchro;	// explicitly pended synchro

    MvmSynchro *sigSynchro;	// last signaled synchro

    MvmThread *bumpCaller;

    MvmThread();

    void spawn();

    static void life();

    virtual void body();

#ifdef CONFIG_XENO_MVM_DEBUG
public:
    static int globalTrace;
    static void setGlobalTrace(int traceLevel);
#endif // CONFIG_XENO_MVM_DEBUG

protected:

    MvmThreadContext tryEnv;

    virtual ~MvmThread();

    virtual void yield();

public :

    static MvmThread *volatile currentThread;

    static MvmThread *mainThread;

    static MvmScheduler runChain;

    MvmThread(const char *name,
	      int pflags =0,
	      unsigned stackSize =32768);

    void resume(MvmSynchro *so);

    void prioritize(int incr);

    void renice(int incr);

    void bumpInto();

    unsigned getStackSize() const {
	return stackSize;
    }

    caddr_t getStackBase() {
	return stackBase;
    }

    int onStackOverflow() {

	if (stackGuard != NULL && *((unsigned *)stackGuard) != 0xdeadbeef) {
	stackGuard = NULL; // Notify once.
	return 1;
	}
	return 0;
    }

    int onStack(const caddr_t addr) const;

    void immediateResume(MvmSynchro *so =0);

    MvmSynchro *waitUntil(MvmSynchro *so,
			  ITime timeout);

    MvmSynchro *waitUntil(MvmSynchro *so) {
	return waitUntil(so,ZEROTIME);
    }

    MvmSynchro *waitOr(SynchroGroup *sog);

    MvmSynchro *waitOrUntil(SynchroGroup *sog,
			    ITime timeout);

#define xtry(context) do_save(&context)

    void xraise(MvmThreadContext& context);

    void print(MvmStream&);

    virtual void ifInit();

    virtual void cancel();

    virtual void pend(MvmSynchro *so);

    virtual void wait(MvmSynchro *so);

    virtual void activate();

    virtual void preempt();

    virtual void delay(ITime delay);

    virtual void suspend();

    virtual void resume() {
	resume(0);
    }

    virtual void timeout(MvmTimer *tm);

    virtual int checkMemory(const void *addr,
			    unsigned length,
			    int type);

    virtual int stateIndex(int);

    virtual void bumpHandler() {
    }
};

MakeGList(MvmThread);

// MvmUndertaker -- a garbage-collector thread destroying
// dead threads. Doing this house-keeping chores this way
// prevents free-memory accesses which would arise if MvmThreads
// attempt to destroy themselves (i.e. well-known stack release problem
// from MvmThread::cancel()).

class MvmUndertaker : public MvmThread {

private:

    MvmThreadGList morgue;

    virtual void body();

public:

    static MvmUndertaker *This;

    MvmUndertaker() : MvmThread("Undertaker",MVM_IFACE_HIDDEN,8192) {
	MvmUndertaker::This = this;
    }

    void bury(MvmThread *thread) {
	morgue.append(thread);
	immediateResume();
    }
};

class XenoThread : public MvmThread {

private:
 
    int traceFlags,
	frameLevel,
	trackedLevel,
	imask,
	started;

    void *tcbarg,
	 *faddr;

    void resetTracking () {
	frameLevel = 0;
	trackedLevel = 0;
	traceFlags = 0;
    }

    virtual void bumpHandler();

    static void kroot(trampoline)(void *tcbarg);

    static int schedLock;

protected:

    virtual ~XenoThread();

    virtual void yield();

public :

    static CString contextString;

    static XenoThread *runningThread;

    static void lockSched();

    static void unlockSched();

    XenoThread(void *tcbarg,
	       void *faddr,
	       int pflags =0,
	       const char *name =NULL);

    XenoThread(const char *name);

    virtual void ifInit();

    void *getTcbArg() {
	return tcbarg;
    }

    int getFrameLevel () const {
	return frameLevel;
    }

    int getTrackLevel() const {
	return trackedLevel;
    }

    int isTraced() const {
	return (traceFlags & MVM_STEP_FLAGS);
    }

    int getIntrMask() const {
	return imask;
    }

    void stepOver(int flags);

    void stepInto(int flags);

    void stepOut();

    void stepInherit(XenoThread *thread);

    void cancelStep () {
	traceFlags &= ~MVM_STEP_FLAGS;
    }

    void joinClientThreads();

    const char *getModeString() const;

    void frameTest();

    void trackFrame(int tag);

    void restart() {
	if (started) {
	resetTracking();
	xraise(tryEnv);
	}
    }

    virtual void body();

    virtual const char *getContextString();

    virtual void suspend();

    virtual void resume();

    virtual void delay(ITime delay);
};

MakeGList(XenoThread);

extern void printRunChain();

extern XenoThreadGList allXenoThreads;

#endif // !_mvm_thread_h
