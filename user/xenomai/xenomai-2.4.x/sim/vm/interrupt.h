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
 * Description:  Interface to the interrupt management classes.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvm_interrupt_h
#define _mvm_interrupt_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vm/trigger.h"
#include "vm/manager.h"

#define MVM_IRQ_LEVELS     7	// max. interrupt levels

#define MVM_IRQ_BUSY       0x01 // IRQ is currently processed
#define MVM_IRQ_ONESHOT    0x02 // IRQ is raised once then destroyed
#define MVM_IRQ_ZOMBIE     0x04 // IRQ is about to be destroyed
#define MVM_IRQ_PENDING    0x08 // IRQ is pending
#define MVM_IRQ_MASKED     0x10 // IRQ is masked

class MvmTrigger;
class MvmGraph;

struct MvmIrq : public MvmObject {

    friend class MvmIrqManager;

protected:

    virtual ~MvmIrq();

public:

    int level;

    int statusWord;

    MvmTrigger *trigger;	// NULL allowed

    enum MvmSourceType sourceType;

    void *cookie;

    void (*handler)(int level,
		    void *cookie);

    MvmIrq(int level,
	   void (*handler)(int level,
			   void *cookie),
	   void *cookie,
	   const char *name =NULL);

    int tstStatus(int mask) const {
	return (statusWord & mask);
    }

    void setStatus(int mask) {
	statusWord |= mask;
    }

    void clrStatus(int mask) {
	statusWord &= ~mask;
    }

    int getLevel() {
	return level;
    }

    MvmTrigger *getTrigger() {
	return trigger;
    }

    void setTrigger(enum MvmSourceType law,
		    MvmTrigger *trigger);

    int configure(enum MvmSourceType law,
		  const char *parameter);

    virtual void ifInit();

    virtual void dynamicTrigger(MvmInterfaceInfoMsg *mbuf);
};

MakeGList(MvmIrq);

class MvmIrqManager : public XenoThread {

protected:

    MvmGraph *graph;

    MvmIrq *currentIrq;

    MvmIrqGList picq;

    void kisrt(doIrqs)();

public:

    static MvmIrqManager *This;

    MvmIrqManager();

    void postIrq(MvmIrq *irq) {

	if (!irq->tstStatus(MVM_IRQ_PENDING))
	    {
	    // IRQ is raised once for a given interrupt.
	    irq->setStatus(MVM_IRQ_PENDING);
	    picq.insert(irq,irq->level);
	    }
    }

    MvmIrq *getCurrentIrq() {
	return currentIrq;
    }

    int onHandlerP () {
	return !!getCurrentIrq();
    }

    void dispatchIrq() {

	if (picq.getCount() == 0)
	    return;

	if (currentIrq == NULL)
	    // Outer level interrupt pending -- wake the manager up to
	    // process it (never preempt the caller using
	    // immediateResume() because this would have undesirable
	    // side-effects).
	    resume();
	else
	    {
	    // Should the currently current IRQ be preempted by a
	    // pending interrupt?  **Warning: carefully test for the
	    // current XenoThread to be the interrupt manager;
	    // otherwise, we could badly recurse on behalf of a mere
	    // MVM thread, which would in turn wreck the kernel state
	    // consistency.

	    if (XenoThread::runningThread == this &&
		currentIrq->level < picq.first()->level)
		kisrt(doIrqs)(); // Recurse.
	    }
    }

    virtual void resume() {
	MvmThread::resume(); // Bypass the XenoThread layer.
    }

    void destroyIrq(MvmIrq *irq);

    virtual void body();

    virtual const char *getContextString();
};

#endif // !_mvm_interrupt_h
