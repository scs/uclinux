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
 * Description: Implementation of the interrupt source.
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
#include "vmutils/interface.h"
#include "vm/manager.h"
#include "vm/monitor.h"
#include "vm/interrupt.h"
#include "vm/display.h"

MvmIrqManager *MvmIrqManager::This = NULL;

static const char *stateLabels[] = {
    "THREAD", "IL1", "IL2", "IL3", "IL4", "IL5", "IL6", "IL7", NULL
};

MvmIrqManager::MvmIrqManager () :
    XenoThread("MvmIrq"),
    picq(PRDN)
{
    This = this;
    currentIrq = NULL;
    graph = new MvmGraph("Interrupts",NULL,stateLabels);
    graph->setState(0);
    graph->ifInit();
    prioritize(2);
}

void MvmIrqManager::body ()

{
    for (;;)
	{
	suspend();
	XenoThread::lockSched();
	kisrt(doIrqs)();
	XenoThread::unlockSched();
	}
}

void MvmIrqManager::kisrt(doIrqs) ()

{
    MvmIrqIterator it(picq);
    MvmIrq *irq, *nirq = it.next();

    while ((irq = nirq) != NULL)
	{
	// Interrupts are listed in decreasing priority order -- when
	// an interrupt priority is lower or equal to the current
	// masking level, the following interrupts cannot be candidate
	// for dispatch.

	if (irq->tstStatus(MVM_IRQ_ZOMBIE))
	    {
	    nirq = it.pop();
	    delete irq;
	    continue;
	    }

	if (irq->level <= MVM_CR_IMASK)
	    break;

	// Interrupt is marked as busy until it is destroyed or it
	// returns from its handler. This prevents a postponed IRQ to
	// be destroyed before the rest of the queue is processed.

	irq->setStatus(MVM_IRQ_BUSY);

	if (!irq->tstStatus(MVM_IRQ_MASKED))
	    {
	    it.unlink();

	    MvmIrq *oldIrq = currentIrq;
	    currentIrq = irq;
	    int oldmask = MVM_CR_IMASK;
	    MVM_CR_IMASK = irq->level;
	    irq->clrStatus(MVM_IRQ_PENDING);
	    int oldState = graph->kdoor(sendState)(irq->level); // levels are 1-based
	    irq->handler(irq->level,irq->cookie);
	    graph->kdoor(sendState)(oldState);
	    MVM_CR_IMASK = oldmask;
	    currentIrq = oldIrq;

	    if (irq->tstStatus(MVM_IRQ_ONESHOT|MVM_IRQ_ZOMBIE))
		delete irq;
	    else
		irq->clrStatus(MVM_IRQ_BUSY);
	    }

	nirq = it.next();
	}
}

const char *MvmIrqManager::getContextString ()

{
    XenoThread::contextString.format("ihandler 0 %d %llu",
				     MVM_CR_IMASK,
				     MvmManager::jiffies());
    return XenoThread::contextString;
}

static void schedIrq (void *cookie)

{
    MvmIrqManager::This->postIrq((MvmIrq *)cookie);
    MvmIrqManager::This->dispatchIrq();
}

void MvmIrqManager::destroyIrq (MvmIrq *irq)

{
    if (irq->tstStatus(MVM_IRQ_BUSY))
	// IRQ is under processing -- Mark it as "zombie". A zombie
	// IRQ is disposed when its handler returns.
	irq->setStatus(MVM_IRQ_ZOMBIE);
    else
	{
	// (Null-effect if "irq" was not linked)
	picq.remove(irq);
	delete irq;
	}
}

MvmIrq::MvmIrq (int _level,
		void (*_handler)(int level,
				 void *cookie),
		void *_cookie,
		const char *_name) :
    MvmObject(_name,NULL,MVM_IFACE_HIDDEN,MvmMonitor::This)
{
    level = _level;
    handler = _handler;
    cookie = _cookie ? _cookie : this;
    statusWord = 0;
    trigger = NULL;
    sourceType = CfEventNull;
}

MvmIrq::~MvmIrq () {

    setTrigger(CfEventNull,NULL);
}

void MvmIrq::ifInit ()

{
}

void MvmIrq::dynamicTrigger (MvmInterfaceInfoMsg *mbuf) {

    schedIrq(this);
}

void MvmIrq::setTrigger (enum MvmSourceType _law,
			 MvmTrigger *_trigger)
{
    if (trigger && trigger != _trigger)
	trigger->cancel();

    sourceType = _law;
    trigger = _trigger;
}

int MvmIrq::configure (enum MvmSourceType law,
		       const char *parameter)
{
    MvmTrigger *_trigger = NULL;
    
    switch (law)
	{
	case CfEventPeriodical:

	    _trigger = new MvmPerTrigger(&schedIrq,
					 parameter,
					 this,
					 level);
	    break;

	case CfEventExponential:

	    _trigger = new MvmExpTrigger(&schedIrq,
					 parameter,
					 this,
					 level);
	    break;

	case CfEventUniform:

	    _trigger = new MvmUniTrigger(&schedIrq,
					 parameter,
					 this,
					 level);
	    break;
		
	case CfEventFile:

	    _trigger = new MvmFileTrigger(&schedIrq,
					  parameter,
					  this,
					  level);
	    break;
		
	case CfEventTimer:

	    if (sourceType == CfEventTimer)
		{
		// Recycle timers -- this saves a thread creation each
		// time the timer is reprogrammed.
		((MvmTimerTrigger *)trigger)->setTimer(parameter);
		_trigger = trigger;
		}
	    else
		_trigger = new MvmTimerTrigger(&schedIrq,
					       parameter,
					       this);
	    break;

	default: ;
	}

    setTrigger(law,_trigger);

    return !_trigger || _trigger->isValid() ? 0 : -1;
}
