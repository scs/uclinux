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
 * Author(s): tb
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include "vm/stream.h"
#include "vm/daemon.h"
#include "vmutils/statobj.h"

int MvmDaemon::globalTrace = 0;

int MvmDaemon::fire (int ord)

{
#ifdef CONFIG_XENO_MVM_DEBUG
    if (MvmDaemon::globalTrace > 0)
	MvmDebug << MvmClock << " DAEMON " << this
		 << " firing order " << ord << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

    body();
    nFires++;
    ord++;

    if (_next)
	ord = _next->fire(ord);

    return ord;
}

MvmDaemon *MvmDaemon::addDaemon(MvmDaemon *doit)

{
    if (!doit)
	return this;

    if (doit->_next)
	{
	MvmDaemon *hell = this;

	while(doit)
	    {
	    MvmDaemon *devil = doit->_next;
	    doit->_next = 0;
	    hell = hell->addDaemon(doit);
	    doit = devil;
	    }

	return hell;
	}
    
    if (doit->_prio > _prio)
	{
	doit->_next = this;

#ifdef CONFIG_XENO_MVM_DEBUG
	if (MvmDaemon::globalTrace > 1)
	    MvmDebug << "DAEMON " << doit  << " prio " << doit->_prio
		     << " before " << this << " prio " << _prio << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	return doit;
	}

    if (_next)
	_next = _next->addDaemon(doit);
    else
	_next = doit;

#ifdef CONFIG_XENO_MVM_DEBUG
    if (MvmDaemon::globalTrace > 1)
	MvmDebug << "DAEMON " << this  << " prio " << _prio
		 << " before " << _next << " prio " << _next->_prio << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

    return this;
}

MvmDaemon *MvmDaemon::remDaemon (MvmDaemon *didit)

{
    if (!didit)
	return this;
    
    if (didit == this)
	{
	didit = didit->_next;
	return didit;
	}
    else
	{
	MvmDaemon *devil = this;

	while(devil && (devil->_next != didit))
	    devil = devil->_next;

	if (devil)
	    devil->_next = didit->_next;

	return this;
	}
}

MvmDaemon *MvmDaemon::isLinked (MvmDaemon *devil) const

{
    MvmDaemon *daemon = (MvmDaemon *)this; // hummm...

    while (daemon && daemon != devil)
	daemon = daemon->_next;

    return daemon;
}

MvmIntegratorInc::MvmIntegratorInc (MvmObject *so, MvmIntegrator *ti)
    : MvmDaemon(0)
{
    sysObj = so;
    integ = ti;
}

void MvmIntegratorInc::body()

{ integ->inc(); }

MvmIntegratorDec::MvmIntegratorDec (MvmObject *so, MvmIntegrator *ti)
    : MvmDaemon(0)
{
    sysObj = so;
    integ = ti;
}

void MvmIntegratorDec::body()

{ integ->dec(); }

void MvmDaemon::setGlobalTrace (int traceLevel)

{ globalTrace = traceLevel; }
