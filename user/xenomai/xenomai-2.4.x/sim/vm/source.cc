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
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include "vm/source.h"
#include "vm/manager.h"

int MvmSource::globalTrace = 0;

MvmSourceManager *MvmSourceManager::This = NULL;

MvmSchedSlave MvmSource::sourceChain;

MvmRandLaw MvmPerSource::randInit(RAND);

MvmSourceManager::MvmSourceManager () :
    MvmThread("Source manager",MVM_IFACE_HIDDEN)
{
    This = this;
    
#ifdef CONFIG_XENO_MVM_DEBUG
    if (MvmSource::globalTrace > 1)
	MvmDebug << "SOURCE MANAGER created\n";
#endif // CONFIG_XENO_MVM_DEBUG
}

void MvmSourceManager::body ()

{
    ITime tNext;

    for(;;)
	{
	MvmSource *so = (MvmSource *)MvmSource::sourceChain.first();

	if (!so)
	    {
#ifdef CONFIG_XENO_MVM_DEBUG
	    if (MvmSource::globalTrace > 0)
		MvmDebug << MvmClock << " SOURCE MANAGER idle\n";
#endif // CONFIG_XENO_MVM_DEBUG

	    suspend();

#ifdef CONFIG_XENO_MVM_DEBUG
	    if (MvmSource::globalTrace > 0)
		MvmDebug << MvmClock << " SOURCE MANAGER resumed\n";
#endif // CONFIG_XENO_MVM_DEBUG

	    continue;
	    }

	tNext = so->getTime();

	if (tNext < MvmClock)
	    MvmManager::This->fatal("MvmSourceManager::body() - preposterous time value");

	if (tNext == MvmClock)
	    {
	    so = (MvmSource *)MvmSource::sourceChain.get();
	    so->activate();
	    continue;
	    }

	schedTime = tNext;
	MvmSource::sourceChain.setTNext(tNext);

#ifdef CONFIG_XENO_MVM_DEBUG
	if (MvmSource::globalTrace > 0)
	    {
	    MvmDebug << MvmClock << " SOURCE MANAGER scheduled at "
		     << tNext << " for " << so << '\n';

	    if (MvmSource::globalTrace > 1)
		MvmSource::printSourceChain();
	    }
#endif // CONFIG_XENO_MVM_DEBUG

	delay(tNext - MvmClock);
	}
}

MvmSource::MvmSource (MvmInfo *_msgTempl,
		      MvmNumericLaw *_law,
		      MvmQueue *_destQ,
		      int _ngen,
		      const ITime& _tStart,
		      const ITime& _tEnd,
		      int _prio,
		      int _fAutoDelete) :
    MvmTimed(NULL,&sourceChain)
{
    msgTempl = _msgTempl;
    law = _law;
    ngen = _ngen;
    tEnd = _tEnd;
    out = _destQ;
    fAutoDelete = _fAutoDelete;
    setPrio(_prio);

    if (_tStart >= ZEROTIME)
	{
	if (_tStart > ZEROTIME)
	    schedTime = _tStart;
	else
	    schedTime = MvmClock + ITime(law->get());

	sched->insert(this);

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    MvmDebug << "SOURCE " << ifGetName() << " " << this
		     << " created and scheduled at "
		     << schedTime << '\n';
#endif // CONFIG_XENO_MVM_DEBUG

	sched->schedule();
	}
#ifdef CONFIG_XENO_MVM_DEBUG
    else if (globalTrace > 0)
	MvmDebug << "SOURCE " << this << " created\n";
#endif // CONFIG_XENO_MVM_DEBUG
}

MvmSource::~MvmSource ()

{
    delete msgTempl;

    if (sourceChain.isLinked(this))
	sourceChain.remove(this);
}

void MvmSource::activate ()

{
#ifdef CONFIG_XENO_MVM_DEBUG
    if (globalTrace > 0)
	MvmDebug << MvmClock << " SOURCE " << ifGetName()
		 << " " << this  << " activated\n";
#endif // CONFIG_XENO_MVM_DEBUG

    for (int i = 0; i < ngen; i++)
	out->put(msgTempl->clone());

    ITime tgap(law->get());

    if (tgap != MAXITIME &&
	(schedTime = MvmClock + tgap) <= tEnd)
	{
	sched->insert(this);

#ifdef CONFIG_XENO_MVM_DEBUG
	if (globalTrace > 0)
	    MvmDebug << MvmClock << " SOURCE " << ifGetName()
		     << " " << this << " scheduled at " << schedTime << '\n';
#endif // CONFIG_XENO_MVM_DEBUG
	}
    else
	finalize();

    sched->schedule();
}

void MvmSource::finalize ()

{
    if (fAutoDelete)
	delete this;
}

void MvmSource::print (MvmStream& ios)

{
    ios << "SOURCE " << ifGetName() << " " <<  this << " scheduled at "
	<< getTime() << " msgTempl " << msgTempl << " by " << ngen
	<< " dest queue " << out << '\n';

    ios.flush();
}

void MvmSource::printSourceChain ()

{
    MvmDebug << "SOURCE CHAIN / " << sourceChain.getCount() << " linked\n";

    for (MvmSource *s = (MvmSource *)sourceChain.first();
	 s; s = (MvmSource *)s->next())
	{
	MvmDebug << "     ";
	s->print(MvmDebug);
	}

    MvmDebug.flush();
}

void MvmSource::setGlobalTrace (int traceLevel)

{ globalTrace = traceLevel; }

MvmPerSource::MvmPerSource (ITime _period,
			    MvmInfo *_msgTempl,
			    MvmQueue *_destQ,
			    int _ngen,
			    const ITime& _tStart,
			    const ITime& _tEnd,
			    int _prio) :
    MvmSource(_msgTempl,
	      new MvmNumericLaw(_period),
	      _destQ,
	      _ngen,
	      NEGTIME,
	      _tEnd,
	      _prio)
{
    period = _period;

    if (_tStart <= ZEROTIME)
	// 1st event scheduled at a random time *within* the source period.
	schedTime = MvmClock + _period * randInit.get();
    else
	schedTime = _tStart;
    
    sched->insert(this);
    sched->schedule();
}

MvmPerSource::~MvmPerSource () {

    delete law;
}

void MvmPerSource::print (MvmStream& ios)

{
    ios << "SOURCE PER " << ifGetName() << " " << this
	<< " period " << period << " scheduled at " << getTime()
	<< " msgTempl " << msgTempl << " by " << ngen
	<< " dest queue " << out << '\n';
    
    ios.flush();
}

MvmUniSource::MvmUniSource (ITime _ltBound,
			    ITime _rtBound,
			    MvmInfo *_msgTempl,
			    MvmQueue *_destQ,
			    int _ngen,
			    const ITime& _tStart,
			    const ITime& _tEnd,
			    int _prio) :
    MvmSource(_msgTempl,
	      new MvmUniLaw(_ltBound,_rtBound,RAND),
	      _destQ,
	      _ngen,
	      NEGTIME,
	      _tEnd,
	      _prio)
{
    tmin = _ltBound;
    tmax = _rtBound;

    if (_tStart <= ZEROTIME)
	schedTime = MvmClock + ITime(law->get());
    else
	schedTime  = _tStart;
    
    sched->insert(this);
    sched->schedule();
}

MvmUniSource::~MvmUniSource () {

    delete law;
}

void MvmUniSource::print (MvmStream& ios)
    
{
    ios << "SOURCE UNI " << ifGetName() << " " << this
	<< " bounds " << tmin << "/" << tmax << " scheduled at "
	<< getTime() << " msgTempl " << msgTempl << " by " << ngen
	<< " dest queue " << out << '\n';
    
    ios.flush();
}

MvmExpSource::MvmExpSource(ITime _tMean,
			   MvmInfo *_msgTempl,
			   MvmQueue *_destQ,
			   int _ngen,
			   const ITime& _tStart,
			   const ITime& _tEnd,
			   int _prio) :
    MvmSource(_msgTempl,
	      new MvmExpLaw(_tMean,RAND),
	      _destQ,
	      _ngen,
	      NEGTIME,
	      _tEnd,
	      _prio)
{
    tmean = _tMean;
    
    if (_tStart <= ZEROTIME)
	schedTime = MvmClock + ITime(law->get());
    else
	schedTime = _tStart;
    
    sched->insert(this);
    sched->schedule();
}

MvmExpSource::~MvmExpSource () {

    delete law;
}

void MvmExpSource::print (MvmStream& ios)

{
    ios << "SOURCE EXP " << ifGetName() << " " << this
	<< " mean " << tmean << " scheduled at " << getTime()
	<< " msgTempl " << msgTempl << " by " << ngen
	<< " dest queue " << out << '\n';
    
    ios.flush();
}

MvmFileSource::MvmFileSource (const char *_file,
			      MvmInfo *_msgTempl,
			      MvmQueue *_destQ,
			      int _ngen,
			      int _prio) :
    MvmSource(_msgTempl,
	      new MvmFileLaw(_file),
	      _destQ,
	      _ngen,
	      NEGTIME,
	      MAXITIME,
	      _prio) {

    initialize();
}

MvmFileSource::MvmFileSource (FILE *_fp,
			      MvmInfo *_msgTempl,
			      MvmQueue *_destQ,
			      int _ngen,
			      int _prio) :
    MvmSource(_msgTempl,
	      new MvmFileLaw(_fp),
	      _destQ,
	      _ngen,
	      NEGTIME,
	      MAXITIME,
	      _prio) {

    initialize();
}

void MvmFileSource::initialize ()

{
    ITime tgap = law->get();

    if (tgap != MAXITIME)
	{
	schedTime = tgap + MvmClock;
	sched->insert(this);
	sched->schedule();
	}
}

MvmFileSource::~MvmFileSource () {

    delete law; // this will close the file if needed
}

void MvmFileSource::print (MvmStream& ios)

{
    ios << "FILE SOURCE " << ifGetName() << " " << this
	<< " scheduled at " << getTime() << " msgTempl "
	<< msgTempl << " by " << ngen << " dest queue "
	<< out << '\n';
    
    ios.flush();
}
