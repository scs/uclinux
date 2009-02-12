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
 * Author(s): tb
 * Contributor(s): rpm
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifndef _mvm_source_h
#define _mvm_source_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vmutils/clock.h"
#include "vm/numlaws.h"
#include "vm/queue.h"
#include "vm/thread.h"
#include "vm/timed.h"

class MvmSourceManager : public MvmThread {

    friend class MvmManager;

protected:

    MvmSourceManager();

    virtual void body();

public:

    static MvmSourceManager * This;
};

class MvmSource : public MvmTimed {

    friend class MvmSourceManager;

protected:

    MvmInfo *msgTempl;

    MvmNumericLaw *law;

    int ngen;

    int fAutoDelete;

    MvmQueue *out;

    ITime tEnd;

    static int globalTrace;

    virtual void activate();

    virtual void finalize();

public:

    static MvmSchedSlave sourceChain;

    static void printSourceChain();

    static void setGlobalTrace(int traceLevel);

    MvmSource(MvmInfo *msgTempl,
	      MvmNumericLaw *law,
	      MvmQueue *destQ,
	      int ngen =1,
	      const ITime& tStart =ZEROTIME,
	      const ITime& tEnd =MAXITIME,
	      int prio =0,
	      int fAutoDelete =0);

    virtual ~MvmSource();

    virtual void print(MvmStream&);
};

MakeGList(MvmSource);

class MvmPerSource : public MvmSource {

protected:

    ITime period;

    static MvmRandLaw randInit;

public:

    MvmPerSource(ITime period,
		 MvmInfo *msgTempl,
		 MvmQueue *destQ,
		 int ngen =1,
		 const ITime& tStart =ZEROTIME,
		 const ITime& tEnd =MAXITIME,
		 int prio =0);

    virtual ~MvmPerSource();

    virtual void print(MvmStream&);
};

class MvmUniSource : public MvmSource {

protected:

    ITime tmin,
	tmax;

public:

    MvmUniSource(ITime tmin,
		 ITime tmax,
		 MvmInfo *msgTempl,
		 MvmQueue *destQ,
		 int ngen =1,
		 const ITime& tStart =ZEROTIME,
		 const ITime& tEnd =MAXITIME,
		 int prio =0);

    virtual ~MvmUniSource();

    virtual void print(MvmStream&);
};

class MvmExpSource : public MvmSource {

protected:

    ITime tmean;

public:

    MvmExpSource(ITime tmean,
		 MvmInfo *msgTempl,
		 MvmQueue *destQ,
		 int ngen =1,
		 const ITime& tStart =ZEROTIME,
		 const ITime& tEnd =MAXITIME,
		 int prio =0);

    virtual ~MvmExpSource();

    virtual void print(MvmStream&);
};
	
class MvmFileSource : public MvmSource {

protected:

    void initialize();

public:

    MvmFileSource(const char *filename,
		  MvmInfo *msgTempl,
		  MvmQueue *destQ,
		  int ngen =1,
		  int prio =0);

    MvmFileSource(FILE *fp,
		  MvmInfo *msgTempl,
		  MvmQueue *destQ,
		  int ngen =1,
		  int prio =0);

    virtual ~MvmFileSource();

    virtual void print(MvmStream&);
};

#endif // !_mvm_source_h
