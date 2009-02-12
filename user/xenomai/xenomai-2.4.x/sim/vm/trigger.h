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

#ifndef _mvm_trigger_h
#define _mvm_trigger_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include "vm/queue.h"

enum MvmSourceType {

    CfEventNull =0,
    CfEventPeriodical,
    CfEventExponential,
    CfEventUniform,
    CfEventFile,
    CfEventTimer,
    CfEventManual
};

class MvmSource;

#define MVM_TRIGGER_MINSTACKSZ 32768

class MvmTrigger : public MvmThread {

protected:

    MvmSource *source;

    void (*handler)(void *);

    void *clientData;

    MvmQueue wakeupQ;

    virtual ~MvmTrigger();

    virtual void body();

public:

    MvmTrigger(void (*handler)(void *),
	       void *clientData =0,
	       unsigned stacksz =MVM_TRIGGER_MINSTACKSZ);

    virtual int isValid() const {
	return !!source;
    }
};

class MvmUniTrigger : public MvmTrigger {

public:

    MvmUniTrigger(void (*handler)(void *),
		  const char *paramString,
		  void *clientData =0,
		  int priority =0,
		  unsigned stacksz =MVM_TRIGGER_MINSTACKSZ);
};

class MvmExpTrigger : public MvmTrigger {

public:

    MvmExpTrigger(void (*handler)(void *),
		  const char *paramString,
		  void *clientData =0,
		  int priority =0,
		  unsigned stacksz =MVM_TRIGGER_MINSTACKSZ);
};

class MvmPerTrigger : public MvmTrigger {

public:

    MvmPerTrigger(void (*handler)(void *),
		  const char *paramString,
		  void *clientData =0,
		  int priority =0,
		  unsigned stacksz =MVM_TRIGGER_MINSTACKSZ);
};

class MvmFileTrigger : public MvmTrigger {

public:

    MvmFileTrigger(void (*handler)(void *),
		   const char *fileName,
		   void *clientData =0,
		   int priority =0,
		   unsigned stacksz =MVM_TRIGGER_MINSTACKSZ);
};

class MvmTimerTrigger : public MvmTrigger {

protected:

    ITime triggerDate;

    virtual void body();

public:

    MvmTimerTrigger(void (*handler)(void *),
		    const char *paramString,
		    void *clientData =0,
		    unsigned stacksz =MVM_TRIGGER_MINSTACKSZ);

    int setTimer(ITime date);

    int setTimer(const char *date);

    virtual int isValid() const;
};

#endif // !_mvm_trigger_h
