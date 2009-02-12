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

#ifndef _bridge_h
#define _bridge_h

#if defined(__GNUG__) && !defined(__OBSCAN__)
#pragma interface
#endif // __GNUG__ && !__OBSCAN__

#include <tcl.h>

#include "vmutils/list++.h"
#include "vmutils/tclist++.h"
#include "vmutils/string++.h"
#include "vmutils/hash++.h"

struct Tcl_Interp;
class TkContextList;
class TkContext;

enum TkContextState {

    TkInitContext,
    TkEnterContext,
    TkLeaveContext
};

typedef void *TkClientData;

typedef unsigned long TkEvent;

#define TKCONTEXT_NULL_EVENT ((TkEvent)-1)

typedef void (*TkAppHookProc)(TkContext *context,
			      TkContextState state);

class TkContext : public Link {

private:

    TkContext *tkMaster;
	
    TkContextList *tkSlaves;
	
    CString tkName;

    HashTable eventTable;

    HashTable linkVarTable;

    static CString tclCommand;

    static CString formatString;

    static CString substString;

protected:

    static void formatArgs(const char *format,
			   int retArgs,
			   va_list& ap);

    static int notifyRequest(ClientData clientData,
			     Tcl_Interp *interp,
			     int argc,
			     char *argv[]);

    static void idleProc(ClientData clientData);

    static Tcl_Interp * tclInterp;

    static TkAppHookProc stateProc;
	
    static int stateProcSem;

    static HashTable tkContextTable;

    static HashTable tkModuleTable;

public:

    static CString installRootDir;

    static CString currentExecPath;

    static int debugMode;

    static int modInitialize(char *tclScript);

    static int modInitialize(char **tclScriptArray);

    static int appInitialize(const char *argv0,
			     char *tclScript =0,
			     TkAppHookProc proc =0);

    static int appInitialize(const char *argv0,
			     char **tclScriptArray,
			     TkAppHookProc proc =0);

    static void dumpInstallPathes(FILE *fp); // useful for fixing an installation glitch

    static const char *callTkGlobalProc(const char *proc,
					const char *format =0,
					...);
    static void appRun();

    static Tcl_Interp *getInterp();

    static TkContext *findContext(const char *tkName);

    TkContext(TkContext *tkParent =0);

    virtual ~TkContext();

    const char *getTkName() const {
	return tkName;
    }

    TkContext *getTkMaster() {
	return tkMaster;
    }

    int callTkProc(const char *proc,
		   const char *format =0,
		   ...);

    void setTkResult(const char *format,
		     ...);
    void appendTkResult(const char *format,
			...);

    void handleEvent(const char *name,
		     TkEvent event =TKCONTEXT_NULL_EVENT,
		     TkClientData clientData =0);

    void ignoreEvent(const char *name);

    void ignoreAllEvents();

    int getTkIntResult() const;

    const char *getTkStringResult() const;

    int getTkListResult(TclList& tclist) const;

    int getTkIntVar(const char *varName) const;

    const char *getTkStringVar(const char *varName) const;

    void setTkVar(const char *varName, const char *value);
	
    void linkTkVar(const char *varName, int *varAddr);

    void linkTkVar(const char *varName, double *varAddr);

    void linkTkVar(const char *varName, char **varAddr);

    void updateTkVar(const char *varName);

    void unlinkTkVar(const char *varName);

    void unlinkAllVars();

    virtual void notify(TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData);
};

MakeList(TkContext);

struct TkEventHook {

    TkEvent event;
    TkClientData clientData;

    TkEventHook(TkEvent _event,
		TkClientData _clientData) {
	event = _event;
	clientData = _clientData;
    }
};

#define TKCHANNEL_MBUFSZ  4096
#define Tkio_success      (0)
#define Tkio_linkdown     (-1)
#define Tkio_wouldblock   (-2)

class TkChannel : public LinkedObject {

protected:

    Tcl_Channel channel;

    char *smbuf,
	*dmbuf;

    int dmsize;

public:

    TkChannel(const char *tclName);

    virtual ~TkChannel();

    int send(int mid, const void *mbuf =0, int nbytes =0);

    int poll(void **mbufp, int *ubytes);

    void dispose();
};

#endif // !_bridge_h
