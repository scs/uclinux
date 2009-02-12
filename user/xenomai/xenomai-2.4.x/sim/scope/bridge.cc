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
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#ifdef __GNUG__
#pragma implementation
#endif // __GNUG__
#include <xeno_config.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <memory.h>
#include "vmutils/toolshop.h"
#include "bridge.h"

extern "C" {

int Tk_Init(Tcl_Interp *interp),
    Tix_Init(Tcl_Interp *interp);

void Tk_MainLoop(void);

}

HashTable TkContext::tkContextTable(128);

HashTable TkContext::tkModuleTable(64);

Tcl_Interp *TkContext::tclInterp = NULL;

int TkContext::stateProcSem = 0;

TkAppHookProc TkContext::stateProc = NULL;

CString TkContext::currentExecPath,
        TkContext::installRootDir,
        TkContext::tclCommand,
        TkContext::formatString,
        TkContext::substString;

int TkContext::debugMode = 0; 

#ifndef DEBUG_ENABLED

static RETSIGTYPE faultHandler (int sig)

{
    _exit(99);	// do not cleanup
#if RETSIGTYPE != void
    return (RETSIGTYPE)0;
#endif
}
#endif // !DEBUG_ENABLED

int TkContext::appInitialize (const char *_argv0,
			      char **_tclScriptArray,
			      TkAppHookProc _stateProc)
{
#ifndef DEBUG_ENABLED
    struct sigaction sa;
    sa.sa_handler = (SIGHANDLER_TYPE)&faultHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGSEGV,&sa,NULL);
    sigaction(SIGBUS,&sa,NULL);
#endif // !DEBUG_ENABLED

    currentExecPath = tosh_getselfpath(_argv0);
    installRootDir = currentExecPath.dirname().dirname();

    // Tix has brain-damage install discrepancies across platforms,
    // so help it a bit to locate its Tcl libdir.

    if (!getenv("TIX_LIBRARY") && *TIX_TCL_LIB)
	{
	CString tixLibrary("TIX_LIBRARY=");
	tixLibrary += TIX_TCL_LIB;
	putenv(strdup(tixLibrary));
	}

    if (!tclInterp)
	tclInterp = Tcl_CreateInterp();

    if (!tclInterp ||
	Tcl_Init(tclInterp) != TCL_OK ||
	Tk_Init(tclInterp) != TCL_OK ||
	Tix_Init(tclInterp) != TCL_OK)
	return TCL_ERROR;

    if (installRootDir[0] == '.')
        {
	Tcl_SetResult(tclInterp,"cannot locate installation directory",TCL_STATIC);
	return TCL_ERROR;
	}

    // The following Tcl variable stands for the GNU "prefix" to the
    // Tcl world, not the "exec_prefix".

    if (!Tcl_SetVar(tclInterp,
		    "tkbridge_prefixdir",
		    installRootDir.gets(),
		    TCL_GLOBAL_ONLY))
	return TCL_ERROR;

    CString localPkgDir(installRootDir);
    localPkgDir += "/lib";

    if (!Tcl_SetVar(tclInterp,
		    "auto_path",
		    localPkgDir.gets(),
		    TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE))
	return TCL_ERROR;

    if (modInitialize(_tclScriptArray) != TCL_OK)
        return TCL_ERROR;

    if (!Tcl_CreateCommand(tclInterp,
			   "TkRequest",
			   &TkContext::notifyRequest,
			   NULL,
			   NULL))
	return TCL_ERROR;
    
    stateProc = _stateProc;
    stateProcSem = 0;

    if (Tcl_GlobalEval(tclInterp,"appInitProc") == TCL_ERROR)
	return TCL_ERROR;

    return TCL_OK;
}

int TkContext::appInitialize (const char *_argv0,
			      char *_tclScript,
			      TkAppHookProc _stateProc)
{
    char *tclArray[] = { _tclScript, NULL };
    return appInitialize(_argv0,tclArray,_stateProc);
}

void TkContext::appRun ()

{
    if (stateProc)
	stateProc(NULL,TkInitContext);

    Tk_MainLoop();
}

// modInitialize() can be passed a script directory OR an inline
// tcl script. The way we choose to process it depends on the
// first character of tclScript, '!' standing for an inline
// script, anything else being interpreted as a directory path.

int TkContext::modInitialize (char *_tclScript)

{
    if (!tclInterp)
        {
        tclInterp = Tcl_CreateInterp();

	if (!tclInterp)
	    return TCL_ERROR;
	}

    if (*_tclScript != '!')
        {
	CString modulePath(_tclScript);

	// try to substitute the installdir placeholder in
	// the module path...

	if (modulePath[0] == '@')
	    modulePath.subst(0,0,installRootDir + "/share");

	if (tkModuleTable.enter(modulePath.expand(),tclInterp) < 0)
	    return TCL_OK;	// module already defined - just ok
    
	if (!Tcl_SetVar(tclInterp,
			"auto_path",
			modulePath.gets(),
			TCL_GLOBAL_ONLY|TCL_LIST_ELEMENT|TCL_APPEND_VALUE))
	    return TCL_ERROR;
	}
    else if (Tcl_GlobalEval(tclInterp,_tclScript + 1) != TCL_OK)
	return TCL_ERROR;

    return TCL_OK;
}

int TkContext::modInitialize (char **_tclScriptArray)

{
    for (int n = 0; _tclScriptArray[n]; n++)
	{
	if (modInitialize(_tclScriptArray[n]) != TCL_OK)
	    return TCL_ERROR;
	}

    return TCL_OK;
}

void TkContext::dumpInstallPathes (FILE *fp)

{
    const char *s;

    s = currentExecPath;
    if (s) fprintf(fp,"TkContext::currentExecPath=%s\n",s);
    else   fprintf(fp,"TkContext::currentExecPath unresolved\n");

    s = installRootDir;
    if (s) fprintf(fp,"TkContext::installRootDir=%s\n",s);
    else   fprintf(fp,"TkContext::installRootDir unresolved\n");

    s = getenv("TCL_LIBRARY");
    if (s) fprintf(fp,"TCL_LIBRARY=%s\n",s);
    else   fprintf(fp,"TCL_LIBRARY unset\n");

    s = getenv("TK_LIBRARY");
    if (s) fprintf(fp,"TK_LIBRARY=%s\n",s);
    else   fprintf(fp,"TK_LIBRARY unset\n");

    s = getenv("TIX_LIBRARY");
    if (s) fprintf(fp,"TIX_LIBRARY=%s\n",s);
    else   fprintf(fp,"TIX_LIBRARY unset\n");
}

Tcl_Interp *TkContext::getInterp ()
    
{ return tclInterp; }

TkContext *TkContext::findContext (const char *tkName)
    
{ return (TkContext *)tkContextTable.find(tkName); }

const char *TkContext::callTkGlobalProc (const char *proc,
					 const char *format, ...)
{
    tclCommand.overwrite(proc);
    tclCommand.appendChar(' ');
    
    if (format)
	{
	va_list ap;
	va_start(ap,format);
	formatArgs(format,0,ap);
	va_end(ap);
	tclCommand += formatString;
	}
    
#ifdef DEBUG_ENABLED
    CString currentCommand = tclCommand;
#endif
    
    int rc = Tcl_GlobalEval(tclInterp,tclCommand.gets());
    
#ifdef DEBUG_ENABLED
    if (debugMode)
	printf("TCL-GLOBAL-INVOKE: %s => %d\n",currentCommand.gets(),rc);
#endif

    if (rc != TCL_OK)
	{
	fprintf(stderr,"xenoscope: %s\n",tclInterp->result);
	return NULL;
	}
    
    return tclInterp->result;
}

TkContext::TkContext (TkContext *_tkMaster) :
    eventTable(32), linkVarTable(16)
{
    tkMaster = _tkMaster;
    tkSlaves = NULL;

    if (tkMaster)
	{
	if (!tkMaster->tkSlaves)
	    tkMaster->tkSlaves = new TkContextList;

	tkMaster->tkSlaves->append(this);
	tkName = tkMaster->tkName;
	}

    tkName += CString().format(".c%p",this);
    tkContextTable.enter(tkName,this);
}

TkContext::~TkContext ()

{
    ignoreAllEvents();
    unlinkAllVars();
    
    if (tkMaster)
	tkMaster->tkSlaves->remove(this);

    if (tkSlaves)
	{
	TkContext *tkContext;

	while ((tkContext = tkSlaves->get()) != NULL)
	    {
	    tkContext->tkMaster = NULL;
	    delete tkContext;
	    }

	delete tkSlaves;
	}

    tkContextTable.remove(tkName);
}

void TkContext::handleEvent (const char *name,
			     TkEvent event,
			     TkClientData clientData)
{
    TkEventHook *hook = new TkEventHook(event,clientData);
    
    if (eventTable.enter(name,hook) < 0)
	eventTable.update(name,hook);
}

void TkContext::ignoreEvent (const char *name)

{
    TkEventHook *hook = (TkEventHook *)eventTable.remove(name);

    if (hook)
	delete hook;
}

void TkContext::ignoreAllEvents ()

{
    HashScanner scanner(eventTable);
    TkEventHook *hook;

    while (scanner.forward((void **)&hook))
	delete hook;
}

void TkContext::linkTkVar (const char *varName, int *varAddr)

{
    linkVarTable.enter(varName,varName);
    char *_varName = linkVarTable.getKeyPtr(varName);
    
    if (_varName)
	Tcl_LinkVar(tclInterp,_varName,(char *)varAddr,TCL_LINK_INT);
}

void TkContext::linkTkVar (const char *varName, double *varAddr)

{
    linkVarTable.enter(varName,varName);
    char *_varName = linkVarTable.getKeyPtr(varName);

    if (_varName)
	Tcl_LinkVar(tclInterp,_varName,(char *)varAddr,TCL_LINK_DOUBLE);
}

void TkContext::linkTkVar (const char *varName, char **varAddr)

{
    linkVarTable.enter(varName,varName);
    char *_varName = linkVarTable.getKeyPtr(varName);
    
    if (_varName)
	Tcl_LinkVar(tclInterp,_varName,(char *)varAddr,TCL_LINK_STRING);
}

void TkContext::updateTkVar (const char *varName)

{
    char *_varName = linkVarTable.getKeyPtr(varName);
    
    if (_varName)
	Tcl_UpdateLinkedVar(tclInterp,_varName);
}

void TkContext::unlinkTkVar (const char *varName)

{
    char *_varName = linkVarTable.getKeyPtr(varName);
    
    if (_varName)
	{
	Tcl_UnlinkVar(tclInterp,_varName);
	linkVarTable.remove(varName);
	}
}

void TkContext::unlinkAllVars ()

{
    HashScanner scanner(linkVarTable);
    const char *varName;

    while ((varName = scanner.forward()) != NULL)
	{
	char *_varName = linkVarTable.getKeyPtr(varName);
	Tcl_UnlinkVar(tclInterp,_varName);
	}

    linkVarTable.clear();
}

void TkContext::notify (TkEvent event,
			int argc,
			char *argv[],
			TkClientData clientData)
{}

int TkContext::notifyRequest (ClientData clientData,
			      Tcl_Interp *interp,
			      int argc,
			      char *argv[])
{
    if (argc < 3)
	{
	Tcl_SetResult(interp,
		      "not enough arguments passed to TkRequest",
		      TCL_STATIC);
	return TCL_ERROR;
	}

    TkContext *context = findContext(argv[1]);
    
    if (!context)
	{
	Tcl_SetResult(interp,
		      CString().format("cannot identify target context: %s",argv[1]).gets(),
		      TCL_VOLATILE);
	return TCL_ERROR;
	}
    
#ifdef DEBUG_ENABLED
    if (debugMode)
	printf("TCL-NOTIFY: %s\n",argv[2]);
#endif
    
    TkEventHook *hook = (TkEventHook *)context->eventTable.find(argv[2]);

    if (hook)	// null hook means "not handled" by user
	{
	if (hook->event == TKCONTEXT_NULL_EVENT)
	    return TCL_OK;

	if (stateProc && stateProcSem == 0)
	    {
	    stateProcSem = 1;
	    stateProc(context,TkEnterContext);
	    Tcl_DoWhenIdle(&idleProc,context);
	    }
	
	context->notify(hook->event,
			argc - 2,
			argv + 2,
			hook->clientData);
	}
    else if (!strcmp(argv[2],"destroy"))
	delete context;
    else
	{
	Tcl_SetResult(interp,
		      CString().format("unhandled event: %s",argv[2]).gets(),
		      TCL_VOLATILE);
	return TCL_ERROR;
	}

    return TCL_OK;
}

void TkContext::idleProc (ClientData clientData)

{
    stateProcSem = 0;
    stateProc((TkContext *)clientData,TkLeaveContext);
}

void TkContext::formatArgs (const char *format,
			    int retArgs,
			    va_list& ap)
{
    int phoff = -1;

    formatString.overwrite(format);

    while ((phoff = formatString.match("&",phoff + 1)) >= 0)
	{
	if (phoff > 0 && formatString[phoff - 1] == '\\')
	    {
	    phoff++;
	    continue;
	    }
	
	switch (formatString[phoff + 1])
	    {
	    case 'C': {		// Tk context handle
	    TkContext *context = va_arg(ap,TkContext *);
	    substString.overwrite(context->tkName);
	    break;
	    }
	    case 'D': {		// standard signed decimal value
	    int n = va_arg(ap,int);
	    substString.format("%d",n);
	    break;
	    }
	    case 'U': {		// standard unsigned decimal value
	    int n = va_arg(ap,unsigned);
	    substString.format("%u",n);
	    break;
	    }
	    case 'G': {		// standard double-precision fp value
	    double *gp = va_arg(ap,double *);
	    substString.format("%f",*gp);
	    substString.trimExtraZeroes();
	    break;
	    }
	    case 'L': {		// TclList (Tcl string list)
	    TclList *l = va_arg(ap,TclList *);
	    if (retArgs)
		substString.overwrite(l->get());
	    else
		{
		substString.overwrite("{");
		substString.catenate(l->get(),l->length());
		substString.appendChar('}');
		}
	    break;
	    }
	    case 'S': {		// (possibly null) string
	    const char *s = va_arg(ap,const char *);
	    if (retArgs)
		substString.overwrite(TclList(s));
	    else
		{
		substString.overwrite("\"");
		substString += s;
		substString.appendChar('"');
		}
	    break;
	    }
	    case 'I': {
	    const char *s = va_arg(ap,const char *);
	    substString.overwrite(TclList(s));
	    break;
	    }
	    case 'R': {		// (possibly null) raw string
	    const char *s = va_arg(ap,const char *);
	    int n = va_arg(ap,int);
	    substString.overwrite(s,n);
	    if (substString.len() == 0 && !retArgs)
		substString += "{}";
	    break;
	    }
	    }

	formatString.subst(phoff,phoff + 1,substString);

	if (substString.len() > 0)
	    phoff += (substString.len() - 2);
	}
}

int TkContext::callTkProc (const char *proc,
			   const char *format, ...)
{
    tclCommand.overwrite(proc);
    tclCommand.appendChar(' ');
    tclCommand += tkName;
    tclCommand.appendChar(' ');
    
    if (format)
	{
	va_list ap;
	va_start(ap,format);
	formatArgs(format,0,ap);
	va_end(ap);
	tclCommand += formatString;
	}
    
    CString currentCommand = tclCommand;
    
    int rc = Tcl_GlobalEval(tclInterp,tclCommand.gets());
    
#ifdef DEBUG_ENABLED
    if (debugMode)
	printf("TCL-INVOKE: %s => %d\n",currentCommand.gets(),rc);
#endif

    if (rc != TCL_OK)
	{
	fprintf(stderr,"xenoscope: %s\n",tclInterp->result);
	fprintf(stderr,"proc: %s\n",currentCommand.gets());
	}
    
    return rc;
}

void TkContext::setTkResult (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    formatArgs(format,1,ap);
    va_end(ap);

    Tcl_ResetResult(tclInterp);
    Tcl_AppendResult(tclInterp,(const char *)formatString,NULL);
}

void TkContext::appendTkResult (const char *format, ...)

{
    va_list ap;
    va_start(ap,format);
    formatArgs(format,1,ap);
    va_end(ap);
    Tcl_AppendResult(tclInterp,(const char *)formatString,NULL);
}

const char *TkContext::getTkStringResult () const

{ return tclInterp->result; }

int TkContext::getTkIntResult () const

{ return CString(tclInterp->result).getInt(); }

int TkContext::getTkListResult (TclList& tclist) const

{
    char **vector;
    int n;

    if (Tcl_SplitList(tclInterp,
		      tclInterp->result,
		      &n,
		      &vector) != TCL_OK)
	return -1;

    for (int e = 0; e < n; e++)
	tclist.append(vector[e]);

    Tcl_Free((char *)vector);

    return n;
}

const char *TkContext::getTkStringVar (const char *_varName) const

{
    CString varName(_varName);
    return Tcl_GetVar(tclInterp,varName.gets(),TCL_GLOBAL_ONLY);
}

int TkContext::getTkIntVar (const char *_varName) const

{
    const char *s = getTkStringVar(_varName);
    return s ? atoi(s) : -1;
}

void TkContext::setTkVar (const char *_varName,
			  const char *_value)
{
    if (_value)
	{
	CString varName(_varName), value(_value);
	Tcl_SetVar(tclInterp,varName.gets(),value.gets(),TCL_GLOBAL_ONLY);
	}
}

// TkChannel is a Tcl-based replacement for a MvmPipe which is still
// compatible with it. This is needed for portability purposes when
// doing binary i/o from C++.  This allows using Tcl i/o channel
// abstraction level with no interoperability problems with the
// underlying system socket support. This code has been lifted from
// the MvmPipe implementation. Note: a TkChannel is built from a
// pre-existing Tcl channel configured in binary i/o mode.

TkChannel::TkChannel (const char *tclName)

{
    channel = Tcl_GetChannel(TkContext::getInterp(),
			     (char *)tclName,
			     NULL);
    dmbuf = NULL;
    smbuf = new char[TKCHANNEL_MBUFSZ];
    memset(smbuf,0,TKCHANNEL_MBUFSZ); // to please Purify et al.
}

TkChannel::~TkChannel ()

{
    dispose();
    delete[] smbuf;
}

int TkChannel::send (int mid, const void *mbuf, int nbytes)

{
    u_long h[2];

    h[0] = htonl((u_long)nbytes);
    h[1] = htonl((u_long)mid);

    if (Tcl_Write(channel,(char *)h,sizeof(h)) != sizeof(h) ||
	(nbytes > 0 && Tcl_Write(channel,(char *)mbuf,nbytes) != nbytes))
	return Tkio_linkdown;

    Tcl_Flush(channel);

    return nbytes;
}

int TkChannel::poll (void **mbufp, int *ubytes)

{
    u_long h[2];

    // FIXME: poll the channel -- this is a very unaesthetic method
    // but we had real problems using nbio sockets with Cygwin
    // ... even thru Tcl... :-}
    Tcl_SetChannelOption(NULL,channel,"-blocking","false");
    int n = Tcl_Read(channel,(char *)h,sizeof(h));
    Tcl_SetChannelOption(NULL,channel,"-blocking","true");

    if (!n)
	return Tcl_Eof(channel) ? Tkio_linkdown : Tkio_wouldblock;

    if ((unsigned)n < sizeof(h))
	{
	int l = Tcl_Read(channel,(char *)h + n,sizeof(h) - n);

	if ((unsigned)l != sizeof(h) - n)
	    return Tkio_linkdown;
	}

    int nbytes = (int)ntohl(h[0]); // fetch actual message size
    int mid = (int)ntohl(h[1]); // fetch message id

    if (nbytes > 0)
	{
	if (nbytes <= TKCHANNEL_MBUFSZ)
	    {
	    // current message fits in the static message area:
	    // so use it to hold the incoming message (also dispose
	    // from the last dynamic area allocated (if any) before
	    // proceeding).
	    dispose();
	    *mbufp = smbuf;
	    }
	else
	    {
	    // current message is too large to fit in the static
	    // area: allocate a dynamic buffer to hold it, after
	    // an attempt to recycle a -non-disposed- previously
	    // allocated buffer (if its size is sufficient).
	    
	    if (dmbuf && dmsize < nbytes)
		dispose();

	    if (!dmbuf)
		{
		dmbuf = new char[nbytes];
		memset(dmbuf,0,nbytes); // to please Purify et al.
		}
	    
	    *mbufp = dmbuf;
	    dmsize = nbytes;
	    }

	// Once a message header has been received, the remaining
	// of this message must follow...
	    
	if (Tcl_Read(channel,(char *)*mbufp,nbytes) != nbytes)
	    return Tkio_linkdown;
	}
    else
	*mbufp = NULL;

    *ubytes = nbytes;
    
    return mid;
}

void TkChannel::dispose ()

{
    if (dmbuf)
	{
	delete[] dmbuf;
	dmbuf = NULL;
	}
}
