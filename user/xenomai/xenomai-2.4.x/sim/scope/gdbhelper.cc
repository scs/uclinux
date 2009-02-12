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
 * Description: GDB support helper for the Xenoscope debugger.
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
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <tcl.h>
#include "vmutils/hash++.h"
#include "vmutils/string++.h"
#include "bridge.h"
#include "gdbhelper.h"

int gdb_dead = 0,
    gdb_iavail = 0;

char **gdb_ivector = NULL;

Tcl_DString gdb_ilog;

int gdb_ivsize = 0,
    gdb_ivecnt = 0;

char *dead_name = "gdb:dead";

Tcl_Channel gdb_stream;

CString gdb_ibuf;

CStringTok gdb_tmpbuf(NULL);

FILE *gdb_fptrace = NULL;

// In order to export a fully-Tcl'ish interface, C++ and Tcl
// code from the GDB support module are roughly mixed using
// direct Tcl command embedding. In fact, this C++ code file
// provides fast routines to Tcl procs for CPU-intensive work, and
// should be considered as highly dependent from its Tcl
// script counterpart (and vice-versa).

static int parseMember(char **sp, int inAggr, TclList& tclist);

static int readInput (ClientData clientData,
		      Tcl_Interp *tclInterp,
		      int argc,
		      char *argv[])
{
    char buf[1024];
    
    for (;;)
	{
	int nbytes = Tcl_Read(gdb_stream,buf,sizeof(buf));

	if (nbytes <= 0)
	    {
	    if (nbytes < 0 || Tcl_Eof(gdb_stream))
		gdb_dead = 1;
	    }
	else
	    {
	    gdb_ibuf.catenate(buf,nbytes);
	    int l = gdb_ibuf.len();

	    if (gdb_ibuf[l - 1] != '\n' &&
		l > 4 && strcmp(&gdb_ibuf[l - 5],"%gdb%"))
		{
		// incomplete input -- wait and loop...
		Tcl_Sleep(100);
		continue;
		}
	    }

	gdb_iavail = 1;

	if (gdb_fptrace)
	    {
	    fprintf(gdb_fptrace,
		    ">>>\nGDB OUTPUT: (%u bytes, eof %d) ==>\n%.*s\n<<<\n",
		    gdb_ibuf.len(),
		    gdb_dead,
		    (int)gdb_ibuf.len(),
		    (const char *)gdb_ibuf);
	    fflush(gdb_fptrace);
	    }
	
	return TCL_OK;
	}
}

static int flushInput (ClientData clientData,
		       Tcl_Interp *tclInterp,
		       int argc,
		       char *argv[])
{
    if (gdb_ivector)
	{
  	while (gdb_ivecnt > 0)
  	    Tcl_Free(gdb_ivector[--gdb_ivecnt]);
 
 	delete[] gdb_ivector;
	gdb_ivector = NULL;
	gdb_ivsize = 0;
	gdb_ivecnt = 0;
	}

    gdb_ibuf = emptyString;

    return TCL_OK;
}

static void saveInput (char *line)

{
    if (gdb_ivecnt >= gdb_ivsize)
	{
	char **nvector = new char *[gdb_ivsize + 32];

	if (gdb_ivsize > 0)
	    {
	    memcpy(nvector,
		   gdb_ivector,
		   sizeof(char *) * gdb_ivsize);
	    delete[] gdb_ivector;
	    }

	gdb_ivsize += 32;
	gdb_ivector = nvector;
	}

    gdb_ivector[gdb_ivecnt++] = strcpy(Tcl_Alloc(strlen(line) + 1),line);
}

static int translateProto (char **funcProto)

{
    char *eow = strchr(*funcProto,'(');
    int code = GDBPROTO_UNSPEC;

    // Assume that the function name may be passed
    // with or without the argument string.

    if (eow)
	do eow--; while (isspace(*eow));
    else
	{
	if (strstr(*funcProto,"<function called from gdb>"))
	    // private kernel context invoked by GDB
	    return GDBPROTO_KPRIV;
	
	eow = strchr(*funcProto,0) - 1;
	}

    // search for a kernel marker at tail of each
    // function name.
	
    if (*eow == '_')
	{
	char *sow = eow;

	do
	    sow--;
	while (sow > *funcProto && !isspace(*sow) && *sow != '_');

	if (*sow == '_')
	    {
	    CString word(sow + 1,eow - sow - 1);

	    if (word == "kisrt")
		{
		*funcProto = "<interrupt handler>";
		code = GDBPROTO_KISRT;
		}
	    else if (word == "kdsrt")
		{
		*funcProto = "<deferred service>";
		code = GDBPROTO_KDSRT;
		}
	    else if (word == "kcout")
		{
		*funcProto = "<callout>";
		code = GDBPROTO_KCOUT;
		}
	    else if (word == "kidle")
		{
		*funcProto = "<idle>";
		code = GDBPROTO_KIDLE;
		}
	    else if (word == "kroot")
		code = GDBPROTO_KROOT;
	    else if (word == "kdoor")
		code = GDBPROTO_KDOOR;
	    else if (word == "khook")
		code = GDBPROTO_KHOOK;
	    else if (word == "khide")
		code = GDBPROTO_KHIDE;
	    else if (word == "kinit")
		{
		*funcProto = "<init>";
		code = GDBPROTO_KINIT;
		}
	    else if (word == "kprea")
		{
		*funcProto = "<preamble>";
		code = GDBPROTO_KPREA;
		}
	    }
	}

    return code;
}

static void buildStackInfo (const char *line, int nvec, int lnum)

{
    Tcl_DString tclString;
    Tcl_DStringInit(&tclString);
    Tcl_DStringAppendElement(&tclString,CString(lnum));
    Tcl_DStringAppendElement(&tclString,line);
    Tcl_Free(gdb_ivector[nvec]);
    gdb_ivector[nvec] = Tcl_Alloc(Tcl_DStringLength(&tclString) + 1);
    strcpy(gdb_ivector[nvec],Tcl_DStringValue(&tclString));
    Tcl_DStringFree(&tclString);
}

static int stackInput (int lcount)

{
    int r = 0, w = 0, wcount = lcount;

    if (gdb_fptrace)
	{
	fprintf(gdb_fptrace,"==> STACK LOG\n");

	for (int x = 0; x < lcount; x++)
	    fprintf(gdb_fptrace,"==> %s\n",gdb_ivector[x]);

	fflush(gdb_fptrace);
	}
    
    // Pack the possibly broken input lines, pretending
    // that each one must start with a '#<nn>' level marker;
    // those who don't are tacked to the previous one in
    // the array. FIXME (rpm): this is now unuseful as we tell
    // GDB that the screen width is infinite (set width 0); so it
    // won't truncate the output lines in any way.

    while (r < wcount)
	{
	char *line = gdb_ivector[r];
	
	if (*line != '#' && w > 0)
	    {
	    w--;
	    line = Tcl_Alloc(strlen(gdb_ivector[w]) +
			     strlen(line) + 2);
	    strcat(strcpy(line,gdb_ivector[w]),gdb_ivector[r]);
	    Tcl_Free(gdb_ivector[w]);
	    Tcl_Free(gdb_ivector[r]);
	    }

	gdb_ivector[w] = line;
	w++, r++;
	}

    wcount = w;
    
    // build a new list for each line moving the stack level
    // number from the original frame information to a standalone
    // list element heading the resulting list.

    for (r = 0; r < wcount; r++)
	{
	char *btrace = gdb_ivector[r] + 1;
	while (isdigit(*btrace)) btrace++; // skip level number
	while (isspace(*btrace)) btrace++; // skip white-spaces
	buildStackInfo(btrace,r,r);
	}

    // Reverse the array order to process the internal markers...
    
    for (int n = 1, perm = wcount / 2; n <= perm; n++)
	{
	char *swap = gdb_ivector[wcount - n];
	gdb_ivector[wcount - n] = gdb_ivector[n - 1];
	gdb_ivector[n - 1] = swap;
	}

    int skip = 1, initSeen = 0;
    
    for (r = 0, w = 0; r < wcount; r++)
	{
	char *funcProto = gdb_ivector[r];

	switch (translateProto(&funcProto))
	    {
	    case GDBPROTO_KROOT:

		Tcl_Free(gdb_ivector[r]);
		skip = 0;
		continue;
		    
	    case GDBPROTO_KHIDE:

	    hide:
	    Tcl_Free(gdb_ivector[r]);
	    continue;

	    case GDBPROTO_KINIT:

		if (initSeen)
		    // <init> frames may be redundant -- keep only the
		    // first one and discard the others as we read them.
		    goto hide;

		initSeen = 1;

		// Falldown wanted

	    case GDBPROTO_KISRT:
	    case GDBPROTO_KDSRT:
	    case GDBPROTO_KCOUT:

		buildStackInfo(funcProto,r,wcount - r - 1);
		skip = 0;
		break;

	    case GDBPROTO_KIDLE:

		buildStackInfo(funcProto,r,wcount - r - 1);
		gdb_ivector[w++] = gdb_ivector[r];
		skip = 1;
		continue;

	    case GDBPROTO_KDOOR:
	    case GDBPROTO_KPRIV:

		skip = 1;
		break;
		    
	    case GDBPROTO_KHOOK:

		if (!skip && r > 0) // should always be > 0
		    {
		    Tcl_Free(gdb_ivector[r - 1]);
		    w--;
		    }
		    
		skip = 1;
		break;
	    }

	if (skip)
	    Tcl_Free(gdb_ivector[r]);
	else
	    gdb_ivector[w++] = gdb_ivector[r];
	}

    wcount = w;

    // Reverse the array back in top/down order...
    
    for (int n = 1, perm = wcount / 2; n <= perm; n++)
	{
	char *swap = gdb_ivector[wcount - n];
	gdb_ivector[wcount - n] = gdb_ivector[n - 1];
	gdb_ivector[n - 1] = swap;
	}

    // Trim upward the rest of the input log which is *not* part of
    // the stack information to fill the hole made by the packing
    // process.
    
    for (int n = lcount; n < gdb_ivecnt; n++)
	gdb_ivector[w++] = gdb_ivector[n++];
    
    gdb_ivecnt = w;

    return wcount;
}

static int splitInput (Tcl_Interp *tclInterp,
		       int rc,
		       char **rv,
		       int withLog,
		       int stackMode,
		       int rc2,
		       char **rv2)
{
    // Scatter input in line elements, making GDB's prompt pattern
    // appear as a single element.
    
    char *ibuf = gdb_ibuf.gets(), *estart = gdb_ibuf.gets();

    Tcl_ResetResult(tclInterp);

    for (;;)
	{
	if (*ibuf == '\0' || *ibuf == '\n')
	    {
	    int c = *ibuf;
	    *ibuf = '\0';

	    if (*estart)
		saveInput(estart);

	    if (!c)
		break;
	    
	    estart = ++ibuf;
	    }
	else if (*ibuf == '%' && strncmp(ibuf + 1,"gdb%",4) == 0)
	    {
	    *ibuf = '\0';

	    if (*estart)
		saveInput(estart);

	    saveInput("%gdb%");
	    ibuf += 5;
	    estart = ibuf;
	    }
	else
	    ibuf++;
	}

    for (int nre = 0; nre < rc; nre++)
	{
	Tcl_RegExp re = Tcl_RegExpCompile(tclInterp,rv[nre]);
	
	for (int l = 0; l < gdb_ivecnt; l++)
	    {
	    if (Tcl_RegExpExec(tclInterp,re,gdb_ivector[l],gdb_ivector[l]))
		{
		char *matched = gdb_ivector[l];

		// Confirm the first match by the secondary one (if given)
		for (int nre2 = 0; nre2 < rc2; nre2++)
		    {
		    Tcl_RegExp re2 = Tcl_RegExpCompile(tclInterp,rv2[nre2]);

		    for (int m = 0; m < l; m++)
			{
			if (Tcl_RegExpExec(tclInterp,re2,gdb_ivector[m],gdb_ivector[m]))
			    {
			    // substitute secondary match
			    matched = gdb_ivector[m];
			    // retain 1st log match
			    rc2 = 0;
			    nre = nre2;
			    break;
			    }
			}
		    }

		Tcl_DString gdb_ilog;
		Tcl_DStringInit(&gdb_ilog);
		
		if (withLog) // log wanted
		    {
		    if (stackMode)
			l = stackInput(l);
		    
		    for (int m = 0; m < l; m++)
			Tcl_DStringAppendElement(&gdb_ilog,gdb_ivector[m]);
		    }

		// The following frag returns the matching index; there is
		// some weird code here: if no secondary match (provided that
		// there was one requested -- i.e. rc2 non-null at init)
		// could confirm the first match (nre), an invalid index
		// is returned equal to the non-null initial rc2, which means
		// "beyond the last possible match". This means that a primary
		// match has been found (e.g. a prompt for sendCommand()), but
		// the contents of the log did not match anything known to
		// the caller. We cannot return -1, which value is reserved
		// to indicate that the connection with GDB has been lost.

		Tcl_AppendElement(tclInterp,CString(rc2 ? rc2 : nre).gets());
		Tcl_AppendElement(tclInterp,matched);
		Tcl_AppendElement(tclInterp,Tcl_DStringValue(&gdb_ilog));
		Tcl_DStringFree(&gdb_ilog);
				  
		for (int m = 0; m <= l; m++)
		    Tcl_Free(gdb_ivector[m]);

		int mdest = 0;
		
		for (int msrc = l + 1; msrc < gdb_ivecnt; msrc++)
		    gdb_ivector[mdest++] = gdb_ivector[msrc];

		gdb_ivecnt = mdest;
		
		return nre;
		}
	    }
	}

    return -1;
}

static int expectInput (ClientData clientData,
			Tcl_Interp *tclInterp,
			int argc,
			char *argv[])
{
    int rc; char **rv;
    Tcl_SplitList(tclInterp,argv[1],&rc,&rv);
    int withLog = argc > 2 && strchr(argv[2],'l') != NULL;
    int stackMode = argc > 2 && strchr(argv[2],'s') != NULL;
    
    while (!gdb_dead)
	{
	int nre = splitInput(tclInterp,rc,rv,withLog,stackMode,0,NULL);
	gdb_ibuf = emptyString;

	if (nre != -1)
	    {
	    Tcl_Free((char *)rv);
	    return TCL_OK;
	    }

	// need more input: wait for readInput() to be
	// called upon gdb_stream file event...

	gdb_iavail = 0;
	
	do
	    Tcl_DoOneEvent(TCL_ALL_EVENTS);
	while (!gdb_iavail && !gdb_dead);
	}

    Tcl_Free((char *)rv);
    Tcl_SetResult(tclInterp,"-1",TCL_STATIC);

    return TCL_OK;
}

static int sendString (ClientData clientData,
		       Tcl_Interp *tclInterp,
		       int argc,
		       char *argv[])
{
    if (gdb_fptrace)
	{
	fprintf(gdb_fptrace,"SENDING: server %s\n",argv[1]);
	fflush(gdb_fptrace);
	}

    // discard pending input each time we send a string to
    // GDB, pretending that we start a new chat context.
    flushInput(clientData,tclInterp,argc,argv);

    if (Tcl_Write(gdb_stream,"server ",-1) != -1 &&
	Tcl_Write(gdb_stream,argv[1],-1) != -1 &&
	Tcl_Write(gdb_stream,"\n",1) != -1)
	Tcl_Flush(gdb_stream);
    
    return TCL_OK;
}

static int sendCommand (ClientData clientData,
			Tcl_Interp *tclInterp,
			int argc,
			char *argv[])
{
    if (gdb_fptrace)
	{
	fprintf(gdb_fptrace,"COMMAND: server %s\n",argv[1]);
	fflush(gdb_fptrace);
	}

    // command: <cmd> <wantlog> <explist>
    flushInput(clientData,tclInterp,argc,argv);

    if (Tcl_Write(gdb_stream,"server ",-1) < 0 ||
	Tcl_Write(gdb_stream,argv[1],-1) < 0 ||
	Tcl_Write(gdb_stream,"\n",1) < 0)
	{
	Tcl_SetResult(tclInterp,"-1",TCL_STATIC);
	return TCL_OK;
	}

    Tcl_Flush(gdb_stream);

    int rc = 1; char *rv[1] = { "^%gdb%" };
    int rc2 = 0; char **rv2 = NULL;
    // NOTE: never define '-' as an option letter - it should be reserved to specify 'no option'
    int withLog = argc > 2 && strchr(argv[2],'l') != NULL;
    int stackMode = argc > 2 && strchr(argv[2],'s') != NULL;

    if (argc > 3)
	Tcl_SplitList(tclInterp,argv[3],&rc2,&rv2);

    while (!gdb_dead)
	{
	int nre = splitInput(tclInterp,rc,rv,withLog,stackMode,rc2,rv2);
	gdb_ibuf = emptyString;

	if (nre != -1)
	    {
	    if (gdb_fptrace)
		{
		fprintf(gdb_fptrace,
			"RESULT(stackmode=%d): %s\n",stackMode,
			Tcl_GetStringResult(tclInterp));
		fflush(gdb_fptrace);
		}

	    Tcl_Free((char *)rv2);
	    return TCL_OK;
	    }

	gdb_iavail = 0;
	
	do
	    // note: do not process window events to prevent
	    // recursive call of gdb:command triggered by a
	    // user action.
	    Tcl_DoOneEvent(TCL_FILE_EVENTS|TCL_TIMER_EVENTS|TCL_IDLE_EVENTS);
	while (!gdb_iavail && !gdb_dead);
	}

    Tcl_Free((char *)rv2);
    Tcl_SetResult(tclInterp,"-1",TCL_STATIC);

    return TCL_OK;
}

static int getPrototype (ClientData clientData,
			 Tcl_Interp *tclInterp,
			 int argc,
			 char *argv[])
{
    // Translate the internal identifiers (e.g. kdoor(), kisrt()
    // and so on) into user-readable context names.
    char *proto = argv[1];
    Tcl_AppendElement(tclInterp,CString(translateProto(&proto)).gets());
    Tcl_AppendElement(tclInterp,proto);
    return TCL_OK;
}

static int lookupSym (ClientData clientData,
		      Tcl_Interp *tclInterp,
		      int argc,
		      char *argv[])
{
    const char *symbol = argv[1];
    const char *rp = symbol;

    Tcl_ResetResult(tclInterp);

    if (!isalpha(*rp) && *rp != '$' && *rp != '_')
	// Cannot be a valid C/C++ identifier
	return TCL_OK;
    
    while (*++rp 
	   && (isalnum(*rp) 
	       || *rp == '$' 
	       || *rp == '_' 
	       || ((*rp == '-') && (*(rp+1) == '>')) 
	       || ((*rp == '>') && (*(rp-1) == '-'))
	       || ((*rp == ':') && (*(rp+1) == ':'))
	       || ((*rp == ':') && (*(rp-1) == ':'))
	       ))
	;

    if (!*rp)
	Tcl_SetResult(tclInterp,(char *)symbol,TCL_STATIC);

    return TCL_OK;
}

static int initIO (ClientData clientData,
		   Tcl_Interp *tclInterp,
		   int argc,
		   char *argv[])
{
    gdb_stream = Tcl_GetChannel(tclInterp,argv[1],NULL);
    gdb_dead = 0;
    flushInput(clientData,tclInterp,argc,argv);

    if (gdb_fptrace)
	{
	if (gdb_fptrace != stderr)
	    fclose(gdb_fptrace);

	gdb_fptrace = NULL;
	}

    const char *traceFile = getenv("MVM_GDBTRACE");

    if (traceFile && *traceFile)
	{
	if (!strcmp(traceFile,"-"))
	    gdb_fptrace = stderr;
	else
	    gdb_fptrace = fopen(traceFile,"w");
	}

    return TCL_OK;
}

static int doneIO (ClientData clientData,
		   Tcl_Interp *tclInterp,
		   int argc,
		   char *argv[])
{
    flushInput(clientData,tclInterp,argc,argv);
    return TCL_OK;
}

// parseXXX routines transform the output of GDB's "output"
// command (i.e. print/inspect with neither history nor
// eol) into a Tcl list which can be parsed in turn by the data
// watcher tool. These routines preserve the hierarchy of
// data members within structs/unions.

static int parseAggr (char **sp, TclList& tclist)

{
    int inAggr = 0, members = 0;
    
    if (**sp == '{')
	(*sp)++, inAggr = 1;

    do
	members += (parseMember(sp,inAggr,tclist) + 1);
    while (**sp == ',' && *(++*sp));
    
    while (isspace(**sp))
	(*sp)++;

    if (inAggr && **sp == '}')
	(*sp)++;

    return members;
}

static int parseMember (char **sp, int inAggr, TclList& tclist)

{
    int subMembers = 0;
    
    while (isspace(**sp))
	(*sp)++;

    CString identifier, value;
    TclList _tclist;

    if (inAggr && !isdigit(**sp))
	{
	for (;;)
	    {
	    while (**sp && (isalnum(**sp) || strchr("_<>",**sp)))
		{ identifier.appendChar(**sp); (*sp)++; }

	    while (**sp && (isspace(**sp) || **sp == '='))
		(*sp)++;
	
	    if (identifier != "static")
		break;

	    identifier.appendChar(' ');
	    }

	_tclist.append(identifier);
	}

    if (**sp == '{')
	{
	_tclist.append("@node");
	
	TclList __tclist;
	subMembers = parseAggr(sp,__tclist);
	_tclist.append(__tclist);
	
	while (**sp && **sp != ',' && **sp != '}')
	    (*sp)++;
	}
    else
	{
	while (**sp != ',' && **sp != '}' && **sp)
	    {
	    if (**sp == '"' || **sp == '\'')
		{
		int closeMark = **sp;
		    
		do
		    { value.appendChar(**sp); (*sp)++; }
		while ((**sp != closeMark || (*sp)[-1] == '\\') && **sp);
		}

	    if (**sp) // malformed if not
		{
		value.appendChar(**sp);
		(*sp)++;
		}
	    }

	_tclist.append(value);
	}

    tclist.append(_tclist);

    return subMembers;
}

static int parseData (ClientData clientData,
		      Tcl_Interp *tclInterp,
		      int argc,
		      char *argv[])
{
    TclList tclist;
    CString cs(argv[1]);

    // Unquote strings only when Tcl has decided to be very
    // conservative (i.e. a string starting with "\{" intro
    // means that every bothering character has been quoted
    // too in our context)... We must not unquote otherwise,
    // because doing so would introduce evaluation problems
    // in our poor parser (i.e. string = "hello \" world"
    // can be passed as is, or as \"hello\ \\\"\ world\").
    
    if (cs[0] == '\\' && cs[1] == '{')
	cs.metaExpandC();

    char *s = cs.gets();

    // Kludge:: GDB usually ends an error message with a period;
    // thus don't even try to decode a string ending with a
    // pattern which cannot not be confused with a valid
    // data member value.
    
    if (cs.len() > 2 && strcmp(&cs[cs.len() - 2],".}") == 0)
	Tcl_AppendResult(tclInterp,argv[1],NULL);
    else
	{
	if (parseAggr(&s,tclist) < 2)
	    Tcl_AppendResult(tclInterp,TclListParser(tclist).next(),NULL);
	else
	    Tcl_AppendResult(tclInterp,"@node { ",tclist.get()," }",NULL);
	}

    return TCL_OK;
}

void helperAttach (Tcl_Interp *tclInterp)

{
    Tcl_CreateCommand(tclInterp,
		      "gdb:initio",
		      &initIO,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:doneio",
		      &doneIO,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:parsedata",
		      &parseData,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:iflush",
		      &flushInput,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:iread",
		      &readInput,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:expect",
		      &expectInput,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:send",
		      &sendString,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:command",
		      &sendCommand,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:getproto",
		      &getPrototype,
		      NULL,
		      NULL);

    Tcl_CreateCommand(tclInterp,
		      "gdb:lookup",
		      &lookupSym,
		      NULL,
		      NULL);

    Tcl_LinkVar(tclInterp,dead_name,
		(char *)&gdb_dead,
		TCL_LINK_BOOLEAN);
}

void helperDetach (Tcl_Interp *tclInterp)

{
    Tcl_DeleteCommand(tclInterp,"gdb:initio");
    Tcl_DeleteCommand(tclInterp,"gdb:parsedata");
    Tcl_DeleteCommand(tclInterp,"gdb:iflush");
    Tcl_DeleteCommand(tclInterp,"gdb:iread");
    Tcl_DeleteCommand(tclInterp,"gdb:expect");
    Tcl_DeleteCommand(tclInterp,"gdb:send");
    Tcl_DeleteCommand(tclInterp,"gdb:command");
    Tcl_DeleteCommand(tclInterp,"gdb:getproto");
    Tcl_DeleteCommand(tclInterp,"gdb:lookup");
    Tcl_UnlinkVar(tclInterp,dead_name);

    if (gdb_fptrace)
	{
	if (gdb_fptrace != stderr)
	    fclose(gdb_fptrace);

	gdb_fptrace = NULL;
	}
}
