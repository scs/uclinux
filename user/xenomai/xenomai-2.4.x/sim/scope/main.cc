/*
 * This file is part of the XENOMAI project.
 *
 * Copyright (C) 1997-2000 Realiant Systems.  All rights reserved.
 * Copyright (C) 2001,2002,2003,2004,2005 Philippe Gerum <rpm@xenomai.org>.
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
 * Description: Xenoscope entry point. Performs the initialization chores.
 *
 * Author(s): rpm
 * Contributor(s):
 *
 * Adapted to XENOMAI by Philippe Gerum.
 */

#include <xeno_config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include "vmutils/toolshop.h"
#include "workspace.h"

extern int optind, opterr;

static void appCleanup ()

{
    if (TheWorkspace)
	TheWorkspace->cleanup();
}

static RETSIGTYPE appCleanupOnSig (int sig)

{
    appCleanup();
    _exit(99);
#if RETSIGTYPE != void
    return (RETSIGTYPE)0;
#endif
}

int main (int argc, char **argv)

{
    static char *tclModules[] = {
#ifdef TCLWRAP
#include "scope.tcc"
#else
	TCLSOFTDIR,
#endif // TCLWRAP
	NULL
    };

    CString projectFile,
	errorLogFile;
    int forgetOldSession = 0,
	autoStartDebug = 0,
	autoStartMonitor = 0,
	autoCreateProject = 0,
	selfExitMode = 0;
    int slavePort = -1, c;

#ifdef DEBUG
    TkContext::debugMode = 0;
#endif

    opterr = 0;

    if (argc > 1 && *argv[1] != '-')
	{
	projectFile = argv[1];

	if (projectFile.basename().match(".mvm") < 0)
	    {
	    projectFile += ".mvm";

	    if (::access(projectFile,F_OK) < 0)
		autoCreateProject = 1;
	    }

	optind++;
	}

    while ((c = getopt(argc,argv,"qugxvf:p:l:")) != EOF)
	{
	switch (c)
	    {
	    case 'u' : // Do not restore previous session

		forgetOldSession = 1;
		break;

	    case 'f' : // load this project file

		projectFile = optarg;
		break;

	    case 'p' : // slave port attachment -- implies -q

		slavePort = atoi(optarg);
		selfExitMode = 1;
		break;

	    case 'g' : // auto-start debug load

		autoStartDebug = 1;
		break;

	    case 'x' : // auto-start monitor mode

		autoStartMonitor = 1;
		break;

	    case 'q' : // self-exit on simulation end

		selfExitMode = 1;
		break;

	    case 'v':  // print version string and exit

		printf("Xenoscope for Xenomai's simulation engine version %s\n",MVM_VERSION_STRING);
		printf("Xenomai/MVM comes with absolutely no warranty.\n");
		printf("This is free software, and you are welcome to redistribute it\n");
		printf("under certain conditions; read the COPYING file for details.\n");
#ifdef CXX_VERSION
		printf("(compiled with GNU/CC version %s)\n",CXX_VERSION);
#endif
		exit(0);

	    case 'l':  // error log file used by the simulator (slave mode only)

		errorLogFile = optarg;
		break;

	    case '?' : // unknown option - error

		fatal("usage: xenoscope [-qugxv][-f <project-file>][-p <port>]\n"
		      "                 -f <project-file>\n");
	    }
	}

    // Trap SIGINT, SIGTERM and SIGHUP to exit gracefully
    struct sigaction sa;
    sa.sa_handler = (SIGHANDLER_TYPE)appCleanupOnSig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGTERM,&sa,NULL);
    sigaction(SIGHUP,&sa,NULL);

    atexit(&appCleanup);
    
    if (TkContext::appInitialize(argv[0],tclModules,NULL) != TCL_OK)
	{
	fprintf(stderr,"%s: %s\n",argv[0],TkContext::getInterp()->result);
	fprintf(stderr,"Dumping runtime settings:\n");
	TkContext::dumpInstallPathes(stderr);
	fatal("(cannot initialize TkContext)");
	}

    if ((slavePort != -1 && (autoStartDebug || autoStartMonitor)) ||
	(autoStartDebug && autoStartMonitor))
	fatal("-p, -g and -x options are mutually exclusive");

    if (slavePort != -1)
	{
	if (projectFile.isEmpty())
	    fatal("-p option needs -f too");

	if (autoStartDebug || autoStartMonitor)
	    // Must restore old session with -g, -x or -p
	    forgetOldSession = 0;
	}

    if (errorLogFile.isEmpty())
	// Pick a log file if none has been specified (master mode)
	errorLogFile = tosh_mktemp(NULL,"mvm");

    if (!projectFile.isEmpty() &&
	projectFile.basename().match(".mvm") < 0 &&
	::access(projectFile,F_OK) < 0)
	// Be smart enough to infere the missing extension
	// for the project file
	projectFile += ".mvm";

    TheWorkspace = new Workspace(errorLogFile,
				 selfExitMode,
				 slavePort);
    if (autoCreateProject)
	TheWorkspace->callTkProc("Workspace:saveProject","&S &S",
				 projectFile.gets(),
				 argv[1]);
    if (!forgetOldSession)
	TheWorkspace->callTkProc("Session:restore","&S",
				 projectFile.gets());
    if (slavePort != -1)
	{
	if (TheWorkspace->attachSimulation() < 0)
	    // Ooops, failed to attach to the simulation process
	    exit(1);
	}
    else if (autoStartDebug)
	TheWorkspace->loadDebug();
    else if (autoStartMonitor)
	TheWorkspace->loadSimulation();

    TkContext::appRun();
    
    return 0;
}
