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
 * Description: C/C++ instrumentation driver.
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
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include "vmutils/version.h"
#include "vmutils/toolshop.h"
#include "vmutils/string++.h"
#include "vmutils/list++.h"

#define SRC_PLACEHOLDER "<**$@$**>"

CString TmpDir,
    CCCmdString,
    CPPCmdString,
    CUserSrcExt,
    CplusUserSrcExt,
    ObjectExt(".o"),
    AsmExt(".s"),
    OutputFile,
    GccBackend,
    Prefix,
    ExecPrefix,
    BackendPrefix,
    GccPrefix,
    ControlFile,
    DepsFile;

CStringList TempFiles,
    BaseFiles;

#if __GNUC__ == 2 || __GNUC_MINOR__ == 95
#define compatible_base_compiler 1
#else
#define compatible_base_compiler 0
#endif

int FlagDryRun = 0,
    FlagToStdout = 0,
    FlagVerbose = 0,
    FlagVersion = 0,
    FlagSaveTemps = 0,
    FlagPreprocess = 0,
    FlagAssemble = 0,
    FlagObjectOnly = 0,
    FlagCExtSet = 0,
    FlagCplusExtSet = 0,
    FlagOutputFile = 0,
    FlagLinking = 0,
    FlagGcicCompiler = !compatible_base_compiler,
    FlagGccVersion = 0,
    FlagHelp = 0,
    FlagNoMvmLib = 0,
    FlagCplusPlus = 0,
    FlagCPPCmdSet = 0,
    FlagCCmdSet = 0,
    FlagKTag = 0,
    FlagITag = 0,
    FlagATag = 0,
    FlagNoInst = 0;

// The list of our local options and flags.

static struct tool_options {

    const char *name;
    int *flag;
    int flagval;
    CString *string;

} ToolOptions[] = {

    { "-dry-run", &FlagDryRun, 1, NULL },
    { "-verbose", &FlagVerbose, 1, NULL },
    { "-save-temps", &FlagSaveTemps, 1, NULL },
    { "-with-gcic-compiler", &FlagGcicCompiler, 1, NULL },
    { "-no-gcic-compiler", &FlagGcicCompiler, 0, NULL },
    { "-stdout", &FlagToStdout, 1, NULL },
    { "-version", &FlagVersion, 1, NULL },
    { "-gcc-version", &FlagGccVersion, 1, NULL },
    { "-temp-dir", NULL, 0, &TmpDir },
    { "-c-ext", &FlagCExtSet, 1, &CUserSrcExt },
    { "-c++-ext", &FlagCplusExtSet, 1, &CplusUserSrcExt },
    { "-obj-ext", NULL, 0, &ObjectExt },
    { "-asm-ext", NULL, 0, &AsmExt },
    { "-cpp", &FlagCPPCmdSet, 1, &CPPCmdString },
    { "-cc", &FlagCCmdSet, 1, &CCCmdString },
    { "-cplusplus", &FlagCplusPlus, 1, NULL },
    { "-control-file", NULL, 0, &ControlFile },
    { "-help", &FlagHelp, 1, NULL },
    { "-kernel-code", &FlagKTag, 1, NULL },
    { "-skin-code", &FlagITag, 1, NULL },
    { "-user-code", &FlagATag, 1, NULL },
    { "-gcic-backend", NULL, 0, &BackendPrefix },
    { "-no-mvm-libs", &FlagNoMvmLib, 1, NULL },
    { "-no-inst", &FlagNoInst, 1, NULL },
    { NULL, NULL, 0, NULL }
};

// The list of options one should never be able to pass to our
// instrumentation backend when it is asked to patch a source file for
// us.

static struct stripped_options {

    const char *prefix;
    int withArg;
    int *flag;
    CString *value;
    int allStages;

} StrippedOptions[] = {

    { "-Wa", 0, NULL, NULL, 0 },
    { "-Wl", 0, NULL, NULL, 0 },
    { "-Xlinker", 1, NULL, NULL, 0 },
    { "-Wid-clash", 0, NULL, NULL, 0 },
    { "-save-temps", 0, NULL, NULL, 0 },
    { "-specs=", 0, NULL, NULL, 0 },
    { "-l", 1, NULL, NULL, 0 },
    { "-B", 1, NULL, NULL, 0 },
    { "-b", 1, NULL, NULL, 0 },
    { "-V", 1, NULL, NULL, 0 },
    { "-E", 0, &FlagPreprocess, NULL, 0 },
    { "-S", 0, &FlagAssemble, NULL, 0 },
    { "-c", 0, &FlagObjectOnly, NULL, 0 },
    { "-o" , 1, &FlagOutputFile, &OutputFile, 0 },
    { "-MT", 1, NULL, NULL, 1 },
    { "-MD", 0, NULL, NULL, 1 },
    { "-MP", 0, NULL, NULL, 1 },
    { "-MF", 1, NULL, &DepsFile, 1 },
    { NULL, 0, NULL, NULL, 0 }
};

struct file_extensions {

    const char *in;
    const char *out;
};

static file_extensions C_Extensions[] = {

    { NULL, NULL },	// user slot
    { ".c", ".i" },
    { ".i", ".i" },
    { NULL, NULL }
};

static file_extensions Cplus_Extensions[] = {

    { NULL, NULL },	// user slot
    { ".cc", ".ii" },
    { ".C", ".ii" },
    { ".cpp", ".ii" },
    { ".cxx", ".ii" },
    { ".c++", ".ii" },
    { ".ii", ".ii" },
    { NULL, NULL }
};

static void usage ()

{
    fprintf(stderr,"usage: gcic [--kernel-code]\n");
    fprintf(stderr,"            [--skin-code]\n");
    fprintf(stderr,"            [--user-code]\n");
    fprintf(stderr,"            [--gcic-backend=<gcc-backend-dir>]\n");
    fprintf(stderr,"            [--temp-dir=<temporary-dir>]\n");
    fprintf(stderr,"            [--c-ext=<c-file-ext{in:out}>]\n");
    fprintf(stderr,"            [--c++-ext=<c++-file-ext{in:out}>]\n");
    fprintf(stderr,"            [--obj-ext=<object-file-ext>]\n");
    fprintf(stderr,"            [--asm-ext=<asm-file-ext>]\n");
    fprintf(stderr,"            [--cplusplus]\n");
    fprintf(stderr,"            [--no-mvm-libs]\n");
    fprintf(stderr,"            [--no-inst]\n");
    fprintf(stderr,"            [--dry-run]\n");
    fprintf(stderr,"            [--stdout]\n");
    fprintf(stderr,"            [--verbose]\n");
    fprintf(stderr,"            [--version]\n");
    fprintf(stderr,"            [--gcc-version]\n");
    fprintf(stderr,"            [--[with/no]-gcic-compiler]\n");
    fprintf(stderr,"            [--save-temps]\n");
    fprintf(stderr,"            [--cpp=<preprocessing-command>]\n");
    fprintf(stderr,"            [--cc=<compilation-command>]\n");
    fprintf(stderr,"            <files-and-args>\n");
}

static void cleanup ()

{
    if (FlagSaveTemps)
	{
	for (LString *ls = TempFiles.first();
	     ls; ls = (LString *)ls->next())
	    printf("(intermediate file %s has been kept...)\n",
		   ls->gets());
	}
    else
	{
	for (LString *ls = TempFiles.first();
	     ls; ls = (LString *)ls->next())
	    unlink(*ls);
	}
}

static RETSIGTYPE cleanupOnSig (int sig)

{
    cleanup();
    _exit(99);

#if RETSIGTYPE != void
    return (RETSIGTYPE)0;
#endif
}

static file_extensions *findFileExt (const char *fileName,
				     file_extensions *ext)
{
    CString name(CString(fileName).basename()), re;

    if (!ext->in)
	// skip user slot if undefined
	ext++;

    while (ext->in)
	{
	re.overwrite("*");
	re += ext->in;

	if (!name.fnmatch(re))
	    return ext;

	ext++;
	}

    return NULL;
}

static void getGccVersion ()

{
    // Force the use of the GCIC installation.
    CString cmdLine = BackendPrefix + "bin/gcc -v ";
    cmdLine += "-B";
    cmdLine += GccPrefix;

    char *av[4];
    av[0] = "sh";
    av[1] = "-c";
    av[2] = cmdLine.gets();
    av[3] = NULL;

    tosh_spawnw(av[0],av);
}

static void addIncludePrefixes (CString& cmdLine,
				int cplus)
{
    if (cplus) // C++ source file?
	{
	// -idirafter <libexec>/gcic/include/c++
	// DO *NOT* SET -isystem for this one!
	cmdLine += " -idirafter ";
	cmdLine += BackendPrefix;
	cmdLine += "include/g++";
	}

    // -isystem <libexec>/gcic/<machine>/include
    cmdLine += " -isystem ";
    cmdLine += BackendPrefix;
    cmdLine += CONFIG_XENO_MVM_BUILD_STRING;
    cmdLine += "/include";

    // -isystem <libexec>/gcic/lib/gcc-lib/<machine>/<version>/include
    cmdLine += " -isystem ";
    cmdLine += GccPrefix;
    cmdLine += CONFIG_XENO_MVM_BUILD_STRING;
    cmdLine.appendChar('/');
    cmdLine += MVM_GCC_VERSION;
    cmdLine += "/include";
}

static int cppSource (CStringList& argStage0,
		      CString& fileName,
		      const file_extensions *ext)
{
    if (!strcmp(ext->in,ext->out))
	return 0;

    CString cmdLine;

    // If no cpp-specific command-line has been given,
    // use current CC settings, forcing -E.

    if (FlagCPPCmdSet)
	cmdLine = CPPCmdString;
    else
	{
	cmdLine = CCCmdString;
	cmdLine += " -E ";
	}

    // Caveat emptor: instrumenting multiple files with the same base
    // filename from different directories in a single execution of
    // "gcic" is not allowed because this would raise name conflicts
    // for files which cannot be solved easily. But this should not
    // really be a major problem for the user anyway.

    CString srcBase(CString(fileName).basename());
    CString tmpName(srcBase);
    tmpName.rstrip(ext->in);
    CString cppFile = TmpDir + "/ic0@" + tmpName + ext->out;

    // To be unlinked later by atexit() hook
    TempFiles.append(new LString(cppFile));

    for (LString *ls = argStage0.first();
	 ls; ls = (LString *)ls->next())
	{
	cmdLine += *ls;
	cmdLine.appendChar(' ');
	}

    cmdLine += fileName;
    cmdLine += " > ";
    cmdLine += cppFile;

    char *av[4];
    av[0] = "sh";
    av[1] = "-c";
    av[2] = cmdLine.gets();
    av[3] = NULL;

    if (FlagVerbose)
	printf("%s\n",cmdLine.gets());

    if (tosh_spawnw(av[0],av))
	return -1;

    fileName = cppFile;

    return 0;
}

static int patchSource (CStringList& argStage0,
			CStringList& argStagei,
			const char *fileName)
{
    file_extensions *ext = findFileExt(fileName,C_Extensions);
    CString langOpt;

    if (!ext)
	{
	ext = findFileExt(fileName,Cplus_Extensions); // may not fail
	langOpt = " -xc++-cpp-output ";
	}
    else
	langOpt = " -xcpp-output ";

    CString cppFileName(fileName);

    if (cppSource(argStage0,cppFileName,ext) < 0)
	{
	fprintf(stderr,"gcic: failed to preprocess %s.\n",fileName);
	return -1;
	}

    // At this point, cppFileName should have been overwritten with
    // the path of the preprocessed version of the original source
    // file.

    CString srcBase(CString(fileName).basename());
    CString tmpName(srcBase);
    tmpName.rstrip(ext->in);
    CString patchedFile = TmpDir + "/ic1@" + tmpName + ext->out;

    if (FlagNoInst)
	{
	if (FlagToStdout)
	    {
	    symlink(cppFileName,patchedFile);
	    system(CString().format("cat " + patchedFile));
	    }
	else
	    {
	    symlink(cppFileName,patchedFile);
	    TempFiles.append(new LString(patchedFile));
	    }
	}
    else
	{
	CString cmdLine = BackendPrefix + "bin/gcc ";
	// Force the use of the GCIC installation.
	cmdLine += "-B";
	cmdLine += GccPrefix;
	cmdLine += " --syntax-only -nostdlib --gcic-mode ";

	// Set context tag. Defaults to tag3 when unspecified to the
	// instrumentation engine.

	if (FlagKTag)
	    cmdLine += "--gcic-trace-tag1 ";

	if (FlagITag)
	    cmdLine += "--gcic-trace-tag2 ";

	if (FlagATag)
	    cmdLine += "--gcic-trace-tag3 ";

	cmdLine += langOpt;
	cmdLine += cppFileName;

	if (!FlagToStdout)
	    {
	    cmdLine += " > ";
	    cmdLine += patchedFile;
	    // To be unlinked later by atexit() hook
	    TempFiles.append(new LString(patchedFile));
	    BaseFiles.append(new LString(tmpName));
	    }

	// Always set the temp file info. even if where are actually
	// redirecting to stdout -- this way, we can have the exact
	// instrumenter's output for debugging purposes.
	CString envArg = "GCIC_TEMP_FILE=" + patchedFile;
	putenv(strdup(envArg));

	// Set the control file once for GCIC.
	if (!ControlFile.isEmpty() && !getenv("GCIC_CONTROL_FILE"))
	    {
	    envArg = "GCIC_CONTROL_FILE=" + ControlFile;
	    putenv(strdup(envArg));
	    }
	
	char *av[4];
	av[0] = "sh";
	av[1] = "-c";
	av[2] = cmdLine.gets();
	av[3] = NULL;

	if (FlagVerbose)
	    printf("%s\n",cmdLine.gets());
	
	if (tosh_spawnw(av[0],av))
	    return -1; // oops --- something went wrong...
	}

    if (!FlagToStdout)
	{
	// replace the next occurrence of a source placeholder within
	// the final arg vector with the instrumented source file
	// name.

	for (LString *ls = argStagei.first();
	     ls; ls = (LString *)ls->next())
	    {
	    if (*ls == SRC_PLACEHOLDER)
		{
		ls->overwrite(patchedFile);
		break;
		}
	    }
	}

    return 0;
}

static void splitOptArg (const char *s,
			 CString& opt,
			 CString& arg)
{
    if (s[0] == '-' && s[1] == '-')
	// Reduce double dash prefix to single option prefix.
	s++;

    if (s[0] == '-')
	{
	CStringTok a(s);
	opt = a.getNextTok('=');
	arg = a.getNextTok('\0');
	}
    else
	arg = s;
}

static LString *getQuotedArg (const char *arg)

{
    LString *ls = new LString(NULL);

    do
	{
	if (strchr("\"\\'`",*arg))
	    ls->appendChar('\\');

	ls->appendChar(*arg);
	}
    while (*++arg);

    return ls;
}

static int findLocalOpt (const char *s)

{
    CString opt, arg;

    splitOptArg(s,opt,arg);

    if (opt.isEmpty())
	return 0;

    for (int n = 0; ToolOptions[n].name != NULL; n++)
	{
	if (opt == ToolOptions[n].name)
	    {
	    if (ToolOptions[n].flag)
		{
		if (!ToolOptions[n].string && !arg.isEmpty())
		    {
		    fprintf(stderr,
			    "gcic: option `%s' has no argument.\n",
			    (const char *)opt);
		    return 1;
		    }

		*ToolOptions[n].flag = ToolOptions[n].flagval;
		}

	    if (ToolOptions[n].string)
		{
		if (arg.isEmpty())
		    {
		    fprintf(stderr,
			    "gcic: option `%s' needs an argument.\n",
			    (const char *)opt);
		    return 1;
		    }

		*ToolOptions[n].string = arg;
		}

	    return 1;
	    }
	}

    return 0;
}

static int filterOpt (char **argv,
		      int argc,
		      int argn,
		      struct stripped_options& optinfo)
{
    const char *opt = argv[argn];

    for (int n = 0; StrippedOptions[n].prefix != NULL; n++)
	{
	if (!strncmp(opt,
		     StrippedOptions[n].prefix,
		     strlen(StrippedOptions[n].prefix)))
	    {
	    optinfo = StrippedOptions[n];

	    if (optinfo.flag)
		*optinfo.flag = 1;

	    if (optinfo.value)
		{
		if (strlen(opt) > strlen(StrippedOptions[n].prefix))
		    *optinfo.value = opt + strlen(opt);
		else if (argn < argc)
		    // argn should also bounce one step ahead in the
		    // caller's context to prevent filenames starting
		    // with a dash to be confused with a command line
		    // option.  Anyway, using dash in front of
		    // filenames would fool many other tools too! So,
		    // let's be dumb...
		    *optinfo.value = argv[argn + 1];
		}

	    return 1;
	    }
	}

    return 0;
}

int main (int argc, char **argv)

{
    int rc, cFileCount = 0, cplusplusFileCount = 0;

    if (argc < 2)
	{
	usage();
	return 0;
	}

    TmpDir = tosh_tempdir();

    // Note: We assume that "prefix" always equals "execprefix".
    Prefix = CString(tosh_getselfpath(argv[0])).dirname().dirname();
    ExecPrefix = Prefix + "/";

    CStringList argStage0, argStagei, sourceList;
    CStringTok cExt(NULL), cplusExt(NULL);

    for (int n = 1; n < argc; n++)
	{
	if (argv[n][0] != '-')
	    {
	    int isSource = 0;

	    if (findFileExt(argv[n],C_Extensions))
		{
		isSource = 1;
		cFileCount++;
		}
	    else if (findFileExt(argv[n],Cplus_Extensions))
		{
		isSource = FlagCplusPlus = 1;
		cplusplusFileCount++;
		}

	    if (isSource)
		{
		sourceList.append(new LString(argv[n]));
		argStagei.append(new LString(SRC_PLACEHOLDER)); // placeholder for source
		}
	    else
		{
		argStage0.append(getQuotedArg(argv[n]));
		argStagei.append(getQuotedArg(argv[n]));
		}
	
	    continue;
	    }

	if (findLocalOpt(argv[n]))
	    {
	    // update the user-defined extension slot for C/C++ source
	    // files if given.

	    if (FlagCExtSet)
		{
		cExt.overwrite(CUserSrcExt);
		C_Extensions[0].in = cExt.getNextTok(':');
		C_Extensions[0].out = cExt.getNextTok('\0');
		if (!C_Extensions[0].out)
		    C_Extensions[0].out = ".i";
		FlagCExtSet = 0;
		}
	    else if (FlagCplusExtSet)
		{
		cplusExt.overwrite(CplusUserSrcExt);
		Cplus_Extensions[0].in = cplusExt.getNextTok(':');
		Cplus_Extensions[0].out = cplusExt.getNextTok('\0');
		if (!Cplus_Extensions[0].out)
		    C_Extensions[0].out = ".ii";
		FlagCplusExtSet = 0;
		}

	    continue;
	    }

	struct stripped_options optinfo;

	if (!filterOpt(argv,argc,n,optinfo))
	    {
	    argStage0.append(getQuotedArg(argv[n]));
	    argStagei.append(getQuotedArg(argv[n]));
	    continue;
	    }

	if (!optinfo.allStages)
	    argStagei.append(new LString(argv[n]));

	if (optinfo.withArg &&
	    strlen(argv[n]) == strlen(optinfo.prefix) &&
	    ++n < argc &&
	    !optinfo.allStages)
	    argStagei.append(getQuotedArg(argv[n]));
	}

    if (BackendPrefix.isEmpty())
	// Set default value.
	BackendPrefix = ExecPrefix + "libexec/gcic";

    if (access(BackendPrefix,0) < 0)
	{
	fprintf(stderr,
		"gcic: instrumenter/compiler is missing -- please check your installation.\n"
		"(GCC version %s + instrumenter extension expected\nwith --prefix=%s)\n",
		MVM_GCC_VERSION,
		(const char *)BackendPrefix);
	return 2;
	}

    BackendPrefix.appendChar('/');
    GccPrefix = BackendPrefix + "lib/gcc-lib/";

    if (FlagVersion)
	{
	if (isatty(1))
	    {
	    printf("C/C++ application instrumenter for Xenomai's simulation engine %s.\n",MVM_VERSION_STRING);
	    printf("Xenomai comes with absolutely no warranty.\n");
	    printf("This is free software, and you are welcome to redistribute it\n");
	    printf("under certain conditions; read the COPYING file for details.\n");
#ifdef CXX_VERSION
	    printf("(compiled with GNU/CC version %s)\n",CXX_VERSION);
#endif
	    }
	else
	    {
	    const char *eos = strchr(MVM_VERSION_STRING,' ');
	    printf("gcic-%.*s\n",eos ? eos - MVM_VERSION_STRING :
		   (int)strlen(MVM_VERSION_STRING),
		   MVM_VERSION_STRING);
	    }
	}

    if (FlagGccVersion)
	getGccVersion();

    if (FlagHelp)
	usage();

    if (FlagVersion || FlagGccVersion || FlagHelp)
	return 0;

    FlagLinking = !(FlagPreprocess || FlagAssemble || FlagObjectOnly);

    // In order to escape from the instrumenter-base/default compiler
    // incompatibility nightmare, simply do not allow to ask for
    // compilation and link on the same command line. At the end of
    // the day, this will save a lot of time for everyone.

    if (FlagLinking && sourceList.getCount() > 0)
	{
	fprintf(stderr,"gcic: cannot handle compile-and-link requests,\n");
	fprintf(stderr,"      please link using a separate GCIC invocation.\n");
	return 2;
	}

    // If the compilation command syntax has not been given son far,
    // try to find a usable default for a native target.

    if (!FlagCCmdSet)
	{
	if (FlagLinking)
	    {
	    // Always use the regular compilation front-end when
	    // linking. Admittedly, this will only work if the default
	    // compiler has been used to build the MVM, or is at least
	    // compatible with the instrumenter base (2.95.x).
	    FlagGcicCompiler = 0;
	    // Force the use of the C++ front-end when linking.
	    FlagCplusPlus = 1;
	    }

	if (FlagGcicCompiler)
	    {
	    // If told to use our own GCC distro, force the
	    // compilation drivers; do *not* depend on what is found
	    // on the search path.

	    CString gccPrefixOpt("-B");
	    gccPrefixOpt += GccPrefix;
	    argStage0.prepend(new LString(gccPrefixOpt));
	    argStagei.prepend(new LString(gccPrefixOpt));

	    if (FlagCplusPlus)
		CCCmdString = BackendPrefix + "bin/c++ ";
	    else
		CCCmdString = BackendPrefix + "bin/gcc ";
	    }
	else if (FlagCplusPlus)
	         CCCmdString = "c++ ";
	     else
		 CCCmdString = "gcc ";
	}
    else
	FlagGcicCompiler = 0;

    // Trap SIGINT, SIGTERM and SIGHUP to exit gracefully
    struct sigaction sa;
    sa.sa_handler = (SIGHANDLER_TYPE)cleanupOnSig;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT,&sa,NULL);
    sigaction(SIGTERM,&sa,NULL);
    sigaction(SIGHUP,&sa,NULL);
    atexit(&cleanup);

    if (sourceList.getCount() > 0)
	{
	if (FlagGcicCompiler)
	    addIncludePrefixes(CCCmdString,FlagCplusPlus);

	// Add the instrumenter signatures to the definitions.

	argStage0.append(new LString("-D__GCIC__"));
	argStage0.append(new LString("-D__XENO_SIM__ -D__XENO__"));

	// Automatically add Xenomai's system and MVM include
	// directories.

	CString incDir("-I");
	incDir += Prefix;
	incDir += "/include";

	argStage0.append(new LString(incDir + "/asm-sim"));
	argStage0.append(new LString(incDir));

	for (LString *ls = sourceList.first();
	     ls; ls = (LString *)ls->next())
	    {
	    if (patchSource(argStage0,argStagei,*ls) < 0)
		return 1;
	    }

	if (FlagToStdout)
	    return 0;
	}

    // If requested to do so, create a (dummy) dependency file so that
    // no one breaks upstream even after we have filtered out the -MF
    // option. This is basically useful when using our private GCC
    // install to compile, since our 2.9x backend is too old to handle
    // dependency generation. We could have been a bit smarter by not
    // filtering the -MF option when 3.x compilers and above are used
    // for compiling the preprocessed output, but having dependency
    // information straight for native simulation code in our
    // Automake-controlled tree is not that important anyway (i.e. not
    // worth the burden).

    if (!DepsFile.isEmpty())
	close(creat(DepsFile,0666));

    if (FlagDryRun) // Do not go further for a dry run
	return 0;

    // Do not allow to mix language types when actually compiling: we
    // would not be able to specify the corresponding CPP output types
    // sanely to GCC. A smarter approach would have been to compile
    // the files one by one, parsing the command line more thoroughly,
    // but it seems rather overkill to implement a fully transparent
    // GCIC front-end for now.

    if (cFileCount > 0 && cplusplusFileCount > 0)
	{
	fprintf(stderr,"gcic: cannot handle mixed languages for actual compilation,\n");
	fprintf(stderr,"      please compile C and C++ files using separate GCIC invocations.\n");
	}

    if (cplusplusFileCount > 0 && !compatible_base_compiler)
	{
	fprintf(stderr,"gcic: cannot compile C++ applications from a GCC 3.x environment.\n");
	fprintf(stderr,"      To do this, please downgrade to GCC 2.95.x and rebuild Xenomai.\n");
	}

    // Do not run the CPP on the preprocessed input file again; as of
    // now, it cannot always reprocess correctly the internal
    // indicators associated to the #line directives from a CPP output
    // file (see the CPP updates included in the instrumenter patch
    // for more). It is assumed that C and C++ source files will not
    // be mixed on a single command-line.

    if (sourceList.getCount() > 0)
	argStagei.prepend(new LString(FlagCplusPlus ?
				      "-xc++-cpp-output" :
				      "-xcpp-output"));

    for (LString *ls = argStagei.first();
	 ls; ls = (LString *)ls->next())
	{
	CCCmdString.appendChar(' ');
	CCCmdString += *ls;
	}

    if (FlagLinking)
	{
	CCCmdString += " -u main -u __xeno_skin_init -u __xeno_user_init";

	CString libDir(ExecPrefix);
	libDir += "lib";
	CCCmdString += " -L";
	CCCmdString += libDir;
	CCCmdString += " -Wl,-rpath,";
	CCCmdString += libDir;

	if (!FlagNoMvmLib)
	    {
	    CCCmdString += " -lmvm";
	    CCCmdString += " -lmvmutils";
	    CCCmdString += " -lnucleus_sim";
	    }

	CCCmdString += " -lm";
#ifdef HAVE_LIBELF
	CCCmdString += " -lelf";
#endif // HAVE_LIBELF
#ifdef HAVE_LIBNSL
	CCCmdString += " -lnsl";
#endif // HAVE_LIBNSL
#ifdef HAVE_LIBSOCKET
	CCCmdString += " -lsocket";
#endif // HAVE_LIBSOCKET
#ifdef HAVE_LIBDL
	CCCmdString += " -ldl";
#endif // HAVE_LIBDL
	CCCmdString += " -Wl,-export-dynamic";
	}

    char *av[4];
    av[0] = "sh";
    av[1] = "-c";
    av[2] = CCCmdString.gets();
    av[3] = NULL;

    if (FlagVerbose)
	printf("%s\n",CCCmdString.gets());

    rc = tosh_spawnw(av[0],av);

    if (rc)
	return rc;

    // If no output file has been specified while producing object or
    // asm files, rename those files to match their respective source
    // base name.
 
    if ((FlagObjectOnly || FlagAssemble) && !FlagOutputFile)
	{
	for (LString *ls = BaseFiles.first();
	     ls; ls = (LString *)ls->next())
	    {
	    CString srcFile("ic1@" + *ls), dstFile(*ls);

	    if (FlagAssemble)
		{
		srcFile += AsmExt;
		dstFile += AsmExt;
		}
	    else
		{
		srcFile += ObjectExt;
		dstFile += ObjectExt;
		}

	    if (rename(srcFile,dstFile) < 0)
		{
		fprintf(stderr,
			"gcic: failed to rename %s to %s\n",
			(const char *)srcFile,
			(const char *)dstFile);
		rc = 2;
		}
	    }
	}

    return rc;
}
