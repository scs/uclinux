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

#include <xeno_config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <limits.h>
#include <malloc.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <stdio.h>
#include <pwd.h>
#include "vmutils/toolshop.h"

static char *breakpath (char **markerp)

{
    char *s = *markerp;

    if (!s)
	return NULL;

    *markerp = strchr(s,':');

    if (*markerp)
	{
	**markerp = '\0';
	(*markerp)++;
	}

    return s;
}

static char *expandsymln (char *path)

{
    char truepath[PATH_MAX];

    if (!path)
	return NULL;

    if (realpath(path,truepath))
	{
	free(path);
	path = strdup(truepath);
	}

    return path;
}

static char *sappend (char *src, const char *tail)

{
    while (*tail)
	*src++ = *tail++;

    return src;
}

static char *expandvars (const char *s)

{
    static char result[MAXPATHLEN];
    char vname[64], *vp, *cp, *seg, *scopy;
    struct passwd *pw;

    scopy = strdup(s);
    cp = result;

    if (*scopy == '/')
	cp = sappend(cp,"/");

    if ((seg = strtok(scopy,"/")) != NULL)
	{
	do
	    {
	    if (*seg == '~')
		{
		if (!*++seg)
		    cp = sappend(cp,getenv("HOME"));
		else
		    {
		    pw = getpwnam(seg);
		    cp = sappend(cp,pw ? pw->pw_dir : "~");
		    }
		}
	    else if (strchr(seg,'$'))
		     {
		     do
			 {
			 char lastc;

			 for (lastc = '\0'; *seg && (*seg != '$' || lastc == '\\'); seg++)
			     {
			     lastc = *seg;
			     *cp++ = *seg;
			     }

			 if (*seg == '$')
			     {
			     vp = vname;

			     if (*++seg && strchr("({",*seg))
				 seg++;

			     for (*vp = 0; isalnum((int)*seg) || *seg == '_'; seg++)
				 *vp++ = *seg;
			 
			     *vp = 0;

			     if (strlen(vname) > 0)
				 {
				 cp = sappend(cp,getenv(vname));

				 if (*seg && strchr(")}",*seg))
				     seg++;
				 }
			     }
			 }
		     while (*seg);
		     }
	         else
		     cp = sappend(cp,seg);

	    if ((seg = strtok((char *)0,"/")) != NULL)
		cp = sappend(cp,"/");
	    }
	while (seg);
	}

    free(scopy);
    *cp = 0;

    return result;
}

char *tosh_findpath (const char *path)

{
    char *epath, *dirname, *marker, *fullpath = NULL;

    if (*path == '/')
	return expandsymln(strdup(path));

    if (strchr(path,'/'))
	{
	char wd[MAXPATHLEN];
	
	/* if we've got a relative path on input, we can find the
	   target file at: workingDir + "/" + path */

	if (!getcwd(wd,sizeof(wd)))
	    return NULL;

	fullpath = (char *)malloc(strlen(wd) + strlen(path) + 2);
	return expandsymln(strcat(strcat(strcpy(fullpath,wd),"/"),path));
	}

    epath = getenv("PATH");

    if (!epath)
	return NULL;

    epath = strdup(epath);
    marker = epath;

    while ((dirname = breakpath(&marker)) != NULL)
        {
	struct stat sbuf;

	/* `::' found in PATH string is legal and means `:.:' */
	if (!*dirname || *dirname == '.')
	  /* We should return an absolute path -- so forget relative specs */
	    continue;

	dirname = expandvars(dirname);
	fullpath = (char *)malloc(strlen(dirname) + strlen(path) + 2);
	strcat(strcat(strcpy(fullpath,dirname),"/"),path);

	/* tested entry must exists as a regular and
	   executable file for the owner */

	if (stat(fullpath,&sbuf) == 0 &&
	    S_ISREG(sbuf.st_mode) &&
	    (sbuf.st_mode & S_IEXEC))
	    break;

	free(fullpath);
	fullpath = NULL;
        }

    free(epath);

    return expandsymln(fullpath);
}

/*
  Note: always return the "real path" of the file, expanding all the
  symbolic links if any: we assume that the caller may need to
  determine other location of interest by applying relative
  displacements from it. As a side-effect, calling tosh_getselfpath()
  with a NULL argument returns the last search result.
 */

char *tosh_getselfpath (const char *argv0)

{
    static char *mypath;

    if (!mypath && argv0)
	{
	mypath = tosh_findpath(argv0);

	if (!mypath)
	    mypath = expandsymln(strdup(argv0));
	}

    return mypath ? strdup(mypath) : NULL;
}

const char *tosh_getposixpath (const char *path)

{ return path; }

const char *tosh_getcanonpath (const char *path)

{ return path; }

// tosh_getfileid() crunches inode-based data from the argument
// file to produce a unique identifier. Returns 0 on failure to access
// the file information.

u_long tosh_getfileid (const char *path)

{
    u_long fileid = 0;
    struct stat sbuf;
    const char *rp;
    int sz;

    if (stat(path,&sbuf) < 0)
	return 0;

#define FID_ULSZ          (sizeof(u_long) * 8)
#define FID_ROL(v,n)      ((v) << (n) | (v) >> (FID_ULSZ - (n)))
#define FID_HASH(h,c)     (((u_long)c) + FID_ROL((u_long)h,7))

    for (sz = 0, rp = (const char *)&sbuf.st_ino;
	 sz < sizeof(sbuf.st_ino); sz++, rp++)
	fileid += FID_HASH(fileid,*rp);

    for (sz = 0, rp = (const char *)&sbuf.st_ctime;
	 sz < sizeof(sbuf.st_ctime); sz++, rp++)
	fileid += FID_HASH(fileid,*rp);

    if (fileid != 0x678153bf)
	// Ensure 0 is never returned on success
	fileid ^= 0x678153bf;

    return fileid;
}

char *tosh_mktemp (const char *tmpdir,
		   const char *prefix)
{
    static char *oldtemp;
    int fd;

    if (oldtemp)
	free(oldtemp);

    /* Emulate tempnam() */

    if (!tmpdir)
	{
	tmpdir = getenv("TMPDIR");

	if (!tmpdir)
	    tmpdir = P_tmpdir;
	}

    if (!prefix)
	prefix= "";

    oldtemp = malloc(strlen(tmpdir) + strlen(prefix) + 8);
    strcpy(oldtemp,tmpdir);
    strcat(oldtemp,"/");
    strcat(oldtemp,prefix);
    strcat(oldtemp,"XXXXXX");

    fd = mkstemp(oldtemp);

    if (fd < 0)
	return NULL;

    close(fd);
    unlink(oldtemp);

    return oldtemp;
}

const char *tosh_tempdir ()

{
    char *tempn, *basen;

    tempn = tosh_mktemp(NULL,"x");

    if (!tempn)
	return NULL;

    basen = strrchr(tempn,'/');

    if (basen)
	*basen = '\0';

    return tempn;
}

int tosh_spawn (const char *program,
		char *const argv[])
{
    int pid = vfork();

    if (!pid)
	{
	execvp(program,argv);
	_exit(99);
	}
    else if (pid < 0)
	     return -1;

    return 0;
}

int tosh_spawnw (const char *program,
		 char *const argv[])
{
    int s;

    if (tosh_spawn(program,argv) < 0 || wait(&s) < 0)
	return 1;

    return WIFSIGNALED(s) ? WTERMSIG(s) : WEXITSTATUS(s);
}
