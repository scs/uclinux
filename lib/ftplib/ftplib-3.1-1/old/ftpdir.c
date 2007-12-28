/***************************************************************************/
/*									   */
/* ftpdir.c - perform a remote directory via ftplib                        */
/* Copyright (C) 1996, 1997 Thomas Pfau, pfau@cnj.digex.net                */
/*	73 Catherine Street, South Bound Brook, NJ, 08880		   */
/*									   */
/* This program is free software; you can redistribute it and/or    	   */
/* modify it under the terms of the GNU General Public License		   */
/* as published by the Free Software Foundation; either version 2	   */
/* of the License, or (at your option) any later version.		   */
/*		   							   */
/* This program is distributed in the hope that it will be useful,	   */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of	   */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the	   */
/* GNU General Public License for more details. 			   */
/*							   		   */
/* You should have received a copy of the GNU General Public License	   */
/* along with this progam; if not, write to the Free Software  		   */
/* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA		   */
/* 02111-1307, USA.							   */
/*									   */
/***************************************************************************/

#if defined(__unix__)
#include <unistd.h>
#elif defined(_WIN32)
#include <windows.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include "ftplib.h"

#if defined(__unix__)
#define ENV_USER "USER"
#elif defined(_WIN32)
#include "getopt.h"
#define ENV_USER "USERNAME"
#endif

static void usage(char *cmd)
{
    printf("%s <host> [filespec] [-l <username>] [-p <password]\n",cmd);
    exit(2);
}

static int ftpdir(char *host, char *user, char *pass, char *root, char *fspec)
{
    if (!ftpOpen(host))
    {
	fprintf(stderr,"Unable to connect to node %s\n%s",host,ftplib_lastresp);
	return 0;
    }
    if (!ftpLogin(user,pass))
    {
	fprintf(stderr,"Login failure\n%s",ftplib_lastresp);
	return 0;
    }
    if (root != NULL)
    {
	if (!ftpChdir(root))
	{
	    fprintf(stderr,"Change directory failed\n%s",ftplib_lastresp);
	    return 0;
	}
    }
    if (!ftpNlst(NULL,fspec))
    {
	fprintf(stderr,"Directory failure\n%s",ftplib_lastresp);
	return 0;
    }
    ftpQuit();
    return 1;
}

void main(int argc, char *argv[])
{
    char *host = NULL;
    char *user = NULL;
    char *pass = NULL;
    char *root = NULL;
    char mode;
    char *fspec = NULL;
    int opt;
    int i;

    while ((opt = getopt(argc,argv,"ail:p:r:v:")) != -1)
    {
	if (opt == '?')
	{
	    fprintf(stderr,"Unknown option %s\n",argv[optind]);
	    exit(2);
	}
	switch (optopt)
	{
	  case 'a' : mode = 'A'; break;
	  case 'i' : mode = 'I'; break;
	  case 'l' :
	    if (opt == ':')
	    {
		fprintf(stderr,"Missing value for -l\n");
		exit(2);
	    }
	    user = optarg;
	    break;
	  case 'p' :
	    if (opt == ':')
	    {
		fprintf(stderr,"Missing value for -p\n");
		exit(2);
	    }
	    pass = optarg;
	    break;
	  case 'r' :
	    if (opt == ':')
	    {
		fprintf(stderr,"Missing value for -r\n");
		exit(2);
	    }
	    root = optarg;
	    break;
	  case 'v' :
	    if (opt == ':')
		ftplib_debug++;
	    else
		ftplib_debug = atoi(optarg);
	    break;
	}
    }

    for (i=1;i<argc;i++)
    {
	if (*argv[i] == '-')
	{
	    switch (argv[i][1])
	    {
	      case 'l':
		user = argv[++i];
		break;
	      case 'p':
		pass = argv[++i];
		break;
	      case 'd':
		ftplib_debug++;
		break;
	      case 'r':
		root = argv[++i];
		break;
	      default:
		usage(argv[0]);
	    }
	}
	else if (host == NULL)
	    host = argv[i];
	else if (fspec == NULL)
	    fspec = argv[i];
	else
	    usage(argv[0]);
    }
    ftpInit();
    if (user == NULL)
    {
	user = "anonymous";
	if (pass == NULL)
	{
	    char *u,h[64];
	    u = getenv(ENV_USER);
	    if (gethostname(h,64) < 0)
	    {
		perror("gethostname");
		exit(2);
	    }
	    if ((u != NULL) && (h != NULL))
	    {
		static char xxx[64];
		sprintf(xxx,"%s@%s",u,h);
		pass = xxx;
	    }
	}
    }
    if ((host == NULL) || (user == NULL) || (pass == NULL))
	usage(argv[0]);

    if (!ftpdir(host,user,pass,root,fspec))
	exit(2);
    exit(0);
}
