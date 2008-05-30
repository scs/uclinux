/* signals.c - signal name handling */
/***********************************************************************\
*   Copyright (C) 1992-1998 by Michael K. Johnson, johnsonm@redhat.com *
*                                                                      *
*      This file is placed under the conditions of the GNU Library     *
*      General Public License, version 2, or any later version.        *
*      See file COPYING for information on distribution  conditions.   *
\***********************************************************************/



#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "proc/signals.h"


typedef struct {
    int number;
    char *name;
} SIGNAME;


static SIGNAME signals[] = {
#include "signames.h" /* should be in same dir as this file */
  { 0,NULL }};


void list_signals(void)
{
    SIGNAME *walk;
    int col;

    col = 0;
    for (walk = signals; walk->name; walk++) {
	if (col+strlen(walk->name)+1 > 80) {
	    putchar('\n');
	    col = 0;
	}
	printf("%s%s",col ? " " : "",walk->name);
	col += strlen(walk->name)+1;
    }
    putchar('\n');
}


int get_signal(char *name,char *cmd)
{
    SIGNAME *walk;

    if (isdigit(*name))
	return atoi(name);
    for (walk = signals; walk->name; walk++)
	if (!strcmp(walk->name,name)) break;
    if (walk->name) return walk->number;
    fprintf(stderr,"%s: unknown signal; %s -l lists signals.\n",name,cmd);
    exit(1);
}

/* get_signal2 is by Michael Shields. 1994/04/25. */
int get_signal2(char *name)
{
    SIGNAME *walk;

    if (!name)
        return(-1);
    if (isdigit(*name))
	return atoi(name);
    for (walk = signals; walk->name; walk++)
        if (!strcmp(walk->name,name))
            return(walk->number);
    return(-1);
}
