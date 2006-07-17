/*
 * err.c for dagrab
 *
 * Miroslav Stibor <stibor@vertigo.fme.vutbr.cz>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include "dagrab.h"
#include <stdlib.h>
#include <stdio.h>

/* 
 * check err.h before inserting/deleting an entry! 
 */
char *errs[] = {
"%s: error opening device %s, maybe try -d option\n",	/* ERR_DEV_OPEN */
"%s: %s: read TOC ioctl failed\n",			/* ERR_READ_TOC */
"%s: data allocation failed\n",				/* ERR_ALLOC */
"%s: read TOC entry ioctl failed\n",			/* ERR_TOC_ENTRY */
"%s: error opening wave file %s\n",			/* ERR_OPEN */
"%s: error changing mode of wave file %s\n",		/* ERR_CHMOD */
"\n%s: error writing wave file %s\n"			/* ERR_WRITING */
};

inline void die(int n, char *p)
{
	fprintf(stderr, errs[n], PROGNAME, p);
	exit(1);
}
