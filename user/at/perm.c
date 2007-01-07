/* 
 *  perm.c - check user permission for at(1)
 *  Copyright (C) 1994  Thomas Koenig
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* System Headers */

#include <sys/types.h>

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#include <pwd.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Local headers */

#include "privs.h"
#include "at.h"

/* Macros */

#if defined(DEBUG_PERM_C)
#define ETCDIR "../test/etc"
#undef PRIV_START
#define PRIV_START while(0)
#undef PRIV_END
#define PRIV_END while(0)
#endif

/* Structures and unions */


/* File scope variables */

static char rcsid[] = "$Id: perm.c,v 1.4 1997/03/12 19:36:06 ig25 Exp $";

/* Function declarations */

static int user_in_file(const char *path, const char *name);

/* Local functions */

/* 
 */  
static int 
user_in_file(const char *path, const char *name)
{
  FILE *fp;
  char buffer[256];
  int found = 0;
  int c = '\n';

  PRIV_START;
    fp = fopen( path, "r");
  PRIV_END;

  if ( fp == NULL )
    return -1;


  while ( !found && fgets(buffer, sizeof(buffer), fp) != NULL) {
    size_t llen = strlen(buffer);

    c = buffer[llen-1];

    if (c == '\n')
      buffer[llen-1] = '\0';
    while (c != '\n' && c != EOF)
      c = fgetc(fp);
    
    found = (strcmp(buffer, name)==0);
  }

  fclose(fp);

  if (c == EOF) {
    fprintf(stderr, "%s: incomplete last line.\n", path);
  }

  return found;
}


/* Global functions */
int
check_permission()
{
  uid_t uid = geteuid();
  struct passwd *pentry;
  int    allow = 0, deny = 1;

  if (uid == 0)
    return 1;

  if ((pentry = getpwuid(uid)) == NULL) {
    perror("Cannot access user database");
    exit(EXIT_FAILURE);
  }

  allow = user_in_file(ETCDIR "/at.allow", pentry->pw_name);
  if (allow==0 || allow==1)
    return allow;

  /* There was an error while looking for pw_name in at.allow.
   * Check at.deny only when at.allow doesn't exist.
   */
 
  deny = user_in_file(ETCDIR "/at.deny", pentry->pw_name);
  return deny == 0;
}


#if defined(DEBUG_PERM_C)

int
main(int argc, char *argv[])
{
  printf("check_permission() ==> %d\n", check_permission());
  return 0;
}

#endif
