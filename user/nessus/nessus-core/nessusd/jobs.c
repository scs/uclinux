/* Nessus
 * Copyright (C) 1998, 1999, 2000 Renaud Deraison
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * In addition, as a special exception, Renaud Deraison
 * gives permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 */
/*
 * Jobs management
 * 
 * Nessus implements its own crond(8)-like management. This way, it knows
 * what to do at startup. We can use this for scheduled detached scans.
 * This also allows us to start the right detached sessions at startup,
 * which is convienent in case of crash
 *
 * This also simplifies the management of continuous scan, as the "continuous"
 * logic is moved somewhere else.
 *
 * I tried to be modular enough to simplify database management here.
 *
 *
 * TODO : document this :)
 *
 * Author : Renaud "I'm bored 'cause I don't have internet access" Deraison
 *
 *
 */
#include <includes.h>


/*--------------------------------------------------------------------------*
 * Basic file management.                                                   *
 *--------------------------------------------------------------------------*/
 
static char *
jobs_get_fname(id)
 int id;
{
 static char fname [sizeof(NESSUSD_JOBS) + 20];
 snprintf(fname, sizeof(fname), "%s/%d", NESSUSD_JOBS, id);
 return fname;
}


static DIR * 
jobs_open_dir()
{
 return opendir(NESSUSD_JOBS);
}

static int jobs_close_dir(dir)
 DIR * dir;
{
 return closedir(dir);
}

static int
jobs_get_next_id()
{
 int id = 1; /* start at 1 */
 DIR * dir = jobs_open_dir();
 if(dir)
 {
  struct dirent * dp;
  while((dp = readdir(dir)))
  {
   int cur_id = atoi(dp->d_name);
   if(cur_id >= id)id = cur_id + 1;
  }
  jobs_close_dir(dir);
 }
 return id;
}

/*
 * Add a new job in the queue.
 *
 * Returns the id of the new job
 */
int
jobs_add(globals, date, target)
 struct arglist * globals;
 char * date;
 char * target;
{
 char * user = globals ? arg_get_value(globals, "user"):"foo";
 char * fname;
 int id;
 int fd;
 struct arglist * preferences = globals ? arg_get_value(globals, "preferences"):NULL;
 
 id = jobs_get_next_id();
 fname = jobs_get_fname(id);
 fd = open(fname, O_RDWR|O_CREAT|O_EXCL, 0600);
 if(fd < 0)
 {
  log_write("Error creating %s - %s\n", fname, strerror(errno));
  return -1;
 }

 write(fd, date, strlen(date));
 write(fd, "\n", 1);
 
 write(fd, user, strlen(user));
 write(fd, "\n", 1);
 
 write(fd, target, strlen(target));
 write(fd, "\n", 1);
 

  if(preferences)
  {
   while(preferences->next)
   {
    write(fd, preferences->name, strlen(preferences->name));
    write(fd, " = ", 3);
    write(fd, preferences->value, strlen(preferences->value));
    write(fd, "\n", 1);
    preferences = preferences->next;
   }
  }
  close(fd);
  
  return id;
}

static int
jobs_rm(id)
 int id;
{
 char * fname =  jobs_get_fname(id);
 int e;

 e = unlink(fname);
 if(e < 0)
 {
  log_write("Error deleting %s - %s\n", fname, strerror(errno));
  return -1;
 }
 
 return 0;
}

static char * 
jobs_get_owner(id)
 int id;
{
 static char owner[1024];
 char * fname = jobs_get_fname(id);
 int fd  = open(fname, O_RDONLY);
 FILE * f;
 char buf[1024];
 if(fd < 0)
 {
  log_write("Error opening %s - %s\n", fname, strerror(errno));
  return NULL;
 }
 
 f = fdopen(fd, "r");
 bzero(buf, sizeof(buf));
 fgets(buf, sizeof(buf) - 1, f);
 bzero(buf, sizeof(buf));
 fgets(buf, sizeof(buf) - 1, f);
 if(buf[strlen(buf) - 1] == '\n'){
 	buf[strlen(buf) - 1] = '\0';
	if(strlen(buf) > (sizeof(owner) - 1))
	 {
	 log_write("Error for job %d - user name too long\n", id);
	 return NULL;
	 }
	strncpy(owner, buf, strlen(buf));
 	return owner;
	}
 log_write("Error parsing job %d\n", id);
 return NULL;
}



/*---------------------------------------------------------------------*
 * Jobs restoration                                                    *
 *---------------------------------------------------------------------*/
 
 
static char *
jobs_running_dirname()
{ 
 static char ret [ PATH_MAX + 1];
 if((strlen(NESSUSD_JOBS) + strlen("/running")) > 
    (sizeof(ret) - 1))
    {
     log_write("jobs_running_dirname(): file name too long");
     return NULL;
    }
  snprintf(ret, sizeof(ret), NESSUSD_JOBS"/running");
  mkdir(ret, 0700);
  chmod(ret, 0700);
  return ret;
}


static char *
jobs_running_fname(id)
 int id;
{
 static char ret [ PATH_MAX + 1];
 char * dir  =  jobs_running_dirname();
 
 if((strlen(dir) + 20) > 
    (sizeof(ret) - 1))
    {
     log_write("jobs_running_fname(): file name too long");
     return NULL;
    }
  snprintf(ret, sizeof(ret), "%s/%d", dir, id);
  return ret;
}


static int
jobs_mark_active(id)
 int id;
{
 char * fname;
 int fd;
 
 fname = jobs_running_fname(id);
 fd = open(fname, O_RDWR|O_CREAT|O_EXCL, 0600);
 if(fd < 0)
 {
  log_write("jobs_mark_active(): could not open %s - %s\n", fname, strerror(errno));
  return -1;
 } 
 
 /*
  * XXX write stuff
  */
 
  
  
  close(fd);
}




static int
jobs_mark_inactive(id)
 int id;
{
 char * fname = jobs_running_fname(id);
 int    e     = unlink(fname);
 
 if(e < 0)
 {
  log_write("jobs_mark_inactive - could not unlink %s - %s\n", fname, strerror(errno));
  return -1;
 }
 
 return 0;
}



static int 
jobs_restore(globals, id)
 struct arglist * globals;
 int id;
{
 return 0;
}


static int
jobs_run(globals, id)
 struct arglist * globals;
 int id;
{
 /*
  * Create a thread here please
  */
 if(jobs_mark_active(id))
  return -1;
  
 if(jobs_restore(id))
  return -1;
  
 if(jobs_mark_inactive(id))
  return -1;
 
 return 0;
}
