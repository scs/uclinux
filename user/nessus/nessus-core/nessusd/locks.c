/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
 *
 * Trivial file locking primitives
 */

#include <includes.h>
#include "utils.h"
#include "log.h"
static char * 
file_lock_name(name)
 char*name;
{
 char * ret;
 char * t;
 
 if(!name)
  return NULL;
 
 ret = emalloc(strlen(name)*2 + 6);
 name = strdup(name);
 t = strrchr(name, '/');
 if(t)
 {
  t[0] = '\0';
  sprintf(ret, "%s/.%s.lck", name, t+1);
  t[0] = '/';
 }
 else sprintf(ret, ".%s.lck", name);
 
 efree(&name);
 return ret;
}
 
int 
file_lock(name)
 char * name;
{
 char * lock = file_lock_name(name);
 int fd = -1;
 char buf[20];
 fd = open(lock, O_RDWR|O_CREAT|O_EXCL, 0600);
 efree(&lock);
 if(fd < 0)
  return -1;
 
 bzero(buf, sizeof(buf));
 snprintf(buf, sizeof(buf), "%d", getpid());
 write(fd, buf, strlen(buf));
 close(fd);
 return 0;
}

int 
file_unlock(name)
 char * name;
{
 char * lock = file_lock_name(name);
 int e = 0;

 e = unlink(lock);
 efree(&lock);
 return e;
}

int
file_locked(name)
 char * name;
{
 char * lock = file_lock_name(name);
 char asc_pid[20];
 int pid;
 int ret = 0;
 int fd = open(lock, O_RDONLY);
 if(fd < 0)
 {
  efree(&lock);
  return 0;
 }
 
 
 /*
  * We check that the process which set the
  * lock is still alive
  */
 bzero(asc_pid, sizeof(asc_pid));
 read(fd, asc_pid, sizeof(asc_pid)-1);
 close(fd);
 pid = atoi(asc_pid);
 if(process_alive(pid))
 {
  log_write("The file %s is locked by process %d. Delete %s if you think this is incorrect\n",
  		name,
		pid,
		lock);
  ret = 1;		
 }
 else
  file_unlock(name);
  
 efree(&lock);
 return ret;
}
