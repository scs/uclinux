/* Nessus
 * Copyright (C) 1998 - 2001 Renaud Deraison
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
 *
 *
 * If we want to scan big networks, nothing should be kept in memory
 * but be stored on disk instead. This also makes the link with
 * a database much easier.
 *
 * "As-is", this module generates a .nsr file on the fly, and nessus
 * reads it at the end of the scan.
 */

#include <includes.h>
#include "monitor_backend.h"
#include "nsr_output.h"
#include "error_dialog.h"

	
#define MAX_TMPFILES 1024
struct tmpfile tmpfiles[MAX_TMPFILES];




void be_info(be, str)
{
#ifdef BACKEND_DEBUG
 printf("%s(%d) disposable:%d, fd:%d, %s\n",
 		str,
 		be,
		tmpfiles[be].disposable,
		tmpfiles[be].fd,
		tmpfiles[be].fname);
#endif
}		

/*--------------------------------------------------------------------*
  	Monitoring functions
----------------------------------------------------------------------*/


int 
monitor_backend_init(fname)
 char * fname;
{
 char * tmpfile;
 int i = 0;
 char * tmpdir;
 
 while((tmpfiles[i].fname) && (i<MAX_TMPFILES))i++;
 if(tmpfiles[i].fname)
  {
   show_error("No free tempfile !\n");
   return -1;
  }
 if(!fname)
 {
 tmpdir = getenv("TMPDIR");
 if(!tmpdir)tmpdir = getenv("TEMPDIR");
 if(!tmpdir)tmpdir = "/tmp";
 
 tmpfile = emalloc(strlen(tmpdir) + strlen("/nessus-XXXXXX") + 1);
 strcat(tmpfile, tmpdir);
 strcat(tmpfile, "/nessus-XXXXXX");
#ifdef HAVE_MKSTEMP
 tmpfiles[i].fd = mkstemp(tmpfile);
 fchmod(tmpfiles[i].fd, 0600); /* glibc bug */
#else
 mktemp(tmpfile);
 tmpfiles[i].fd = open(tmpfile, O_CREAT|O_EXCL|O_RDWR, 0600); 
#endif
 tmpfiles[i].disposable = 1;
 }
 else
 {
  if((tmpfiles[i].fd = open(fname,O_RDONLY)) < 0)
   {
   perror("open ");
   return -1;
   }
  tmpfile = estrdup(fname);
  tmpfiles[i].disposable = 0;
 }
 
 if(tmpfiles[i].fd < 0)
  {
  show_error(strerror(errno));
  return -1;
  }
 tmpfiles[i].fname = tmpfile; 
 tmpfiles[i].backend_type = BACKEND_NSR;
 
 be_info(i, "BACKEND_INIT");
		
 return i;
}



int 
monitor_backend_ro(be)
	int be;
{
	close(tmpfiles[be].fd);
	tmpfiles[be].fd = open(tmpfiles[be].fname, O_RDONLY);
	return 0;
}



int 
monitor_backend_type(be) 
 int be;
{
 return tmpfiles[be].backend_type;
}




/*
 * monitor_backend_write_port is a variation of monitor_backend_write(),
 * I should clean that up soon.
 */
int
monitor_backend_write_port(be, host, port)
 int be;
 char * host;
 char * port;
{
 lseek(tmpfiles[be].fd, 0, SEEK_END);
 if((write(tmpfiles[be].fd, host, strlen(host)) < 0 )	         ||
    (write(tmpfiles[be].fd, "|", 1) < 0)			 ||
    (write(tmpfiles[be].fd, port, strlen(port)) < 0)		 ||
    (write(tmpfiles[be].fd, "|", 1) < 0)			 ||
    (write(tmpfiles[be].fd, "\n", 1) < 0))
    	{
	perror("write ");
    	return -1;
	}
 else
   return 0;
}


int
monitor_backend_write(be, host, port, script_id, severity, data)
 int be; /* backend */
 char * host;
 char * port;
 char * script_id;
 char * severity;
 char * data;
{
 char * t;
 t = addslashes(data);

 lseek(tmpfiles[be].fd, 0, SEEK_END);
 if((write(tmpfiles[be].fd, host, strlen(host)) < 0) 	  	  ||
    (write(tmpfiles[be].fd, "|", 1) < 0) 			  ||
    (write(tmpfiles[be].fd, port, strlen(port)) < 0)	  	  ||
    (write(tmpfiles[be].fd, "|", 1) < 0) 			  ||
    (write(tmpfiles[be].fd, script_id, strlen(script_id)) < 0)    ||
    (write(tmpfiles[be].fd, "|", 1) < 0)			  ||
    (write(tmpfiles[be].fd, severity, strlen(severity)) < 0)      ||
    (write(tmpfiles[be].fd, "|", 1) < 0) 			  ||
    (write(tmpfiles[be].fd, t, strlen(t)) < 0)		  ||
    (write(tmpfiles[be].fd, "\n", 1) < 0))
 {
  perror("write ");
  efree(&t);
  return -1;
 }
 
 efree(&t);
 return 0;
}


struct arglist *
monitor_backend_load(be)
 int be;
{
 struct arglist * ret = NULL;

 
 file_to_arglist(&ret, tmpfiles[be].fname);

 return ret;
}



int
monitor_backend_close(be)
 int be;
{
 be_info(be, "CLOSE");
#ifdef HAVE_MMAP
 if(tmpfiles[be].mmap)
 {
  struct stat  buf;
  fstat(tmpfiles[be].fd, &buf);
  munmap(tmpfiles[be].mmap, buf.st_size);
  tmpfiles[be].mmap = NULL;
 }
#endif 
 if(tmpfiles[be].fd >= 0)
  close(tmpfiles[be].fd);
 tmpfiles[be].fd = -1;
}

int
monitor_backend_dispose(be)
 int be;
{
 int disposable = tmpfiles[be].disposable;
 
 be_info(be, "DISPOSE");
		
 if(tmpfiles[be].fd >= 0)
  monitor_backend_close(be);
 
 if(disposable)
 {
 unlink(tmpfiles[be].fname);
 }
 if(tmpfiles[be].fname)
	 bzero(tmpfiles[be].fname, strlen(tmpfiles[be].fname));
 efree(&(tmpfiles[be].fname));
 tmpfiles[be].fd = -1;
 return 0; 
}


int
monitor_backend_size(be)
 int be;
{
 if(tmpfiles[be].fname)
 {
  struct stat buf;
  if(!fstat(tmpfiles[be].fd, &buf))
    return buf.st_size;
  else
	 {
		 perror("fstat ");
    		 return -1;
	  }
 }
 return -1;
}


int
monitor_backend_clear_all()
{
 int i;
 for(i=0;i<MAX_TMPFILES;i++)
 {
  if(tmpfiles[i].fname)
   monitor_backend_dispose(i);
 }
}
