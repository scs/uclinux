/* Nessus
 * Copyright (C) 1998 - 2002 Renaud Deraison
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
 * Log.c -- manages the logfile of Nessus
 *
 */
 


#include <includes.h>
#include <stdarg.h>
#ifndef _CYGWIN_
#include <syslog.h>
#endif

#ifdef NESSUSNT
#include <time.h>
#include "wstuff.h"
#endif
#include "comm.h"
#include "utils.h"
#include "log.h"
#include "corevers.h"


#ifdef _CYGWIN_
static char *log_ident = 0;
static int log_sock = -1;
static int my_openlog(const char *ident, int ignored, int ignored2) {
	struct sockaddr_in sa;

	log_ident = strdup(ident);
	log_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if(log_sock < 0)
		return;
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons(514);
	if(connect(log_sock, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		shutdown(log_sock, 2);
		close(log_sock);
		log_sock = -1;
	}
}
static void my_closelog() {
	if(log_ident) {
		free(log_ident);
		log_ident = 0;
	}
	if(log_sock >= 0) {
		shutdown(log_sock, 2);
		close(log_sock);
		log_sock = -1;
	}
}

static int my_syslog(int priority, char *fmt, ...) {
  va_list param;
  char disp[4096];
  char * tmp;
  va_start(param, fmt);
  vsnprintf(disp, sizeof(disp),fmt, param);

  while((tmp=(char*)strchr(disp, '\n')))tmp[0]=' ';
  if(disp[strlen(disp)-1]=='\n')disp[strlen(disp)-1]=0;
  if(log_sock >= 0)
  {
   char timestr[255];
   time_t t;
   FILE *log = fdopen(log_sock, "w");
   
   t = time(NULL);
   tmp = ctime(&t);
   
   strncpy(timestr, tmp, sizeof(timestr) - 1);
   timestr[sizeof(timestr) -  1 ] = '\0';
   timestr[strlen(timestr) - 1] = '\0'; /* chop(timestr) */
   fprintf(log, "[%s][%d] %s\n", timestr, getpid(), disp);
  }
  va_end(param);  
}
#define openlog		my_openlog
#define syslog		my_syslog
#define closelog	my_closelog
#define LOG_DAEMON	(3 << 3)
#define LOG_NOTICE	5
#endif
static FILE * log;


/* 
 * initialization of the log file
 */
void 
log_init(filename)
  const char * filename;
{
  if((!filename)||(!strcmp(filename, "stderr"))){
  	log = stderr;
	dup2(2, 3);
	}
  else if(!strcmp(filename, "syslog")){
  	openlog("nessusd", 0, LOG_DAEMON);
	log = NULL;
	}
  else
    {
      int fd = open(filename, O_WRONLY|O_CREAT|O_APPEND, 0644);
      if(fd < 0)
      {
       perror("log_init():open ");
       print_error("Could not open the logfile, using stderr\n");
       log = stderr;
      }
      
      if(fd != 3)
      {
      if(dup2(fd, 3) < 0)
      {
        perror("dup2 ");
      }
      close(fd);
      }
      
      log = fdopen(3, "a");
      if(log == NULL)
       {
       perror("fdopen ");
       log = stderr;
       dup2(2, 3);
       }
       
#ifdef _IOLBF
	setvbuf(log, NULL, _IOLBF, 0);
#endif	       
    }
}



void log_close()
{
 if(log != NULL)
 {
  log_write("closing logfile");
  fclose(log);
  log = NULL;
 }
 else closelog();
}
 

/*
 * write into the logfile
 * Nothing fancy here...
 */
void 
log_write(const char * str, ...)
{
  va_list param;
  char disp[4096];
  char * tmp;
  
  va_start(param, str);
  vsnprintf(disp, sizeof(disp),str, param);
  va_end(param);  
  
  tmp = disp;
  while((tmp=(char*)strchr(tmp, '\n')) != NULL)
  	tmp[0]=' ';
  
	
  if(log != NULL)
  {
   char timestr[255];
   time_t t;
   
   t = time(NULL);
   tmp = ctime(&t);
  
   timestr[sizeof(timestr) - 1 ] = '\0';
   strncpy(timestr, tmp, sizeof(timestr) - 1);
   timestr[strlen(timestr) - 1 ] = '\0';
   fprintf(log, "[%s][%d] %s\n", timestr, getpid(), disp);
  }
  else syslog(LOG_NOTICE, "%s", disp);
}

