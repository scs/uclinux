/* Nessus
 * Copyright (C) 1998 - 2003 Renaud Deraison
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
 * Plugins scheduler / launcher.
 *
 */
 
 
#include <includes.h>
#include "pluginload.h"
#include "piic.h"
#include "plugs_req.h"
#include "utils.h"
#include "preferences.h"
#include "log.h"
#include "sighand.h"
#include "processes.h"
#include "pluginscheduler.h"

struct running {
	nthread_t pid;
	int kb_soc;
	int data_soc;
	struct arglist * globals;
	struct arglist * kb;
	char           * name;
	struct arglist * plugin;
	struct timeval start;
	int timeout;
	int data_soc_upstream;
	};
	
	
/*
 * This is the 'hard' limit of the max. number of concurrent
 * plugins
 */	
#define MAX_PROCESSES 32
#undef VERBOSE_LOGGING	/* This really fills your nessusd.messages */

#undef DEBUG_CONFLICTS
static void read_running_processes();
static void update_running_processes();
	
static struct running processes[MAX_PROCESSES];
static int    num_running_processes;
static int    max_running_processes;
static int    old_max_running_processes;
static struct arglist * non_simult_ports_list;



 
/*
 * Due to linux' broken send() implementation, we have to multiplex
 * the data sent from the plugins to the client. Basically, we have the
 * following scheme :
 *
 *			client
 *			   |
 *			nessusd (utils.c - check_threads_input())
 *			/   |  \
 *		        h   h   h
 *		       /|\  |   |\
 *		      p p p p   p p
 *
 * This function works at the level of <h> and reads data coming from the
 * multiple <p>s. 
 */ 
static int forward_data(in, out)
 int in;
 int out;
{
 char buffer[65000];
 int len;
 int n;
 int in_err;
 
 buffer[sizeof(buffer) - 1] = '\0';
 do
 {
 len = recv_line(in, buffer, sizeof(buffer) - 1);
 if(len <= 0)
  return -1;
 /* ack our reception */
 do {
 in_err =  send(in, ".", 1, 0);
 } while (in_err < 0 && errno == EINTR);
  
 n = 0;
 while(n < len)
 {
  int e = send(out, buffer + n, len - n , 0);
  if(e < 0)
   {
   if( errno != EINTR )
    {
    fprintf(stderr, "pluginlaunch.c:forward_data() failed - %s\n", strerror(errno));
    break;
    }
   }
  else 
    n += e;
 }
 
 /*
  * Receive the ack
  */
ack_again :
  len = recv(out, buffer, 1, 0);
  
  if(len < 0)
   {
    if(errno == EINTR) goto ack_again;
    else perror("pluginlaunch.c: recv() ");
   }
  } 
  while( data_left(in) > 0);
  return 0;
} 
  
void
wait_for_children(int sig)
{
 int i;
 for(i = 0 ; i < MAX_PROCESSES ; i ++)
 {
	 int ret;
	 if(processes[i].pid != 0)
	 {
	 	do {
		 	ret = waitpid(processes[i].pid, NULL, WNOHANG);
		} while(ret < 0 && errno == EINTR);
	 }
				 	
 }
}
/*
 * Signal management
 */

void
process_mgr_sighand_term(sig)
 int sig;
{
 int i;

 for(i=0;i<MAX_PROCESSES;i++)
 {
  if(processes[i].pid > 0)
        {
	kill(processes[i].pid, SIGTERM);
	num_running_processes--;
	plugin_set_running_state(processes[i].plugin, PLUGIN_STATUS_DONE);
	bzero(&(processes[i]), sizeof(struct running));
	}
 }
 _EXIT(0);
}

 	
static void
update_running_processes()
{
 int i;
 struct timeval now;
 int log_whole = 1;
 
 for(i=0;(processes[i].globals == NULL) && i < MAX_PROCESSES; i ++) ;
 
 if(i < MAX_PROCESSES)
  {
  struct arglist * prefs = arg_get_value(processes[i].globals, "preferences");
  log_whole = preferences_log_whole_attack(prefs);
  }
 
 gettimeofday(&now, NULL);
 
 if(num_running_processes == 0)
  return;
  
 for(i=0;i<MAX_PROCESSES;i++)
 {
  if(processes[i].pid > 0)
  {
   int alive;
  if( (! (alive = process_alive(processes[i].pid))) ||
  	(processes[i].timeout > 0 &&
        ((now.tv_sec - processes[i].start.tv_sec) > processes[i].timeout)))
  {  
   if(alive){
	if(log_whole)
   		log_write("%s (pid %d) is slow to finish - killing it\n", 
   			processes[i].name, 
			processes[i].pid);
	terminate_process(processes[i].pid);
	}
   else  
   {
     struct timeval old_now = now;
     if(now.tv_usec < processes[i].start.tv_usec)
     {
      processes[i].start.tv_sec ++;
      now.tv_usec += 1000000;
     }
     if(log_whole)
     	log_write("%s (process %d) finished its job in %ld.%.3ld seconds\n", 
     			processes[i].name,
	 		processes[i].pid,
	 		now.tv_sec - processes[i].start.tv_sec,
			(now.tv_usec - processes[i].start.tv_usec) / 1000);
     now = old_now;			
   }
   num_running_processes--;
   plugin_set_running_state(processes[i].plugin, PLUGIN_STATUS_DONE);
   
   /*
    * Read remaining data in the buffer
    */ 
  if( data_left(processes[i].kb_soc) > 0 )
   piic_read_socket(processes[i].globals, processes[i].kb, processes[i].kb_soc);
  if( data_left(processes[i].data_soc) > 0 )
    forward_data(processes[i].data_soc, processes[i].data_soc_upstream);
  
   shutdown(processes[i].kb_soc, 2);
   shutdown(processes[i].data_soc, 2);
   close(processes[i].kb_soc);
   close(processes[i].data_soc);
   bzero(&(processes[i]), sizeof(processes[i]));
   }
  }
 }
}

static int
next_free_process(upcoming)
 struct arglist * upcoming;
{
 int r;
       	
 wait_for_children(0);
 for(r=0;r<MAX_PROCESSES;r++)
 {
  if(processes[r].pid > 0)
  { 
   struct arglist * common_ports;
   if((common_ports = requirements_common_ports(processes[r].plugin, upcoming)))
   {
    int do_wait = -1;
    if(common(common_ports, non_simult_ports_list))
     do_wait = r;
    arg_free(common_ports);
    if(do_wait >= 0)
     {
#ifdef DEBUG_CONFLICT
      printf("Waiting has been initiated...\n");
      log_write("Ports in common - waiting...\n");
#endif      
      while(process_alive(processes[r].pid))
      	{
	read_running_processes();
	update_running_processes();
	wait_for_children(0);
	}
#ifdef DEBUG_CONFLICT      
      printf("End of the wait - was that long ?\n");
#endif      
    }
   }
  }
 }
 r = 0;
 while((r < MAX_PROCESSES) &&
       (processes[r].pid > 0))r++;
       
 
 if(r >= MAX_PROCESSES)
  return -1;
 else
  return r;
}


static void
read_running_processes()
{
 int i;
 int flag = 0;
 struct timeval tv;
 fd_set rd;
 int max = 0;
 int e;


 if(num_running_processes == 0)
  return;
 

#ifdef VERBOSE_LOGGING
 log_write("Waiting for spawned processes (%d)\n", num_running_processes); 
#endif 

  FD_ZERO(&rd);
  for(i=0;i<MAX_PROCESSES;i++)
  {
    if(processes[i].pid > 0 )
    {
    FD_SET(processes[i].kb_soc, &rd);
    if( processes[i].kb_soc > max)
      	max = processes[i].kb_soc;

    FD_SET(processes[i].data_soc, &rd);
    if(processes[i].data_soc > max)
      	max = processes[i].data_soc;
    }
  }

again:
  tv.tv_sec = 0;
  tv.tv_usec = 50000;
  e = select(max + 1, &rd, NULL, NULL, &tv);
  if( e == 0 ) return;
  if( e < 0 && errno == EINTR)goto again;

  for(i=0;i<MAX_PROCESSES;i++)
  {
   if(processes[i].pid > 0 )
   {
     flag ++;
    if(FD_ISSET(processes[i].kb_soc, &rd) != 0 )
     piic_read_socket(processes[i].globals, processes[i].kb, processes[i].kb_soc);
    if(FD_ISSET(processes[i].data_soc, &rd) != 0 )
      forward_data(processes[i].data_soc, processes[i].data_soc_upstream);
  }
 }

 if(flag == 0 && num_running_processes != 0)
	  {
	   num_running_processes = 0;
	   }
}


void
pluginlaunch_init(globals)
 struct arglist * globals;
{
 struct arglist * preferences = arg_get_value(globals, "preferences");
 non_simult_ports_list = arg_get_value(preferences, "non_simult_ports_list");
 max_running_processes = get_max_checks_number(globals, preferences);
 old_max_running_processes = max_running_processes;
 
 signal(SIGCHLD, wait_for_children);
 
 if(max_running_processes >= MAX_PROCESSES)
 {
  log_write("max_checks (%d) > MAX_PROCESSES (%d) - modify nessus-core/nessusd/pluginlaunch.c\n",
  			max_running_processes,
			MAX_PROCESSES);
   max_running_processes = MAX_PROCESSES - 1;
 }

		
 num_running_processes = 0;
 bzero(&(processes), sizeof(processes));
 nessus_signal(SIGTERM, process_mgr_sighand_term);
}

void
pluginlaunch_disable_parrallel_checks()
{
  max_running_processes = 1;
}

void
pluginlaunch_enable_parrallel_checks()
{
 max_running_processes = old_max_running_processes;
}


void
pluginlaunch_stop()
{
 int i;
 read_running_processes();
 
 for(i=0;i<MAX_PROCESSES;i++)
 {
  if(processes[i].pid > 0)kill(processes[i].pid, SIGTERM);
 }
 
 usleep(2000);	 
 for(i=0;i<MAX_PROCESSES;i++)
 {
  if(processes[i].pid > 0)
  	 {
	 kill(processes[i].pid, SIGKILL);
	 num_running_processes--;
	 plugin_set_running_state(processes[i].plugin, PLUGIN_STATUS_DONE);
	 bzero(&(processes[i]), sizeof(struct running));
	 }
 }
 nessus_signal(SIGTERM, _exit);
}


int
plugin_launch(globals, plugin, hostinfos, preferences, key, name, launcher)
	struct arglist * globals;
	struct arglist * plugin;
	struct arglist * hostinfos;
	struct arglist * preferences;
	struct arglist * key;
	char * name;
	pl_class_t * launcher;
{ 
 int p;
 struct arglist * args = plugin->value;
 int dsoc[2], ksoc[2];


 /*
  * Wait for a free slot while reading the input
  * from the plugins
  */ 
 while (num_running_processes >= max_running_processes)
 {
  read_running_processes();
  update_running_processes();
 }
 
 
 p = next_free_process(plugin->value);
 processes[p].kb = key;
 processes[p].globals = globals;
 processes[p].plugin  = plugin->value;
 processes[p].name    = plugin->name;
 processes[p].timeout = preferences_plugin_timeout(preferences, plug_get_id(args));
 if( processes[p].timeout == 0)
   processes[p].timeout = plug_get_timeout(args);

 
 
 if(processes[p].timeout == 0)
 {
  int category = plug_get_category(args);
  if(category == ACT_SCANNER)processes[p].timeout = -1;
  else processes[p].timeout = preferences_plugins_timeout(preferences);
 }

 if(socketpair(AF_UNIX, SOCK_STREAM, 0, ksoc) < 0)
 { 
  perror("pluginlaunch.c:plugin_launch:socketpair(1) ");
 }
 gettimeofday(&(processes[p].start), NULL);

#if 0
 fprintf(stderr, "About to launch plugin: name=%s PPID=%d PID=%d\n",
	 name, getppid(), getpid());
 fflush(stderr); /* Just in case... */
#endif

 if(socketpair(AF_UNIX, SOCK_STREAM, 0, dsoc)  < 0)
 { 
  perror("pluginlaunch.c:plugin_launch:socketpair(2) ");
 }
 processes[p].data_soc_upstream = plugin_get_socket(plugin);
 processes[p].data_soc = dsoc[0];
 plugin_set_socket(plugin, dsoc[1]);
 

 processes[p].pid = 
 	(*launcher->pl_launch)(globals,
 			        plugin->value,
				hostinfos,
				preferences,
				key,
				name,
				ksoc[1]);
 
 processes[p].kb_soc = ksoc[0];
 close(ksoc[1]);
 close(dsoc[1]);
 if(processes[p].pid > 0)num_running_processes++;
 else plugin_set_running_state(processes[p].plugin, PLUGIN_STATUS_UNRUN);
 return processes[p].pid;
}


void 
pluginlaunch_wait()
{
 do
 {
  wait_for_children(0);
  read_running_processes();
  update_running_processes();
 }
 while (num_running_processes != 0);
}


void 
pluginlaunch_wait_for_free_process()
{
 int num = num_running_processes;
 do {
  wait_for_children(0);
  read_running_processes();
  update_running_processes();
 }
 while (num_running_processes == num);
}
