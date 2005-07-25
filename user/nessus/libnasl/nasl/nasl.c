/* Nessus Attack Scripting Language 
 *
 * Copyright (C) 2002 - 2003 Michel Arboi and Renaud Deraison
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
 * In addition, as a special exception, Renaud Deraison and Michel Arboi
 * give permission to link the code of this program with any
 * version of the OpenSSL library which is distributed under a
 * license identical to that listed in the included COPYING.OpenSSL
 * file, and distribute linked combinations including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * this file, you may extend this exception to your version of the
 * file, but you are not obligated to do so.  If you do not wish to
 * do so, delete this exception statement from your version.
 *
 */
#include <includes.h>

#include "nasl.h"
#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include <getopt.h>


#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif




extern char * nasl_version();
extern void * hg_init(char *, int);
extern int hg_next_host(void*, struct in_addr*, char *, int);
harglst * Globals;
extern int execute_instruction(struct arglist *, char *);
void exit_nasl(struct arglist *, int);


int safe_checks_only = 0;

static struct arglist * 
init_hostinfos( hostname, ip)
     char * hostname;
    struct in_addr * ip;
{
  struct arglist * hostinfos;
  struct arglist * ports;
  
  hostinfos = emalloc(sizeof(struct arglist));
  arg_add_value(hostinfos, "FQDN", ARG_STRING, strlen(hostname), hostname);
  arg_add_value(hostinfos, "NAME", ARG_STRING, strlen(hostname), hostname);
  arg_add_value(hostinfos, "IP", ARG_PTR, sizeof(struct in_addr), ip);
  ports = emalloc(sizeof(struct arglist));
  arg_add_value(hostinfos, "PORTS", ARG_ARGLIST, sizeof(struct arglist), ports);  
  return(hostinfos);
}

void
sighandler(s)
 int s;
{
 exit(0);
}

struct arglist * 
init(hostname, ip)
 char * hostname;
 struct in_addr ip;
{
 struct arglist * script_infos = emalloc(sizeof(struct arglist));
 struct arglist * prefs        = emalloc(sizeof(struct arglist));
 struct in_addr *pip = 		emalloc(sizeof(*pip));
 *pip = ip;
 
 arg_add_value(script_infos, "standalone", ARG_INT, sizeof(int), (void*)1);
 arg_add_value(prefs, "checks_read_timeout", ARG_STRING, 4, estrdup("5"));
 arg_add_value(script_infos, "preferences", ARG_ARGLIST, -1, prefs);
 
 if(safe_checks_only != 0)
   arg_add_value(prefs, "safe_checks", ARG_STRING, 3, estrdup("yes"));
   
 arg_add_value(script_infos, "HOSTNAME", ARG_ARGLIST, -1,
 		init_hostinfos(hostname, pip));
	
 return script_infos;
}

void
usage()
{
 printf("\nnasl -- Copyright (C) 1999 - 2003 Renaud Deraison <deraison@cvs.nessus.org>\n");
 printf("nasl -- Copyright (C) 2002 - 2003 Michel Arboi <arboi@alussinan.org>\n\n");
 printf("Usage : nasl [-vh] [-p] [ -t target ] [-T trace_file] script_file ...\n");
 printf("\t-h : shows this help screen\n");
  printf("\t-p : parse only - do not execute the script\n");
 printf("\t-t target : Execute the scripts against the target(s) host\n");
 printf("\t-T file : Trace actions into the file (or '-' for stderr)\n");
 printf("\t-s : specifies that the script should be run with 'safe checks' enabled\n");
 printf("\t-v : shows the version number\n");
}

extern FILE	*nasl_trace_fp;

int main(int argc, char ** argv)
{
 struct arglist * script_infos;
 int i;
 char * target = NULL;
 char * default_target = "127.0.0.1";
 char * kb_fname;
#ifdef __UCLIBC__
 struct hostent * he;
#else
 void * hg_globals;
#endif
 struct in_addr ip;
 int start, n; 
 char hostname[1024];
 int	mode = 0;
 
 /*--------------------------------------------
 	Command-line options
  ---------------------------------------------*/
  
 while((i = getopt(argc, argv, "hvt:k:T:sp"))!=EOF)
  switch(i)
  {
   case 't' :
   	if(optarg)target = strdup(optarg);
	else {
		usage();
		exit(1);
	     }
	 break;
   case 'p' :
     mode |= NASL_EXEC_PARSE_ONLY;
     break;
   case 'T':
     if (optarg == NULL || strcmp(optarg, "-") == 0)
       {
	 nasl_trace_fp = stderr;
       }
     else
       {
	 FILE	*fp = fopen(optarg, "w");
	 if (fp == NULL)
	   {
	     perror(optarg);
	     exit(2);
	   }
	 nasl_trace_fp = fp;
       }
     break;
   case 'h' :
   	usage();
	exit(0);
	break;
  case 'k':
  	if(optarg)kb_fname = strdup(optarg);
	else {
		usage();
		exit(0);
		}
	break;
 case 'v' :
 	printf("nasl %s\n\n", nasl_version());
	printf("Copyright (C) 1999 - 2003 Renaud Deraison <deraison@cvs.nessus.org>\n");
	printf("Copyright (C) 2002 - 2003 Michel Arboi <arboi@noos.fr>\n\n");
	printf("See the license for details\n\n\n");
	exit(0);
	break;
	
 case 's' :
 	safe_checks_only ++;
	break;

 }
 
 
 if(!argv[optind])
 { 
  fprintf(stderr, "Error. No input file specified !\n");
  usage();
 }
 
#ifndef _CYGWIN_
 if(geteuid())
 {
  fprintf(stderr, "** WARNING : packet forgery will not work\n");
  fprintf(stderr, "** as NASL is not running as root\n");
 }
 signal(SIGINT, sighandler);
 signal(SIGTERM, sighandler);
 signal(SIGPIPE, SIG_IGN);
#endif 
 if(!target)target = estrdup(default_target);
 
 start = optind;
 
#ifdef __UCLIBC__
 he = gethostbyname(target);
#else
 hg_globals = hg_init(target,  4);
#endif
 efree(&target);

#ifdef __UCLIBC__
 for (i=0; he->h_addr_list[i]; i++)
 {
 ip = *(struct in_addr *)(he->h_addr_list[i]);
 strcpy(hostname, he->h_name);
#else
 while(hg_next_host(hg_globals, &ip, hostname, sizeof(hostname)) >= 0)
 {
#endif
 script_infos = init(hostname, ip);
 n = start;
 while(argv[n])
  {
  execute_nasl_script(script_infos, argv[n], mode);
  n++;
  }
 }
#ifndef __UCLIBC__
 hg_cleanup(hg_globals);
#endif
 return(0);
}
