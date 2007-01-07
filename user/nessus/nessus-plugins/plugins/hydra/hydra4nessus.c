/*
 * Hydra4Nessus
 *
 * This plugin makes hydra run as a Nessus plugin.
 * Originally developed by Renaud Deraison for Hydra 1.7
 * Additional changes by Javier Fernandez-Sanguino for Hydra 2.2
 * (add REXEC, LDAP and CISCO_ENABLE
 *
 * Hydra is (c) Van Hauser and can be downloaded from 
 * http://www.thehackerschoice.com
 * Is distributed under a modified GNU GPL 2.0 license 
 * (read LICENSE.GNU and LICENCE.Hydra)
 *
 *  This "glue" plugin is 
 *  (c) 2002 Renaud Deraison
 *  (c) 2003 Javier Fernandez-Sanguino
 *
 *  and is distributed under the GNU GPL license
 */
 

#include <includes.h>


#define NAME "Brute force login (Hydra)"

#define DESC "\
This plugin checks for common login/password\n\
combinations on various protocols\n\n\
Risk factor : High\n\
Solution : Use strong passwords\n"


#define COPY "(c) Van Hauser / Nessus port by rd"

#define SUMM "Accounts brute force"


#define FR_FAMILY "Divers"
#define FAMILY "Misc."

/*
 * Preferences
 */

#define PREFS_NUM_TASKS "Number of simultaneous connections : "
#define PREFS_NUM_TASKS_DFL "4"

#define PREFS_LOGIN_FILE "Logins file : "
#define PREFS_PASS_FILE "Passwords file : "

#define PRFS_TELNET "Brute force telnet"
#define PRFS_FTP "Brute force FTP"
#define PRFS_POP3 "Brute force POP3"
#define PRFS_IMAP "Brute force IMAP"
#define PRFS_CISCO "Brute force cisco"
#define PRFS_CISCO_ENABLE "Brute force cisco-enable"
#define PRFS_VNC "Brute force VNC"
#define PRFS_SOCKS5 "Brute force SOCKS 5"
#define PRFS_REXEC "Brute force rexec"
#define PRFS_NNTP "Brute force NNTP"
#define PRFS_HTTP "Brute force HTTP"
#define PRFS_ICQ "Brute force ICQ"
#define PRFS_PCNFS "Brute force PCNFS"
#define PRFS_SMB "Brute force SMB"
#define PRFS_LDAP "Brute force LDAP"


#define PRFS_HTTP_PAGE "Web page to brute force : "



extern int hydra_main(int soc, struct arglist * nessus, int argc, char **argv);
struct arglist * HydraDesc;

/*
 * Returns a name suitable for a temporary file. 
 * This function ensures that this name is not taken
 * already.
 */
static char*
temp_file_name(orig)
 char * orig;
{
 char* ret;
 int fd = - 1;
 char * prefix = strrchr(orig, '/');
 
 if(!prefix)orig = "/tmp/";
 else {
  prefix[0] = '\0';
 }
 
 ret = emalloc(strlen(orig)+strlen("tmp") + 40);
 
 
 do {
 if(fd > 0){
 	if(close(fd) < 0)
	 perror("close ");
	}
 sprintf(ret, "%s/tmp.%d-%d", orig, getpid(), rand()%1024);
 fd = open(ret, O_RDONLY);
 } 
  while (fd >= 0);
  
 
 if(prefix)prefix[0] = '/'; 
 return ret;
}


/*
 * mk_login_file ()
 * Creates a file which includes all login information derived
 * from the Nessus knowledge-base.
 *
 * NOTE: It currently only uses information derived from 
 * SMB checks. It should be improved by using other plugins
 * which check for users (for example the 'finger' plugins)
 */
static char *
mk_login_file(desc, orig)
 struct arglist * desc;
 char * orig;
{
 int i = 1;
 char buf[255];
 char * name = temp_file_name(orig);
 FILE * f = fopen(name, "w+");
 
 sprintf(buf, "SMB/Users/%d", i);
 name = plug_get_key(desc, buf);
 while(name)
 {
  fprintf(f, "%s\n", name);
  sprintf(buf, "SMB/Users/%d", ++i);
  name = plug_get_key(desc, buf);
 }
 
 i = 1;
 sprintf(buf, "SMB/LocalUsers/%d", i);
 name = plug_get_key(desc, buf);
 while(name)
 {
 fprintf(f, "%s\n", name);
 sprintf(buf, "SMB/LocalUsers/%d", ++i);
 name = plug_get_key(desc, buf);
 }
 
 fclose(f);
 return name;
}

static int 
process_alive(pid)
 pid_t pid;
{
 int i, ret;
 if(!pid) 
  return 0;
 
 for(i=0,ret=1;(i<100) && (ret > 0);i++)
   ret = waitpid(pid, NULL, WNOHANG);
   
   
 return kill(pid, 0) == 0;
}




struct jobs {
	pid_t pid;
	int soc;
	FILE * fsoc;
	struct jobs * next;
};


static void 
sighand_term(x)
 int x;
{
 kill(-getpgrp(), SIGTERM);
 _exit(0);
}

static void 
sighand_chld(x)
 int x;
{
  int status = 0;
  wait(&status);
}
static struct jobs * 
add_job(jobs, pid, soc) 
 struct jobs * jobs;
 pid_t pid;
 int soc;
{
 struct jobs * r = emalloc(sizeof(*r));
 r->pid = pid;
 r->soc = soc;
 r->fsoc = fdopen(soc, "r+");
 r->next = jobs;
 return r;
}


static int 
jobs_running(jobs)
 struct jobs * jobs;
{
 int ret = 0;
 while(jobs)
 {
 if( (jobs->pid > 0) )
 {
     if(process_alive(jobs->pid))ret ++;
     else jobs->pid = -1;
 }
 jobs = jobs->next;
 }
 return ret;
}


static int
jobs_fill_fdset(jobs, rd)
 struct jobs * jobs;
 fd_set *rd;
{ 
 int max = 0;
 FD_ZERO(rd);
 while(jobs)
 {
  if(jobs->pid > 0)
  {
   FD_SET(jobs->soc, rd);
   if(jobs->soc > max)max = jobs->soc;
  }
  jobs = jobs->next;
 }
 return max;
}

static int
jobs_select(rd, max)
 fd_set * rd;
 int max;
{
 struct timeval tv = {0, 30000};
 return select(max + 1, rd, NULL, NULL, &tv);
}

static int 
jobs_dispatch_input(desc, jobs, rd)
 struct arglist * desc;
 struct jobs* jobs;
 fd_set * rd;
{
 while(jobs)
 {
  if(jobs->pid > 0)
  {
   if(FD_ISSET(jobs->soc, rd))
   {
    char buf[2048];
    char * t;
    int port;
    char*svc_name;
    char * report;
    
    fgets(buf, sizeof(buf) - 1, jobs->fsoc);
    t = strchr(buf, '[');
    if(!t)goto nxt;
    t++;
    port = atoi(t);
    t = strchr(t, '[');
    if(!t)goto nxt;
    svc_name = &(t[1]);
    t = strchr(t, ']');
    if(!t)goto nxt;
    t[0] = '\0';
    svc_name = estrdup(svc_name);
    t[0] = ']';
    t = t+1;
    
    report = emalloc(strlen(svc_name) + strlen(t) + 255);
    sprintf(report, "A valid %s account has been found by brute force :\n%s\n\n\
Solution: Use strong passwords and difficult to guess usernames\n\
Risk factor : High",
		svc_name, t);
    efree(&svc_name);
    post_hole(desc, port, report);		    
    efree(&report);
   }
  }
nxt:
  jobs = jobs->next;
 }
 return 0;
}


int 
plugin_init(desc)
 struct arglist * desc;
{
 plug_set_id(desc, 10909); 
 plug_set_version(desc, "$Revision: 1.16 $");
 
 plug_set_cve_id(desc, "CAN-1999-0502");
 plug_set_cve_id(desc, "CAN-1999-0505");
 plug_set_cve_id(desc, "CAN-1999-0516");
 plug_set_cve_id(desc, "CAN-1999-0518");
 
 plug_set_name(desc, NAME, NULL);
 
 plug_set_description(desc, DESC, NULL);
 plug_set_summary(desc, SUMM, NULL);
 
 plug_set_copyright(desc, COPY, NULL);
 
 plug_set_family(desc, FR_FAMILY, "francais");
 plug_set_family(desc, FAMILY, NULL);
 
 plug_set_category(desc, ACT_ATTACK);
 plug_set_timeout(desc, -1);
 
 add_plugin_preference(desc, PREFS_NUM_TASKS, PREF_ENTRY, PREFS_NUM_TASKS_DFL);
 add_plugin_preference(desc, PREFS_LOGIN_FILE, PREF_FILE, "");
 add_plugin_preference(desc, PREFS_PASS_FILE, PREF_FILE, ""); 
 
 add_plugin_preference(desc, PRFS_TELNET, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_FTP, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_POP3, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_IMAP, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_CISCO, PREF_CHECKBOX, "no"); 
 add_plugin_preference(desc, PRFS_CISCO_ENABLE, PREF_CHECKBOX, "no"); 
 add_plugin_preference(desc, PRFS_VNC, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_SOCKS5, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_REXEC, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_NNTP, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_HTTP, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_HTTP_PAGE, PREF_ENTRY, "");
 add_plugin_preference(desc, PRFS_ICQ, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_PCNFS, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_SMB, PREF_CHECKBOX, "no");
 add_plugin_preference(desc, PRFS_LDAP, PREF_CHECKBOX, "no");
 
 plug_set_dep(desc, "find_service.nes");
 plug_set_dep(desc, "netbios_name_get.nasl");
 return 0;
}


static struct jobs * 
launch_hydra(jobs, desc, name, argc, argv)
 struct jobs * jobs;
 struct arglist * desc;
 char * name;
 int argc;
 char ** argv;
{
  pid_t pid;
  int soc[2];
  char * page = NULL;
  
  if(!strcmp(name, "www"))
  {
   page = get_plugin_preference(desc, PRFS_HTTP_PAGE);
   if(!page || !(page[0]) || !(page[0] == '/'))
   {
    char *report="Could not do HTTP brute force as no valid start page\n\
was given in option";
    post_note(desc, 80, report);
    return jobs;
   }
  }
  
  
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, soc) < 0)
   {
    perror("socketpair ");
    return jobs;
   }
   
      if(!(pid = fork()))
      {
       int devnull = open("/dev/null", O_RDWR);
       close(2); /* close stderr */
       close(1); /* close stdout */
       dup2(devnull, 2);
       dup2(devnull, 1);
       signal(SIGTERM, exit);
       argv = append_argv(argv, name);
	
        if(page){
		argv = append_argv(argv, page);
		argc++;
		}
	
	
	hydra_main(soc[1], desc, argc, argv);  
	
	exit(0);
      }
      else 
      {
	if(pid < 0)
	{
	  perror("hydra4nessus: fork() ");
	}
	else
         jobs = add_job(jobs, pid, soc[0]);
      }
    return jobs;
}

int 
plugin_run(desc)
 struct arglist * desc;
{
 char ** argv;
 int argc = 0;
 char * login = get_plugin_preference(desc, PREFS_LOGIN_FILE);
 char * pass  = get_plugin_preference(desc, PREFS_PASS_FILE);
 char * host;
 struct in_addr * addr;
 struct jobs * jobs = NULL;
 char * str;
 char * tasks = get_plugin_preference(desc, PREFS_NUM_TASKS);
 int created_file = 0;
 
 HydraDesc = desc;
 
 setpgid(0, 0);
 argv = append_argv(NULL, "Hydra");argc++;
 argv = append_argv(argv, "bogus");argc++;
 
 
 /* Note: the plugin should be capable of extracting the location of servers
  * from Nessus' knowledgebase  using the -S switch otherwise standard
  * server ports will be used (jfs) */
 
 
 if(!(pass  && pass[0]))
    	return -1;

 /* This CLI argument is useful to avoid having login or password files full of entries
  * with the same information in login and password info (jfs) */
 argv = append_argv(argv, "-e");argc++;
 argv = append_argv(argv, "ns");argc++;
 
 pass = (char*)get_plugin_preference_fname(desc, pass);
 if(!login || !login[0])
 {
  login = mk_login_file(desc, pass);
  created_file = 1;
 }
 else 
  login = (char*)get_plugin_preference_fname(desc, login);
  
 argv = append_argv(argv, "-L");argc++;
 argv = append_argv(argv, login);argc++;
 
 argv = append_argv(argv, "-P");argc++;
 argv = append_argv(argv, pass);argc++;
 
 
 if(!tasks)tasks = "4";
 argv = append_argv(argv, "-t");argc++;
 argv = append_argv(argv, tasks);argc++;
 
 addr = plug_get_host_ip(desc);argc++;
 if(!addr)
  return -1;
 host = estrdup(inet_ntoa(*addr));
 argv = append_argv(argv, host);argc++;
 
 signal(SIGCHLD, sighand_chld);
 signal(SIGTERM, sighand_term);
 

  if((str = get_plugin_preference(desc, PRFS_TELNET)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "telnet", argc, argv);
     
   if((str = get_plugin_preference(desc, PRFS_FTP)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "ftp", argc, argv);  
   
  if((str = get_plugin_preference(desc, PRFS_POP3)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "pop3", argc, argv);
 
  if((str = get_plugin_preference(desc, PRFS_IMAP)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "imap", argc, argv);
     
  if((str = get_plugin_preference(desc, PRFS_CISCO)) &&
   	 !strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "cisco", argc, argv);   
  
  if((str = get_plugin_preference(desc, PRFS_CISCO_ENABLE)) &&
   	 !strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "cisco-enable", argc, argv);   
     
  if((str = get_plugin_preference(desc, PRFS_VNC)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "vnc", argc, argv);
     
   if((str = get_plugin_preference(desc, PRFS_SOCKS5)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "socks5", argc, argv);     
     
   if((str = get_plugin_preference(desc, PRFS_NNTP)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "nntp", argc, argv);  
     
   if((str = get_plugin_preference(desc, PRFS_HTTP)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "www", argc, argv);  
     
     if((str = get_plugin_preference(desc, PRFS_ICQ)) &&
   	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "icq", argc, argv);  
     
    if((str = get_plugin_preference(desc, PRFS_PCNFS)) &&
 	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "pcnfs", argc, argv);   
        
    if((str = get_plugin_preference(desc, PRFS_SMB)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "smb", argc, argv);  
     
    if((str = get_plugin_preference(desc, PRFS_LDAP)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "ldap", argc, argv);  
     	
    if((str = get_plugin_preference(desc, PRFS_REXEC)) &&
    	!strcmp(str, "yes"))
     jobs = launch_hydra(jobs, desc, "rexec", argc, argv);  

 while(jobs_running(jobs) > 0)
 {
  fd_set rd;
  int max = jobs_fill_fdset(jobs, &rd);
  if(jobs_select(&rd, max) > 0)
   jobs_dispatch_input(desc, jobs, &rd);
 }
  
 if(created_file)unlink(login);
 efree(&host);
 return 0;
}
