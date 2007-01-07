 /*
 * Nmap wrapper
 *
 * Allows the smart users of nmap to use it
 * through Nessus
 */

#include <includes.h>

/*
 *  Plugin functions
 */

#define EN_NAME "Nmap"
#define FR_NAME "Nmap"

#define EN_DESC "\
This plugin calls the program nmap(1). See\n\
the section 'plugins options' to configure it"

#define FR_DESC "\
Ce plugin appelle le programme nmap(1). Allez voir\n\
la section 'plugins options' pour le configurer"


#define COPYRIGHT "Nmap is copyright (C) Fyodor - <fyodor@dhp.com>"

#define EN_SUMMARY "Performs portscan / rpc scan / os recognition"
#define FR_SUMMARY "Fait un scan de ports / rpc / reconnaissance d'OS"

#define EN_FAMILY "Port scanners"
#define FR_FAMILY "Scanners de ports"


#define TCP_PORTSCAN "TCP scanning technique :"
#define TCP_DFL_300 "connect();SYN scan;FIN scan;Xmas Tree scan;SYN FIN scan;FIN SYN scan;Null scan"
#define TCP_DFL_254 "connect();SYN scan;FIN scan;Xmas Tree scan;Null scan"



#define UDP_PORTSCAN "UDP port scan"
#define UDP_DFL "no"

#define RPC_PORTSCAN "RPC port scan"
#define RPC_DFL "no"

#define PING_HOST "Ping the remote host"
#define PING_HOST_DFL "no"

#define OS_ID "Identify the remote OS"
#define OS_ID_DFL "no"

#define OS_HIDDEN "Use hidden option to identify the remote OS"
#define OS_HIDDEN_DFL "no"

#define FRAG_SCAN "Fragment IP packets (bypasses firewalls)"
#define FRAG_DFL "no"

#define IDENTD_INFO "Get Identd info"
#define IDENTD_DFL "no"

#define PORTRANGE "Port range"
#define PORTRANGE_DFL "User specified range;Default range (nmap-services + privileged ports);Fast scan (nmap-services)"


#define DONT_RANDOMIZE_PORTS "Do not randomize the  order  in  which ports are scanned"
#define DONT_RANDOMIZE_PORTS_DFL "yes"

#define SOURCE_PORT "Source port :"
#define SOURCE_DFL "any"

#define TIMING_POL "Timing policy :"
#define TIMING_DFL "Normal;Insane;Aggressive;Polite;Sneaky;Paranoid;Custom"

#define HOST_TIMEOUT "Host Timeout (ms) :"
#define HOST_DFL ""

#define MINRTT_TIMEOUT "Min RTT Timeout (ms) :"
#define MINRTT_DFL ""

#define MAXRTT_TIMEOUT "Max RTT Timeout (ms) :"
#define MAXRTT_DFL ""

#define INITIAL_RTT_TIMEOUT "Initial RTT timeout (ms)"
#define INITIAL_RTT_DFL ""

#define MAX_THREADS "Ports scanned in parallel (max)"
#define MAX_THREADS_DFL ""
#define MIN_THREADS "Ports scanned in parallel (min)"
#define MIN_THREADS_DFL ""

#define SCAN_DELAY "Minimum wait between probes (ms)"
#define SCAN_DELAY_DFL ""

#define NMAP_FILE "File containing nmap's results : "
#define NMAP_FILE_DFL ""

#define DATA_LENGTH	"Data length : " /* nmap V3 */

#define NMAP "nmap"

static int valid_port_range(char *);
static int	parse_line(struct arglist *, char *);



static pid_t nmap_pid = -1;
static int   num_udp_ports = 0;
static int   found_my_host = 0;


static char * def2portstr()
{
 int num;
 unsigned short * ports = (unsigned short*)getpts("default", &num);
 char * str;
 int i;

  str = emalloc(num * 5 + 1);
  for(i=0;i<num;i++)
  {
    char tmp[40];
    snprintf(tmp, sizeof(tmp), "%d", ports[i]);
    if(str[0] != '\0')
        strcat(str, ",");
    strcat(str, tmp);
  } 
  
  return str;
}



/*
 * That's a *FAKE* progress bar. Its purpose is just
 * to show users that nmap is still alive, not to
 * show the level of completion of a scan
 *
 * This is update "MacOS-style", meaning that 
 * n% of the remaining chart is updated every
 * three seconds
 *
 * Thanks to Michel Arboi for this suggestion 
 *
 * Q: "is not it lame to have a fake progress bar ?"
 * A: "Yes it is. However, nmap offers no convienent way to have a
 *     real progress bar, because of the retries, and users would 
 *     send me panicked emails saying that 'nmap does not work' because
 *     the progress bar was not updated. If you can come up with 
 *     a better solution, let me know"
 *
 * 2002-05-01 [MA]
 * Pavel Kankovsky suggested that we use the debugging option.
 * But I couldn't make it work yet.
 */

#define FAKE_PROGRESS_BAR

static struct arglist * Globals   = NULL;
static struct arglist * Hostinfos = NULL;
#ifdef FAKE_PROGRESS_BAR
static int progress_bar_level 	  = 0;
#else
static int	total_tcp_ports = 0, total_udp_ports = 0;
static int	scanned_tcp_ports = 0, scanned_udp_ports = 0;
#endif

static void
update_progress_bar()
{
#ifdef FAKE_PROGRESS_BAR
  int total = 100000;
  int remaining = total - progress_bar_level;
  int addme = 0;
  addme = (5*100*remaining)/total;
  progress_bar_level += addme;
  comm_send_status(Globals, 
		  arg_get_value(Hostinfos, "NAME"), 
  		  "portscan", 
		  progress_bar_level,
		  total);  
 signal(SIGALRM, update_progress_bar);
 
 /* 
  * Update the alarm time
  */
 alarm((progress_bar_level/(total))+4);
#else
 fprintf(stderr, "T =%d/%d\tU=%d/%d\n", 
	 scanned_tcp_ports, total_tcp_ports,
	 scanned_udp_ports, total_udp_ports);
 comm_send_status(Globals, 
		  arg_get_value(Hostinfos, "NAME"), 
  		  "portscan", 
		  scanned_tcp_ports + scanned_udp_ports,
		  total_tcp_ports + total_udp_ports);  
#endif
}


static int	nmap_V_major = 0, nmap_V_minor = 0;
static int	nmap_V_alpha = 0, nmap_V_beta = 0;

static int
update_nmap_version()
{
  FILE		*fp;
  pid_t		pid;
  char		str[128], *p;
  int		flag = -1, x;
  static char	*args[] = { NMAP, "-V", NULL };

  if ((fp = nessus_popen(NMAP, (const char**)args, &pid)) == NULL)
    return -1;
  
  while (fgets(str, sizeof(str), fp) != NULL)
    {
#define NMAP_V1	"nmap V. "
#define NMAP_V2	"nmap version "
      if ((p = strstr(str, NMAP_V1)) != NULL)
	p += sizeof(NMAP_V1)-1;
      else if ((p = strstr(str, NMAP_V2)) != NULL)
	p += sizeof(NMAP_V2)-1;
      else
	continue;	
      x = sscanf(p, "%d.%dBETA%d",
		 &nmap_V_major, &nmap_V_minor, &nmap_V_beta);
      if (x == 2)		/* did not get the "BETA" string */
	x = sscanf(p, "%d.%dALPHA%d",
		   &nmap_V_major, &nmap_V_minor, &nmap_V_alpha);
      if (x ==2 || x == 3)
	{
	  flag = 0;
	  break;
	}
    }
#if 0
  if (! flag)
    fprintf(stderr, "Nmap version = %d.%d ALPHA%d BETA%d\n",
	    nmap_V_major, nmap_V_minor,
	    nmap_V_alpha, nmap_V_beta);
#endif
  (void) nessus_pclose(fp, pid);
  return flag;
}


static void
kill_nmap 
  (void)
{
  if (nmap_pid == -1)
    return;
  if (kill (nmap_pid, SIGTERM) == -1)
      return ;	     
  kill(nmap_pid, SIGKILL);
}

static void
term_handler(int s)
{
#ifdef FAKE_PROGRESS_BAR
 signal(SIGALRM, SIG_IGN);
 alarm(0);
#endif
 kill_nmap();
#ifdef HAVE__EXIT
 _exit(0);
#else
 exit(0);
#endif
}

static int
check_nmap(pid)
 pid_t pid;
{
 if(pid < 0 || kill(pid, 0) == -1)
  return 1;
 else
   return 0;
}

static FILE*
ptycall_nmap
  (struct arglist *env,
   char   *cmd,
   char **argv,
   pid_t *pid)
{
  FILE *fp;
  
  if ((fp = nessus_popen(cmd, (const char**)argv, pid)) == 0)
    return NULL;

  nmap_pid = *pid;
  atexit (kill_nmap);
  return fp;
}


static int
read_nmap_output(struct arglist * env,
	         FILE * fp,
		 int nmap_pid)
{
 int my_host_found = 0;
 struct in_addr * ip;
 char	ip_expected[20];
 char buf [1024], *s;
 int	num_ports = 0;

 ip = plug_get_host_ip(env);
 snprintf(ip_expected, sizeof(ip_expected), "%s", inet_ntoa(*ip));
 
 for(;;) {
   if ((s = fgets (buf, sizeof (buf) - 1, fp)) == NULL)
     if (ferror(fp))
       {
	 if (errno == EINTR)
	   {
	     clearerr(fp);
	     continue;
	   }
	 perror("fgets");
       }

    if (s != 0)
      {
       if(!strlen(s))s = 0;
       else {
       		if(strstr(s, "Interesting ports"))
		   {
		    if(strstr(s, ip_expected))
		    	{
		    	my_host_found = 1;
			found_my_host ++;
			}
		    else
		    	my_host_found = 0;
		   }
		 else if((!strncmp(s, "All", 3)) && 
		          strstr(s, "scanned ports"))
			  {
			   if(strstr(s, ip_expected))
			   	{
			   	my_host_found = 1;
				found_my_host ++;
				}
			   else
			        my_host_found = 0;
			  }
       		if(my_host_found)
		  num_ports += parse_line (env, s);
      }
     }
     else if(check_nmap(nmap_pid))
      {
       nessus_pclose(fp, nmap_pid);
       return num_ports;
       }
  }
  nessus_pclose(fp, nmap_pid);
  return num_ports;
}		



PlugExport int plugin_init(struct arglist * desc)
{
 if(!is_shell_command_present(NMAP))
	return -1;
 plug_set_id(desc, 10336);
 plug_set_version(desc, "$Revision: 1.102 $");
   
 update_nmap_version();
          
 plug_set_name(desc, FR_NAME, "francais");
 plug_set_name(desc, EN_NAME, NULL);
 
 
 plug_set_summary(desc, FR_SUMMARY, "francais");
 plug_set_summary(desc, EN_SUMMARY, NULL);
 
 
 plug_set_description(desc, FR_DESC, "francais");
 plug_set_description(desc, EN_DESC, NULL);
 
 plug_set_copyright(desc, COPYRIGHT,NULL);
 plug_set_category(desc, ACT_SCANNER);
 plug_set_family(desc, FR_FAMILY, "francais");
 plug_set_family(desc, EN_FAMILY, NULL);
 plug_set_dep(desc, "ping_host.nasl");
 
 /*
  * No timeout for Nmap
  */
  
  
 plug_set_timeout(desc, -1);
 
 
 /*
  * Nmap options
  */
 if (nmap_V_major >= 3 || (nmap_V_major == 2 && nmap_V_minor == 99))
   add_plugin_preference(desc, TCP_PORTSCAN, PREF_RADIO, TCP_DFL_300);
 else
   add_plugin_preference(desc, TCP_PORTSCAN, PREF_RADIO, TCP_DFL_254);

 add_plugin_preference(desc, UDP_PORTSCAN, PREF_CHECKBOX, UDP_DFL);
 add_plugin_preference(desc, RPC_PORTSCAN, PREF_CHECKBOX, RPC_DFL);
 add_plugin_preference(desc, PING_HOST, PREF_CHECKBOX, PING_HOST_DFL);
 add_plugin_preference(desc, OS_ID, PREF_CHECKBOX, OS_ID_DFL);
 add_plugin_preference(desc, OS_HIDDEN, PREF_CHECKBOX, OS_HIDDEN_DFL);
 add_plugin_preference(desc, FRAG_SCAN, PREF_CHECKBOX, FRAG_DFL);
 add_plugin_preference(desc, IDENTD_INFO, PREF_CHECKBOX, IDENTD_DFL);
 add_plugin_preference(desc, PORTRANGE, PREF_RADIO, PORTRANGE_DFL);
 add_plugin_preference(desc, DONT_RANDOMIZE_PORTS, PREF_CHECKBOX, DONT_RANDOMIZE_PORTS_DFL);
 add_plugin_preference(desc, SOURCE_PORT, PREF_ENTRY, SOURCE_DFL);

 add_plugin_preference(desc, DATA_LENGTH, PREF_ENTRY, "");

 if (nmap_V_major >= 3 && (nmap_V_major > 10 ||
			   nmap_V_minor == 10 &&  nmap_V_alpha >= 3))
   add_plugin_preference(desc, MIN_THREADS, PREF_ENTRY, MIN_THREADS_DFL);

 add_plugin_preference(desc, MAX_THREADS, PREF_ENTRY, MAX_THREADS_DFL);

 add_plugin_preference(desc, TIMING_POL, PREF_RADIO, TIMING_DFL);
 add_plugin_preference(desc, HOST_TIMEOUT, PREF_ENTRY, HOST_DFL);
 add_plugin_preference(desc, MINRTT_TIMEOUT, PREF_ENTRY, MINRTT_DFL);
 add_plugin_preference(desc, MAXRTT_TIMEOUT, PREF_ENTRY, MAXRTT_DFL);
 add_plugin_preference(desc, INITIAL_RTT_TIMEOUT, PREF_ENTRY, INITIAL_RTT_DFL);
 add_plugin_preference(desc, SCAN_DELAY, PREF_ENTRY, SCAN_DELAY_DFL);
 add_plugin_preference(desc, NMAP_FILE, PREF_FILE, NMAP_FILE_DFL);
 return(0);
}



static void sigchld_handler(int sig)
{ 
 int status;
 wait(&status);
}

PlugExport int plugin_run(struct arglist * desc)
{
 struct in_addr * ip ;
 char ** argv;
 char * tcp_scan;
 char * timing_pol;
 char * opt;
 char	*t;
 struct arglist * globals = arg_get_value(desc, "globals");
 struct arglist * hostinfos = arg_get_value(desc, "HOSTNAME");
 int udp_scan = 0;
 int raw_scan = 1;
 int nmap_pid = -1;
 int	num_ports = 0, warned = 0;
 FILE * fp = NULL;
 char * fname = get_plugin_preference(desc, NMAP_FILE);
 int	user_spec_ports = -1;
 int	minp = 0, maxp = 0;
 int    custom_policy = 0;
 struct in_addr src_addr;
 
 
 signal(SIGCHLD, sigchld_handler);
 
 if(fname && (fname[0] != '\0'))
 {
  char * local = (char*)get_plugin_preference_fname(desc, fname);
  if(local)
    {
#ifdef DEBUG
      fprintf(stderr, "nmap_wrapper: reading %s [%s]\n", local, fname);
#endif
      if ((fp = fopen(local, "r")) == NULL)
	perror(local);
    }
 }


again:
 if(!fp)
 {
 signal(SIGTERM, term_handler);
 ip = plug_get_host_ip(desc);
 
 if(!valid_port_range(get_preference(desc, "port_range")))
 	return 0;

 argv = append_argv    (0, NMAP);
 argv = append_argv    (argv, "-n");
 
 src_addr = socket_get_next_source_addr();
 if( src_addr.s_addr != INADDR_ANY )
 {
  argv = append_argv(argv, "-S");
  argv = append_argv(argv, estrdup(inet_ntoa(src_addr)));
 }
 
 opt = get_plugin_preference(desc, PING_HOST);
 if(opt !=0 && strcmp(opt, "no") == 0)
  argv = append_argv (argv, "-P0");
 
 opt = get_plugin_preference(desc, PORTRANGE);
 if (opt == NULL || strncmp (opt, "User spec", 9) == 0) 
   {
     char	*pr = get_preference (desc, "port_range");
     int	p1, p2, t = 0;
     char	*p = pr, *q;
  
     if(strcmp(pr, "default") == 0)
     	pr = def2portstr();
     else {
     /* This "parser" is very simple and you may shoot you in the foot */
     while (*p != '\0')
       {
	 q = p;
	 while (isdigit(*q)) 
	   q++;
	 if (*q == ',')
	   {
	     t ++;
	     p = q + 1;
	   }
	 else if (*q == '\0')
	   {
	     t++;
	     break;
	   }
	 else if (*q == '-')
	   {
	     p1 = atoi(p);
	     p = q + 1;
	     p2 = atoi(p);
	     if (p2 >= p1)
	       t += p2 - p1 + 1;
	     while (isdigit(*p)) 
	       p++;
	   }
	 else if(*q == 'T' || *q == 'U')
	   {
	      p = q + 2;
	   }
	 else
	   p = q;		/* Bad format */
       }
#ifndef FAKE_PROGRESS_BAR
     /* TBD: total_udp_ports may be 0 if -sU not set */
     total_udp_ports = total_tcp_ports = t;
#endif
     user_spec_ports = t;
     pr = estrdup(pr);
     }
     argv = append_argv (argv, "-p");
     argv = append_argv (argv, pr);
   }
 else if (strncmp(opt, "Fast", 4) == 0)
   {
     argv = append_argv (argv, "-F");
#ifdef BORING_COMMENTS
     post_note(desc, 0, "\"Fast scan\" set. nmap ignored the user specified port range and scanned only the ports that are declared in nmap-services");
#endif     
     warned = 1;
#ifndef FAKE_PROGRESS_BAR
     /* That's the correct value for nmap 2.54BETA33 */
     total_udp_ports = 986;
     total_tcp_ports = 1102;
#endif
   }
 else
   {
     /* Else nothing ! */
#ifdef BORING_COMMENTS     
     post_note(desc, 0, "\"Default scan\" set. nmap ignored the user specified port range and scanned only the 1024 first ports and those declared in nmap-services");
#endif     
     warned = 1;
#ifndef FAKE_PROGRESS_BAR
     /* That's the correct value for nmap 2.54BETA33 */
     total_udp_ports = 1024 + 435;
     total_tcp_ports = 1024 + 532;
#endif
   }

 /* Read the option */
 opt = get_plugin_preference(desc, UDP_PORTSCAN);
 if(!strcmp(opt, "yes")) {
 	argv = append_argv (argv, "-sU");
 	udp_scan = 1;
	}

 if ((tcp_scan = get_plugin_preference (desc, TCP_PORTSCAN)) != 0) {
   if      (!strcmp (tcp_scan, "connect()")) {
   	opt = "-sT";
	raw_scan = 0;
	}	
	
   else if (!strcmp (tcp_scan, "SYN scan") ||
	    !strcmp (tcp_scan, "SYN FIN scan"))     opt = "-sS";
   else if (!strcmp (tcp_scan, "FIN scan") ||
	    !strcmp (tcp_scan, "FIN SYN scan"))     opt = "-sF";
   else if (!strcmp (tcp_scan, "Null scan")) 	    opt = "-sN";
   
   else if (!strcmp (tcp_scan, "Xmas Tree scan"))   opt = "-sX";
   else    { 
    	     /* default to connect() scan */
   	     opt = "-sT";
	     raw_scan = 0;
	   }
   if (opt != NULL)
     argv = append_argv (argv, opt);

   if (!strcmp(tcp_scan, "SYN FIN scan") || !strcmp(tcp_scan, "FIN SYN scan"))
     {
       /* There is a conflict in nmap 3.00 between -sU and --scanflags
	* so we added -sS when udp_scan was set.
	* Anyway, according to Fyodor, we _must_ use either -sS for
	* "Syn scan" semantics (expect ACK on open ports), or -sF for 
	* "FIN scan" semantics (expect RST on closed ports)
	* That's what I called "SYN FIN" or "FIN SYN"
	*/
       argv = append_argv (argv, "--scanflags");
       argv = append_argv (argv, "SYNFIN");
     }

 }
 
 if ((opt = get_plugin_preference (desc, DATA_LENGTH)) != 0 && *opt != '\0')
   {
     for (t = opt; *t != '\0'; t++)
       if (!isdigit(*t) ) return 0;
     argv = append_argv(argv, "--data_length");
     argv = append_argv(argv, opt);
   }

 if ((opt = get_plugin_preference (desc, MIN_THREADS)) != 0 && *opt != '\0')
   {
     for (t = opt; *t != '\0'; t++)
       if (!isdigit(*t) ) return 0;
     argv = append_argv(argv, "--min_parallelism");
     argv = append_argv(argv, opt);
     sscanf(opt, "%d", &minp);
   }

 if ((opt = get_plugin_preference (desc, MAX_THREADS)) != 0 && *opt != '\0')
   {
     for (t = opt; *t != '\0'; t++)
       if (!isdigit(*t) ) return 0;
     sscanf(opt, "%d", &maxp);
     if (maxp < minp) return 0;	/* Is this wise? */
     argv = append_argv(argv, "--max_parallelism");
     argv = append_argv(argv, opt);
   }


 if ((timing_pol = get_plugin_preference (desc, HOST_TIMEOUT)) != 0
	&& *timing_pol != '\0') 
     {
     	     custom_policy++;
	     for (t = timing_pol; *t != '\0'; t++)
	       if (!isdigit(*t) ) return 0;
	     argv = append_argv(argv, "--host_timeout");
	     argv = append_argv(argv, timing_pol);
     }
     if ((timing_pol = get_plugin_preference (desc, MINRTT_TIMEOUT)) != 0
	&& *timing_pol != '\0')
     {
         custom_policy++;
	 for (t = timing_pol; *t != '\0'; t++)
	     if (!isdigit(*t) ) return 0;
	 argv = append_argv(argv, "--min_rtt_timeout");
	 argv = append_argv(argv, timing_pol);
     }
     if ((timing_pol = get_plugin_preference (desc, MAXRTT_TIMEOUT)) != 0
	&& *timing_pol != '\0')
     {
         custom_policy++;
	 for (t = timing_pol; *t != '\0'; t++)
	     if (!isdigit(*t) ) return 0;
	 argv = append_argv(argv, "--max_rtt_timeout");
	 argv = append_argv(argv, timing_pol);
     }
     if ((timing_pol = get_plugin_preference (desc, INITIAL_RTT_TIMEOUT)) != 0
	&& *timing_pol != '\0')
     {
         custom_policy++;
	 for (t = timing_pol; *t != '\0'; t++)
	     if (!isdigit(*t) ) return 0;
	 argv = append_argv(argv, "--initial_rtt_timeout");
	 argv = append_argv(argv, timing_pol);
     }
     if ((timing_pol = get_plugin_preference (desc, SCAN_DELAY)) != 0
	&& *timing_pol != '\0')
     {
         custom_policy++;
	 for (t = timing_pol; *t != '\0'; t++)
	     if (!isdigit(*t) ) return 0;
	 argv = append_argv(argv, "--scan_delay");
	 argv = append_argv(argv, timing_pol);
     }
     
     
 /* Timing policy */
 if( custom_policy ==  0)
 {
  if ((timing_pol = get_plugin_preference (desc, TIMING_POL)) != 0) {
    /* Handle a custom timing policy */
  if (strcmp(timing_pol, "Custom") == 0) {
     if(custom_policy == 0)
     {
      /* do nothing */
      /*
       * XXX we should check if custom_policy == 0 and issue an alert
       * in that case
       */
     }
  }
    /* Think that this was wrong in the original patch */
  else if (strcmp (timing_pol, "Normal") != 0) {
    argv = append_argv(argv, "-T");
    argv = append_argv(argv, timing_pol);
   }
  }
   /* else default to normal timing */
 }
 
 opt = get_plugin_preference(desc, RPC_PORTSCAN);
 if(!strcmp(opt, "yes")) argv = append_argv (argv, "-sR");

 opt = get_plugin_preference(desc, OS_ID);
 if(!strcmp(opt, "yes")) argv = append_argv (argv, "-O");

 opt = get_plugin_preference(desc, OS_HIDDEN);
 if(!strcmp(opt, "yes")) argv = append_argv (argv, "--osscan_guess");
  
 if(raw_scan)
 {
 opt = get_plugin_preference(desc, FRAG_SCAN);
 if(!strcmp(opt, "yes")) argv = append_argv (argv, "-f");
 }
 
 opt = get_plugin_preference(desc, IDENTD_INFO);
 if(!strcmp(opt, "yes")) argv = append_argv (argv, "-I");
 
 opt = get_plugin_preference(desc, DONT_RANDOMIZE_PORTS);
 if(!strcmp(opt, "yes")) argv = append_argv(argv, "-r");
 
 opt = get_plugin_preference(desc, SOURCE_PORT);
 if(opt && raw_scan)
 {
  if(strcmp(opt, "any") && atoi(opt) && valid_port_range(opt))
  {
   argv = append_argv(argv, "-g");
   argv = append_argv(argv, opt);
  }
 }
#ifndef FAKE_PROGRESS_BAR
 argv = append_argv(argv, "-d");
 argv = append_argv(argv, "-d");
#endif
 argv = append_argv (argv, inet_ntoa (*ip));
  
#ifdef BORING_COMMENTS
 if (! warned && user_spec_ports >= 0)
   {
     char	msg[256];

     msg[0] = '\0';
     if (user_spec_ports < 65535)
       {
	 snprintf(msg, sizeof(msg), "Nmap scanned only the user specified range, i.e. %d ports out of 65535. ", user_spec_ports);
       }
     if (! udp_scan)
       strcat(msg, "UDP scan was not enabled.");   
     if (msg[0] != '\0')
       post_note(desc, 0, msg);
     warned = 1;
   }
#endif   

 comm_send_status(globals, arg_get_value(hostinfos, "NAME"),"portscan",  0,100);
 num_udp_ports = 0;
 
 Globals = globals;
 Hostinfos = hostinfos;
 
#ifdef FAKE_PROGRESS_BAR
 signal(SIGALRM, update_progress_bar);
 alarm(1);
#endif
 fp = ptycall_nmap (desc, NMAP, argv, &nmap_pid);
#ifdef FAKE_PROGRESS_BAR
 signal(SIGALRM, SIG_IGN);
 alarm(0);
#endif
 destroy_argv (argv);
 }

 if(!fp)
	return 0;

 num_ports = read_nmap_output(desc, fp, nmap_pid);
 if((nmap_pid < 0) && 
    !(found_my_host)){
   	/*
	 * Our host is not present in the list -> we start nmap
	 */
    	fp = NULL;
	goto again;
 	}
 comm_send_status(globals, arg_get_value(hostinfos, "NAME"),"portscan",  100,100);
 plug_set_key (desc, "Host/scanned", ARG_STRING, "1");
 if(num_udp_ports)plug_set_key (desc, "Host/udp_scanned", ARG_STRING, "1");

#ifdef BORING_COMMENTS
 if (! warned && num_ports < 2 * 65535)
   {
     char	str[128];
     if(udp_scan || (fname != NULL && num_udp_ports > 0))
     	snprintf(str, sizeof(str), "Nmap only scanned %d UDP & TCP ports out of 131070", num_ports);
     else 
       {
	 *str = '\0';
	 if (num_ports < 65535)
	   snprintf(str, sizeof(str), "Nmap only scanned %d TCP ports out of 65535.",
		   num_ports);
	 strcat(str, "\nNmap did not do a UDP scan, I guess.");
       }
     post_note(desc, 0, str);
   }
#endif   

 return 0;
}

/*
 * Send the result of the scans to nessusd
 */  
static int 
parse_line(env, line)
   struct arglist * env;
   char * line;
{
  char * protocol;
  char * t;
  int num;
  int		ret = 0;

  if(!strlen(line))
    return 0;
  
  
  /*--------------------------------------------------------------------
  
  			         Host down
			
   --------------------------------------------------------------------*/
   
   if(strstr(line, " (0 hosts up) "))
   {
    plug_set_key(env, "Host/ping_failed", ARG_STRING, "yes");
    return 0;
   }			 
  
   if (strstr(line, "ports scanned but not shown below are in state"))
     {
       num = atoi(line + 5);
       return num;
     }

#ifndef FAKE_PROGRESS_BAR
   if (strstr(line, "Adding closed port") || strstr(line, "Adding open port")
       || strstr(line, "Adding filtered port") )
     {
       char	*p = strchr(line, '/');
       if (strncmp(p, "/tcp", 4) == 0)
	 scanned_tcp_ports ++;
       else if (strncmp(p, "/udp", 4) == 0)
	 scanned_udp_ports ++;
       update_progress_bar();
       return 0;
     }
#endif

  /*--------------------------------------------------------------------
                                                                      
   			  Operating system guess                        
   							                
   --------------------------------------------------------------------*/
  if((!strncmp(line, "Remote ",
  			strlen( "Remote "))
	&& (strstr(line, "OS guess") || strstr(line, "operating system"))) 
	
     ||
     
     (strncmp(line, "OS ", strlen("OS ")) == 0 &&
       strstr(line, "details") != NULL))
     	
  {
   char * report = malloc(strlen(line)+255);
   t = strchr(line, ':');
   if(!t)return;
   line = t+(sizeof(char)*2);
   line[strlen(line)-1]='\0';
   plug_set_key(env, "Host/OS", ARG_STRING, line);
   snprintf(report, strlen(line) + 255, "Nmap found that this host is running %s\n",
   			line);
   proto_post_note(env, 0, "tcp", report);
   return 0;
  }
   
   
  /*--------------------------------------------------------------------
                                                                       
    			  TCP Sequence                                  
  							                
   --------------------------------------------------------------------*/ 
  if(!strncmp(line, "TCP Sequence Prediction",
  		strlen("TCP Sequence Prediction")))
  {
   char * s = strstr(line, "Class=");
   if(!s)return; /* ?? */
   s = strchr(s, '=');
   s[strlen(s)-1]='\0';
   s+=sizeof(char);
   /* s = <class> */
   
   /*
    * Constant 
    */
   if(!strcmp(s, "constant sequence number (!!)"))
   {
    char * report = "The TCP sequence numbers of the remote host are\n\
constant ! A cracker may use this flaw to spoof TCP connections\n\
easily.\n\n\
Solution : contact your vendor for a patch\n\
Risk factor : High";

	post_hole(env, 0, report);
	plug_set_key(env, "Host/tcp_seq", ARG_STRING, "constant");
	return 0;
    }
    
    /*
     * 64K rule
     */
    if(!strcmp(s, "64K rule"))
    {
     char * report = "The TCP sequence numbers of the remote host are\n\
always incremented by 64000, so they can be\n\
guessed rather easily. A cracker may use\n\
this flaw to spoof TCP connections easily.\n\n\
Solution : contact your vendor for a patch\n\
Risk factor : High";
	post_hole(env, 0, report);
	plug_set_key(env, "Host/tcp_seq", ARG_STRING, "64000");
	return 0;
    }
    
    /*
     * i800 rule
     */
    if(!strcmp(s,"increments by 800"))
    {
     char * report = "The TCP sequence numbers of the remote host are\n\
always incremented by 800, so they can be\n\
guessed rather easily. A cracker may use\n\
this flaw to spoof TCP connections easily.\n\n\
Solution : contact your vendor for a patch\n\
Risk factor : High";
	post_hole(env, 0, report);
	plug_set_key(env, "Host/tcp_seq", ARG_STRING, "800");
	return 0;
    }
    
    /*
     * Windows rule :)
     */
    if(!strcmp(s,"trivial time dependency"))
    {
     char * report = "The TCP sequence numbers of the remote host\n\
depends on the time, so they can be\n\
guessed rather easily. A cracker may use\n\
this flaw to spoof TCP connections easily.\n\n\
Solution : http://www.microsoft.com/technet/security/bulletin/ms99-046.asp\n\
Risk factor : High";
	post_hole(env, 0, report);
	plug_set_key(env, "Host/tcp_seq", ARG_STRING, "time");
	return 0;
    }
    /*
     * Ignore the rest
     */
     plug_set_key(env, "Host/tcp_seq", ARG_STRING, "random");
     return 0;
  }

  /*--------------------------------------------------------------------

                               Closed/filtered port

   --------------------------------------------------------------------*/

  if((strstr(line, "/tcp") || strstr(line, "/udp")) &&
     (strstr(line, "closed  ") || strstr(line, "filtered  ")))
    return 1;
  
  /*--------------------------------------------------------------------
                                                                   
                               Open port                           
                                                                   
   --------------------------------------------------------------------*/	
  if(!strstr(line, "open "))
    return 0;
  t = strchr(line, ' ');
  if (t == NULL)
    return 0;
  t[0] = 0;
  num = atoi(line);
  if(!num)
    return 0;
  if(strchr(line, '/'))
  {
   char * f = strchr(line, '/');
   protocol = f+sizeof(char);
   t = t+sizeof(char);
   /* 
    * t now points on "   open    "
    */
    while((t[0]==' ')||(t[0]=='\t'))t+=sizeof(char);
    t = strchr(t, ' ');
    while((t[0]==' ')||(t[0]=='\t'))t+=sizeof(char);
  }
  else
  {
  line = t+sizeof(char);
  while(line[0]==' ' && line[0])line+=sizeof(char);
  if(!line[0])
    return 0;
  line = strchr(line, ' ');
  if (line == NULL)
    return 0;
  while(line[0]==' ' && line[0])line+=sizeof(char);
  if(!line[0])
    return 0;
  t = strchr(line, ' ');
  if (t == NULL)
    return 0;
  t[0] = 0;
  t+=sizeof(char);
  protocol = line;
  while((t[0]==' ')||(t[0]=='\t'))t+=sizeof(char);
  }
  if(strcmp(protocol, "tcp")&&strcmp(protocol, "udp"))
    return 0;
  if(!strcmp(protocol, "udp"))num_udp_ports++;
  scanner_add_port(env, num, protocol);
  ret ++;
  
  
  /*
   * t now points on the service
   */
   
  /*
   * RPC service running on port
   */
  if(strchr(t, '('))
  {
   char * s = strchr(t, '(');
   char * e = strchr(t, ')');
   /*
    * There is a RPC service over here 
    */
   if(s && e)
   {
    char * report;
    s+=sizeof(char);
    e[0]=0;
    report = malloc(strlen(s)+1024);
    sprintf(report, "The RPC service %s is running on this port\n\
If you do not use it, disable it, as it is\n\
a potential security risk", s);
    proto_post_info(env, num, protocol, report);
    free(report);
    t = e+sizeof(char);
   }
  }
   
   /*
    * Owner of the service
    */
  
   t = strchr(t, ' ');
   if(t && !strcmp(protocol, "tcp"))
   {
    while(t[0]==' ' && t[0])t+=sizeof(char);
    if(isalnum(t[0]))
    {
     char* report = malloc(255+strlen(t));
     /* t = <username> */
     
     sprintf(report, "This service is owned by user %s", t);
     proto_post_note(env, num, protocol, report);
     free(report);
    }
  }
   return ret;
}


/* We should also test duplicate ports, because of a bug in some 
 * Nmap versions  (infinite loop after the error message) */

static int valid_port_range(char * r)
{ 
 if(strcmp(r, "default") == 0)
 	return 1;
	
 if(!r[0])return 1;
 else
  if(!isdigit(r[0]) && 
        (r[0]!='-') && 
	(r[0]!=',') && 
	(r[0]!= 'T') &&
	(r[0]!= 'U') &&
	(r[0]!= ':'))return 0;
  else return valid_port_range(++r);
 }
