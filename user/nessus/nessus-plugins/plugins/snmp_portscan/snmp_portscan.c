/*
 * snmpwalk wrapper
 *
 * Finds open ports by walking through the TCP and UDP MIB
 */

#include <includes.h>
#define SNMPWALK "snmpwalk"


pid_t		snmpwalk_process;


/*
 *  Plugin functions
 */

#define EN_NAME "SNMP port scan"
#define FR_NAME "Scan de ports SNMP"

#define EN_DESC "\
This plugin runs snmpwalk(1) on the TCP and UDP MIB.\n\
See the section 'plugins options' to configure it"

#define FR_DESC "\
Ce plugin appelle snmpwalk(1) sur les MIB TCP et UDP.\n\
Allez voir la section 'plugins options' pour le configurer"


#define COPYRIGHT "This script is copyright (C) Michel Arboi - <arboi@algoriel.fr>"

#define EN_SUMMARY "Find open ports through snmpwalk"
#define FR_SUMMARY "Trouve les ports ouverts à l'aide de snmpwalk"

#define EN_FAMILY "Port scanners"
#define FR_FAMILY "Scanners de ports"


#define SNMP_COMMUNITY "Community name :"
#define SNMP_COMMUNITY_DFL "public"

#define SNMP_VERSION "SNMP protocol :"
#define SNMP_VERSION_DFL "1;2c"

#define SNMP_LAYER "SNMP transport layer :"
#define SNMP_LAYER_DFL "udp;tcp"

#define SNMP_PORT "TCP/UDP port :"
#define SNMP_PORT_DFL ""

#define SNMP_RETRIES "Number of retries :"
#define SNMP_RETRIES_DFL ""

#define SNMP_TIMEOUT "Timeout between retries :"
#define SNMP_TIMEOUT_DFL ""


PlugExport int plugin_init(desc)
     struct arglist	*desc;
{
  if(!is_shell_command_present(SNMPWALK))
    	return -1;

  plug_set_id(desc, 10841);
  plug_set_version(desc, "$Revision: 1.17 $");
   
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
 
  plug_set_timeout(desc, 60);
  add_plugin_preference(desc, SNMP_COMMUNITY, PREF_ENTRY, SNMP_COMMUNITY_DFL);
  add_plugin_preference(desc, SNMP_VERSION, PREF_RADIO, SNMP_VERSION_DFL);
  add_plugin_preference(desc, SNMP_LAYER, PREF_RADIO, SNMP_LAYER_DFL);
  add_plugin_preference(desc, SNMP_PORT, PREF_ENTRY, SNMP_PORT_DFL);
  add_plugin_preference(desc, SNMP_RETRIES, PREF_ENTRY, SNMP_RETRIES_DFL);
  add_plugin_preference(desc, SNMP_TIMEOUT, PREF_ENTRY, SNMP_TIMEOUT_DFL);
  return(0);
}


#define BFLAGS	(sizeof(int) * 8)

static int
read_snmpwalk_output(desc, fp, flags)
     struct arglist	*desc;
     FILE		*fp;
     int		*flags;
{
  int	count = 0, n;
  char	s[256], *p;

  while ((fgets(s, sizeof(s), fp)) != NULL)
    {
      if ((p = strrchr(s, '=')) != NULL)
	{
#ifdef DEBUG_SNMPWALK_OUTPUT
	  fprintf(stderr, "P> %s\n", p);
#endif
	  /* skip white space and other stupid strings, e.g. "INTEGER:" */
	  while (*p != '\0' && ! isdigit(*p)) p ++;
	  n = atoi(p);
	  if (n > 0)
	    flags[n / BFLAGS] |= (1 << (n % BFLAGS));
	}
    }
  return count;
}

static int	v506 = 0;

static int	layer_udp = 0;

static char**
make_argv(desc, arg1, flag2, snmp_comm_p, snmp_port_p)
     struct arglist	*desc;
     const char		*arg1;
     int		flag2;	/* Not really a flag any more */
     char		**snmp_comm_p;
     int		*snmp_port_p;
{
  char			**argv, *p, s[256], ip_str[16], *opt;
  int			x;
  struct in_addr	*ip;


  ip = plug_get_host_ip(desc);
  strcpy(ip_str, inet_ntoa(*ip));

  opt = strrchr(SNMPWALK, '/');
  if (opt)
    ++ opt ;
  else
    opt = SNMPWALK;
 
  argv = append_argv(0, opt);

  p = get_plugin_preference(desc, SNMP_VERSION);
  if (p != NULL)
    {
      argv = append_argv(argv, "-v");
      argv = append_argv(argv, p);
    }

  p = get_plugin_preference(desc, SNMP_LAYER);
  if (p != NULL && ! v506)
    {
      argv = append_argv(argv, "-T");
      argv = append_argv(argv, p);
      if (strcasecmp(p, "udp") == 0)
	layer_udp = 1;
    }
      
  p = get_plugin_preference(desc, SNMP_RETRIES);
  if (p != NULL && (x = atoi(p)) > 0)
    {
      snprintf(s, sizeof(s), "%d", x);	/* safer */
      argv = append_argv(argv, "-r");
      argv = append_argv(argv, s);
    }

  p = get_plugin_preference(desc, SNMP_TIMEOUT);
  if (p != NULL && (x = atoi(p)) > 0)
    {
      snprintf(s, sizeof(s), "%d", x);	/* safer */
      argv = append_argv(argv, "-t");
      argv = append_argv(argv, s);
    }

  p = get_plugin_preference(desc, SNMP_PORT);
  if (p != NULL && (x = atoi(p)) > 0)
    {
      snprintf(s, sizeof(s), "%d", x);	/* safer */
      argv = append_argv(argv, "-p");
      argv = append_argv(argv, s);
      *snmp_port_p = x;
    }

  if (! v506)
    argv = append_argv(argv, ip_str);

  p = get_plugin_preference(desc, SNMP_COMMUNITY);
  if (p == NULL || p[0] == '\0')
    p = "public";	/* Most likely... */
  *snmp_comm_p = p;
  if (v506)
    argv = append_argv(argv, "-c");
  argv = append_argv(argv, p);

  /* Version 5.0.6: put the hostname *after* the options */
  if (v506)
     argv = append_argv(argv, ip_str);

  switch (flag2)
    {
    case 1:
      snprintf(s, sizeof(s), "%s.%s", arg1, ip_str); break;
    case 0:
      snprintf(s, sizeof(s), "%s.0.0.0.0", arg1); break;
    case 2:
      strncpy(s, arg1, sizeof(s) - 1); s[sizeof(s) - 1] = '\0';  break;
    default:
      fprintf(stderr, "Unknown flag value %d\n", flag2); break;
    }

  argv = append_argv(argv, s);

  return argv;
}

static void chld_handler(int sig)
{
	int status = 0;
	wait(&status);
}

static void term_handler(int sig)
{
	kill(snmpwalk_process, SIGKILL);
}

#define TCP_TRUC	"tcp.tcpConnTable.tcpConnEntry.tcpConnLocalPort"
#define UDP_TRUC	"udp.udpTable.udpEntry.udpLocalPort"
#define WIN_INST_SOFT	"host.hrSWInstalled.hrSWInstalledTable.hrSWInstalledEntry.hrSWInstalledName"

PlugExport int plugin_run(desc)
     struct arglist	*desc;
{
  struct arglist * globals = arg_get_value(desc, "globals");
  struct arglist * hostinfos = arg_get_value(desc, "HOSTNAME");
  FILE	*fp = NULL;
  char	**argv;
  int	open_ports[65536 / BFLAGS], i, num_tcp_ports, num_udp_ports;
  char		*snmp_comm;
  int		snmp_port = 161; /* default */
#ifdef WIN_INST_SOFT
  char		s[512], *p, *q, *msg = NULL;
  int		patch_nb = 0, msg_len = 0, l;
#endif
  
  signal(SIGCHLD, chld_handler);
  signal(SIGTERM, term_handler);

  /* snmpwalk options changed in Redhat 8.0 */
  argv = append_argv(0, SNMPWALK);
  argv = append_argv(argv, "-V");
  fp = nessus_popen(SNMPWALK, (const char**)argv, &snmpwalk_process);
  if (fp == NULL)
    {
      fprintf(stderr, "nessus_popen(snmpwalk) failed\n");
      return 0;
    }

  if (fgets(s, sizeof(s), fp) != NULL)
    {
      int	x = 0, y = 0, z = 0;
      sscanf(s, "NET-SNMP version: %d.%d.%d", &x, &y, &z);
      if (x > 5 || x == 5 && (y > 0 || z > 5))
	v506 = 1;
      else
	v506 = 0;
    }
  nessus_pclose(fp, snmpwalk_process);
  destroy_argv(argv);


  comm_send_status(globals, arg_get_value(hostinfos, "NAME"),"portscan",
    0, 100);
  /* TCP "scan" */
  memset(open_ports, 0, sizeof(open_ports));

  argv = make_argv(desc, TCP_TRUC, 0, &snmp_comm, &snmp_port);
  fp = nessus_popen(SNMPWALK, (const char**)argv, NULL);
  destroy_argv (argv);

  if (fp == NULL)
    {
      fprintf(stderr, "nessus_popen(snmpwalk) failed\n");
      return 0;
    }

  read_snmpwalk_output(desc, fp, open_ports);
  fclose(fp);

  argv = make_argv(desc, TCP_TRUC, 1, &snmp_comm, &snmp_port);

 fp = nessus_popen(SNMPWALK, (const char**)argv, NULL);
 destroy_argv (argv);

  if (fp == NULL)
    {
      fprintf(stderr, "nessus_popen(snmpwalk) failed\n");
      return 0;
    }

  read_snmpwalk_output(desc, fp, open_ports);
  fclose(fp);

  for (i = 1, num_tcp_ports = 0; i < 65536; i ++)
    if (open_ports[i / BFLAGS] & (1 << (i % BFLAGS)))
      {
	num_tcp_ports ++;
	scanner_add_port(desc, i, "tcp");
#if 0
	fprintf(stderr, "TCP:%d\n", i);
#endif
      }

  /* UDP "scan" */
  memset(open_ports, 0, sizeof(open_ports));

  argv = make_argv(desc, UDP_TRUC, 0, &snmp_comm, &snmp_port);

 fp = nessus_popen(SNMPWALK, (const char**)argv, NULL);
 destroy_argv (argv);

  if (fp == NULL)
    {
      fprintf(stderr, "nessus_popen(snmpwalk) failed\n");
      return 0;
    }

  read_snmpwalk_output(desc, fp, open_ports);
  fclose(fp);

 argv = make_argv(desc, UDP_TRUC, 1, &snmp_comm, &snmp_port);

 fp = nessus_popen(SNMPWALK, (const char**)argv, NULL);
 destroy_argv (argv);

  if (fp == NULL)
    {
      fprintf(stderr, "nessus_popen(snmpwalk) failed\n");
      return 0;
    }

  read_snmpwalk_output(desc, fp, open_ports);
  fclose(fp);

  for (i = 1, num_udp_ports = 0; i < 65536; i ++)
    if (open_ports[i / BFLAGS] & (1 << (i % BFLAGS)))
      {
	num_udp_ports ++;
	scanner_add_port(desc, i, "udp");
#if 0
	fprintf(stderr, "UDP:%d\n", i);
#endif
      }

  /* ******** */

  comm_send_status(globals, arg_get_value(hostinfos, "NAME"), "portscan",
		   100, 100);

  if (num_tcp_ports > 0 || num_udp_ports > 0)
    {
      char	*msg = emalloc(strlen(snmp_comm) + 80);

      plug_set_key (desc, "Host/scanned", ARG_STRING, "1");
      
      sprintf(msg, "snmpwalk could get the open port list with the community name '%s'", snmp_comm);
      if (layer_udp)
	post_note_udp(desc, snmp_port, msg);
      else
      post_note(desc, snmp_port, msg);
      efree(&msg);
    }
  if (num_udp_ports > 0)
    plug_set_key (desc, "Host/udp_scanned", ARG_STRING, "1");

#ifdef WIN_INST_SOFT
  argv = make_argv(desc, WIN_INST_SOFT, 2, &snmp_comm, &snmp_port);
  fp = nessus_popen(SNMPWALK, (const char**)argv, NULL);
  destroy_argv (argv);

  if (fp == NULL)
    {
      fprintf(stderr, "nessus_popen(snmpwalk) failed\n");
      return 0;
    }

  while ((fgets(s, sizeof(s), fp)) != NULL)
    {
      if ((q = strstr(s, " = ")) != NULL &&
	  (q = strstr(q, "Windows")) != NULL )
	{
	  if ((p = strstr(q, "Hotfix")) != NULL ||
	      (p = strstr(q, "Security Rollup Package")) != NULL )
	    {
	      if ((q = strstr(p, "See Q")) != NULL)
		{
		  char		key[64], *p2 = q;
		  q --;
		  while (isdigit(*p2))
		    p2 ++;
		  *p2 = '\0';
		  if (*p == 'H')
		    snprintf(key, sizeof(key), "Windows/Installed/HotFix/%s", q);
		  else
		    snprintf(key, sizeof(key), "Windows/Installed/SRP/%s", q);
		  plug_set_key(desc, key, ARG_INT, (void*)1);
		  patch_nb ++;
		  if (msg_len == 0)
		    {
#define SNMP_HF	"According to the SNMP MIB, those patchs are installed:\n"
		      msg_len = sizeof(SNMP_HF)-1;
		      msg = estrdup(SNMP_HF);
		    }
		  l = strlen(q);
		  msg = erealloc(msg, msg_len + l + 2);
		  sprintf(msg + msg_len, "%s\n", q);
		  msg_len += l + 1;
		}
	    }
	}
    }
  fclose(fp);

  if (patch_nb > 0)
    {
      post_note(desc, snmp_port, msg);
      efree(&msg);
      plug_set_key (desc, "Windows/Installed/SNMP_found_patches", ARG_INT, (void*)1);
    }
  else
    plug_set_key (desc, "Windows/Installed/SNMP_found_patches", ARG_INT, (void*)0);
#endif

  return 0;
}


