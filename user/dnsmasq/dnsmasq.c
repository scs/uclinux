/* dnsmasq is Copyright (c) 2000 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
*/

/* See RFC1035 for details of the protocol this code talks. */

/* Author's email: simon@thekelleys.org.uk */

#include "dnsmasq.h"

static struct server *last_server;  
static struct frec *ftab;
static int sighup, sigusr1;
static int wait_timeout = 2;
static int cache_failures = 0;
static int num_servers = 0;

#ifndef HAVE_GETOPT_LONG
  struct option
  {
    const char *name;
    int has_arg;
    int *flag;
    int val;
  };

  #define no_argument		0
  #define required_argument	1
  #define optional_argument	2

  #define getopt_long(ARGC, ARGV, OPTS, OPTARRAY, INDEX) getopt(ARGC, ARGV, OPTS)
#endif

static struct option opts[] = { 
  {"version", no_argument, 0, 'v'},
  {"no-hosts", no_argument, 0, 'h'},
  {"no-poll", no_argument, 0, 'n'},
  {"help", no_argument, 0, '?'},
  {"no-daemon", no_argument, 0, 'd'},
  {"user", required_argument, 0, 'u'},
  {"resolv-file", required_argument, 0, 'r'},
  {"mx-host", required_argument, 0, 'm'},
  {"mx-target", required_argument, 0, 't'},
  {"cache-size", required_argument, 0, 'c'},
  {"port", required_argument, 0, 'p'},
  {"dhcp-lease", required_argument, 0, 'l'},
  {"domain-suffix", required_argument, 0, 's'},
  {"interface", required_argument, 0, 'i'},
  {"listen-address", required_argument, 0, 'a'},
  {"bogus-priv", no_argument, 0, 'b'},
  {"filterwin2k", no_argument, 0, 'f'},
  {"pid-file", required_argument, 0, 'x'},
  {"wait-timeout", required_argument, 0, 'w'},
  {"cache-failures", no_argument, 0, 'F'},
  {"conf-file", required_argument, 0, 'C'},
  {0}
};

static char *usage =
"Usage: dnsmasq [options]\n"
"\nValid options are :\n"
"-v, --version               Display dnsmasq version.\n"
"-d, --no-daemon             Do NOT fork into the background.\n"
"-h, --no-hosts              Do NOT load " HOSTSFILE " file.\n"
"-n, --no-poll               Do NOT poll " RESOLVFILE " file, reload only on SIGHUP.\n"
"-u, --user=username         Change to this user after startup. (defaults to " CHUSER ").\n"  
"-b, --bogus-priv            Fake reverse lookups for RFC1918 private address ranges.\n"
"-f, --filterwin2k           Don't forward spurious DNS requests from Windows hosts.\n"
"-r, --resolv-file=path      Specify path to resolv.conf (defaults to " RESOLVFILE ").\n"
"-x, --pid-file=path         Specify path of PID file. (defaults to " RUNFILE ").\n"
"-p, --port=number           Specify port to listen for DNS requests on (defaults to 53).\n"
"-m, --mx-host=host_name     Specify the MX name to reply to.\n"
"-t, --mx-target=host_name   Specify the host in an MX reply.\n"
"-c, --cache-size=cachesize  Specify the size of the cache in entries (defaults to %d).\n"
"-l, --dhcp-lease=path       Specify the path to the DHCP lease file.\n"
"-s, --domain-suffix=domain  Specify the domain suffix which DHCP entries will use.\n"
"-i, --interface=interface   Specify interface(s) to listen on.\n"
"-a, --listen-address=ipaddr Specify local address(es) to listen on.\n"
"-w, --wait-timeout=to       The amount of time to wait before returning the best answer.\n"
"-F, --cache-failures        Cache failed query responses.\n"
"-C, --conf-file             Specify an additional conf file to read for options (defaults to " CONFFILE ").\n"
"-?, --help                  Display this message.\n"
"\n";

static void forward_query(int udpfd, 
			  int peerfd,
			  int peerfd6,
			  union mysockaddr *udpaddr, 
			  union mysockaddr *myaddr,
			  int ifindex,
			  HEADER *header,
			  int plen);
static void reply_query(int fd, char *packet, int cachesize);
static void forward_reply(struct frec *forward, char *packet, int n);
static int reload_servers(char *fname, struct irec *interfaces,
			   int peerfd, int peerfd6);
static void *safe_malloc(int size);
static char *safe_string_alloc(const char *cp);
static void die(const char *message, ...);
static int sa_len(union mysockaddr *addr);
static struct irec *find_all_interfaces(struct iname *names, 
					struct iname *addrs,
					int fd, int port);
#ifndef BIND_EACH_INTERFACE
static struct irec *bind_any_interface(int port);
#endif
static int sockaddr_isequal(union mysockaddr *s1, union mysockaddr *s2);
static void sig_handler(int sig);
static struct frec *get_new_frec(time_t now);
static struct frec *lookup_frec(unsigned short id);
static struct frec *lookup_frec_by_sender(unsigned short id,
					  union mysockaddr *addr);
static unsigned short get_id(void);
static int response_better_than(struct frec *forward, HEADER *new);
static void timeout_responses(int cachesize);
static int response_acceptable(HEADER *header);
static int recvto(int s, void *buf, size_t len, int flags,
		  struct sockaddr *from, socklen_t *fromlen,
		  union mysockaddr *to,
		  unsigned int *ifindex);
static int sendfrom(int s, void *buf, size_t len, int flags,
    		    struct sockaddr *to, socklen_t tolen,
		    union mysockaddr *from,
		    unsigned int ifindex);

static int cachesize = CACHESIZ;
static int port = NAMESERVER_PORT;
static int boguspriv = 0;
static int filterwin2k = 0;
static int use_hosts = 1, daemonize = 1, do_poll = 1, first_loop = 1;
static char *runfile = RUNFILE;
static char *resolv = RESOLVFILE;
static char *mxname = NULL;
static char *mxtarget = NULL;
static char *lease_file = NULL;
static char *domain_suffix = NULL;
static char *username = CHUSER;
static struct iname *if_names = NULL;
static struct iname *if_addrs = NULL;
static char *conffile = NULL;

static int do_option(int option, const char *optarg)
{
  if (option == 'b')
      boguspriv = 1;
    
  if (option == 'f')
      filterwin2k = 1;
      
  if (option == 'v')
    {
      fprintf(stderr, "dnsmasq version %s\n", VERSION);
      exit(0);
    }

  if (option == 'h')
    use_hosts = 0;

  if (option == 'n')
    do_poll = 0;

  if (option == 'd')
    daemonize = 0;
  
  if (option == 'x')
    runfile = safe_string_alloc(optarg);

  if (option == 'r')
    resolv = safe_string_alloc(optarg);
    
  if (option == 'm')
    mxname = safe_string_alloc(optarg);

  if (option == 't')
    mxtarget = safe_string_alloc(optarg);
  
  if (option == 'l')
    lease_file = safe_string_alloc(optarg);
  
  if (option == 's')
    domain_suffix = safe_string_alloc(optarg);

  if (option == 'u')
    username = safe_string_alloc(optarg);
  
  if (option == 'i')
    {
      struct iname *new = safe_malloc(sizeof(struct iname));
      new->next = if_names;
      if_names = new;
      new->name = safe_string_alloc(optarg);
      new->found = 0;
    }

  if (option == 'a')
    {
      struct iname *new = safe_malloc(sizeof(struct iname));
      new->next = if_addrs;
      if_addrs = new;
      new->found = 0;
      if (inet_pton(AF_INET, optarg, &new->addr.in.sin_addr))
	new->addr.sa.sa_family = AF_INET;
#ifdef HAVE_IPV6
      else if (inet_pton(AF_INET6, optarg, &new->addr.in6.sin6_addr))
	new->addr.sa.sa_family = AF_INET6;
#endif
      else
	option = '?'; /* error */
    }

  if (option == 'c')
    {
      cachesize = atoi(optarg);
      /* zero is OK, and means no caching.
	 Very low values cause prolems with  hosts
	 with many A records. */
      
      if (cachesize < 0)
	option = '?'; /* error */
      else if ((cachesize > 0) && (cachesize < 20))
	cachesize = 20;
      else if (cachesize > 1000)
	cachesize = 1000;
    }

  if (option == 'p')
    port = atoi(optarg);

  if (option == 'w')
    wait_timeout = atoi(optarg);

  if (option == 'F')
    cache_failures = 1; /* cache failures */

  if (option == 'C')
	conffile = safe_string_alloc(optarg);

  return option;
}

static void read_opts (int argc, char **argv)
{
  int option = 0, i;
  FILE *f = NULL;
  char buff[256];

  opterr = 0;

  while (1)
    {
      if (!f)
        {
	  option = getopt_long(argc, argv, "fFnbvhdr:m:p:c:l:s:i:t:u:a:x:w:C:", opts, NULL);
        }
      else
	{ /* f non-NULL, reading from conffile. */
	  if (!fgets(buff, MAXDNAME, f))
	    {
	      /* At end of file, all done */
	      fclose(f);
	      break;
	    }
	  else
	    {
	      char *p;
	      /* fgets gets end of line char too. */
	      while (strlen(buff) > 0 && 
		     (buff[strlen(buff)-1] == '\n' || 
		      buff[strlen(buff)-1] == ' ' || 
		      buff[strlen(buff)-1] == '\t'))
		buff[strlen(buff)-1] = 0;
	      if (*buff == '#' || *buff == 0)
		continue; /* comment */
	      if ((p=strchr(buff, '=')))
		{
		  optarg = p+1;
		  *p = 0;
		}
	      else
		optarg = NULL;
	      
	      option = 0;
	      for (i=0; opts[i].name; i++) 
		if (strcmp(opts[i].name, buff) == 0)
		  option = opts[i].val;
	      if (!option)
		die("Bad option in %s: %s", conffile ?: CONFFILE, buff);
	    }
	}
      
      if (option == -1)
	{ /* end of command line args, start reading conffile. */
	  if (conffile && !*conffile)
	    break; /* "confile=" option disables */
	  if (!(f = fopen(conffile ?: CONFFILE, "r")))
	    {   
	      if (errno == ENOENT && !conffile)
		break; /* No conffile, all done. */
	      else
		die("Cannot read %s: %m", conffile);
	    }
		continue;
	}
     
      if (f) {
		  if (option == 'v' || option == 'C' || option == '?')
			  continue;
      
	for (i=0; opts[i].name; i++)
	  if (option == opts[i].val)
	    {
	      if (opts[i].has_arg == no_argument && optarg) {
		die("Extraneous parameter for %s in config file.", buff);
	      }
	      if (opts[i].has_arg == required_argument && !optarg) {
		die("Missing parameter for %s in config file.", buff);
	      }
	      break;
	    }
      }
      
      if (option && option != '?')
	{
	  option = do_option(option, optarg);
	}

      if (option == '?')
	{
	  if (f)
	    {
	      die("Missing parameter for %s in config file.", buff);
	    }
	  else
	    {
	      fprintf (stderr, usage, CACHESIZ);
	      exit(0);
	    }
	}
    }
}
      
int main (int argc, char **argv)
{
  int i;
  int peerfd, peerfd6;
  time_t resolv_changed = 0;
  off_t lease_file_size = (off_t)0;
  ino_t lease_file_inode = (ino_t)0;
  time_t lease_file_mtime = (time_t)0;
  struct irec *iface, *interfaces = NULL;
  struct timeval to;
  FILE *pidfile;

  sighup = 1; /* init cache the first time through */
  sigusr1 = 0; /* but don't dump */
  signal(SIGUSR1, sig_handler);
  signal(SIGHUP, sig_handler);

  last_server = NULL;

  read_opts(argc, argv);
  
  /* port might no be known when the address is parsed - fill in here */
  if (if_addrs)
    {  
      struct iname *tmp;
      for(tmp = if_addrs; tmp; tmp = tmp->next)
#ifdef HAVE_IPV6
	if (tmp->addr.sa.sa_family == AF_INET6)
	  { 
#ifdef HAVE_SOCKADDR_SA_LEN
	    tmp->addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	    tmp->addr.in6.sin6_port = htons(port);
	    tmp->addr.in6.sin6_flowinfo = htonl(0);
	  }
	else
#endif
	  {
#ifdef HAVE_SOCKADDR_SA_LEN
	    tmp->addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
	    tmp->addr.in.sin_port = htons(port);
	  }
    }

  /* only one of these need be specified: the other defaults to the
     host-name */
  if (mxname || mxtarget)
    {
      static char hostname[MAXDNAME];
      if (gethostname(hostname, MAXDNAME) == -1)
	{
	  perror("dnsmasq: cannot get host-name");
	  exit(1);
	}
      
      if (!mxname)
	mxname = safe_string_alloc(hostname);
      
      if (!mxtarget)
	mxtarget = safe_string_alloc(hostname);
    }

  /* peerfd is not bound to a low port
     so that we can send queries out on it without them getting
     blocked at firewalls */
  
  if ((peerfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1 && 
      errno != EAFNOSUPPORT &&
      errno != EINVAL)
    {
      perror("dnsmasq: cannot create socket");
      exit(1);
    }
  
  if ((peerfd6 = socket(AF_INET6, SOCK_DGRAM, 0)) == -1 && 
      errno != EAFNOSUPPORT &&
      errno != EINVAL)
    {
      perror("dnsmasq: cannot create IPv6 socket");
      exit(1);
    }
     
  if (peerfd == -1 && peerfd6 == -1)
    {
      fprintf(stderr, "dnsmasq: no kernel support for IPv4 _or_ IPv6.\n");
      exit(1);
    }

#ifdef BIND_EACH_INTERFACE
  interfaces = find_all_interfaces(if_names, if_addrs,
				   peerfd == -1 ? peerfd6 : peerfd, port);
  
  /* open a socket bound to NS port on each local interface.
     this is necessary to ensure that our replies originate from
     the address they were sent to. See Stevens page 531 */
  for (iface = interfaces; iface; iface = iface->next)
    {
      if ((iface->fd = socket(iface->addr.sa.sa_family, SOCK_DGRAM, 0)) == -1)
	{
	  perror("dnsmasq: cannot create socket");
	  exit(1);
	}
      
      if (bind(iface->fd, &iface->addr.sa, sa_len(&iface->addr)))
	{
	  perror("dnsmasq: bind failed");
	  exit(1);
	}
    }
#else
  interfaces = bind_any_interface(port);
#endif

  ftab = safe_malloc(FTABSIZ*sizeof(struct frec));
  for (i=0; i<FTABSIZ; i++)
    {
      ftab[i].new_id = 0;
      ftab[i].packet_alloc = 0;
      ftab[i].packet = NULL;
    }
  
  if (cachesize) 
    cache_init(cachesize);

  setbuf(stdout,NULL);

  if (daemonize)
    {
      struct passwd *ent_pw;
        
      /* The following code "daemonizes" the process. 
	 See Stevens section 12.4 */

#ifndef __uClinux__
      if (fork() != 0 )
	exit(0);
      
      setsid();
      
      if (fork() != 0)
	exit(0);
#endif
      

      for (i=0; i<64; i++)
	{
	  if (i == peerfd || i == peerfd6)
	    continue;
	  for (iface = interfaces; iface; iface = iface->next)
	    if (iface->fd == i)
	      break;
	  if (!iface)
	    close(i);
	}

      /* Change uid and gid for security */
      if ((ent_pw = getpwnam(username)))
	{
	  gid_t dummy;
	  struct group *gp;
	  /* remove all supplimentary groups */
	  setgroups(0, &dummy);
	  /* change group to "dip" if it exists, for /etc/ppp/resolv.conf 
	     otherwise get the group for "nobody" */
	  if ((gp = getgrnam("dip")) || (gp = getgrgid(ent_pw->pw_gid)))
	    setgid(gp->gr_gid); 
	  /* finally drop root */
	  setuid(ent_pw->pw_uid);
	}
    }
  
  chdir("/");
  umask(022); /* make pidfile 0644 */
      
  /* write pidfile _after_ forking ! */
  if ((pidfile = fopen(runfile, "w")))
    {
      fprintf(pidfile, "%d\n", (int) getpid());
      fclose(pidfile);
    }

  umask(0);

  openlog("dnsmasq", LOG_PID, LOG_DAEMON);
  
  if (cachesize)
    syslog(LOG_INFO, "started, version %s cachesize %d", VERSION, cachesize);
  else
    syslog(LOG_INFO, "started, version %s cache disabled", VERSION);
  
  if (mxname)
    syslog(LOG_INFO, "serving MX record for mailhost %s target %s", 
	   mxname, mxtarget);
  
  if (getuid() == 0 || geteuid() == 0)
    syslog(LOG_WARNING, "failed to drop root privs");
  
  while (1)
    {
      /* Size: we check after adding each record, so there must be 
	 memory for the largest packet, and the largest record */
      /* declare packet as below to ensure alignment for header access */
      static HEADER _packet[(PACKETSZ+MAXDNAME+RRFIXEDSZ)/sizeof(HEADER)+1];
      char *packet = (char *) &_packet[0];
      int ready, maxfd = peerfd > peerfd6 ? peerfd : peerfd6;
      fd_set rset;
      HEADER *header;
      struct stat statbuf;
      
      if (first_loop)
	/* do init stuff only first time round. */
	{
	  first_loop = 0;
	  ready = 0;
	}
      else
	{
	  if (wait_timeout)
	    {
	      /* Send the best response so far for anything taking too long */
	      timeout_responses(cachesize);
	      to.tv_sec = wait_timeout;
	      to.tv_usec = 0;
	    }

	  FD_ZERO(&rset);
	  if (peerfd != -1)
	    FD_SET(peerfd, &rset);
	  if (peerfd6 != -1)
	    FD_SET(peerfd6, &rset);
	  for (iface = interfaces; iface; iface = iface->next)
	    {
	      FD_SET(iface->fd, &rset);
	      if (iface->fd > maxfd)
		maxfd = iface->fd;
	    }
	  
	  ready = select(maxfd+1, &rset, NULL, NULL, wait_timeout ? &to : NULL);
	  
	  if (ready == -1)
	    {
	      if (errno == EINTR)
		ready = 0; /* do signal handlers */
	      else
		continue;
	    }
	}

      if (sighup)
	{
	  signal(SIGHUP, SIG_IGN);
	  cache_reload(use_hosts, cachesize, domain_suffix);
	  if (!do_poll)
	    num_servers = reload_servers(resolv, interfaces, peerfd, peerfd6);
	  sighup = 0;
	  signal(SIGHUP, sig_handler);
	}

      if (sigusr1)
	{
	  signal(SIGUSR1, SIG_IGN);
	  dump_cache(daemonize, cachesize);
	  sigusr1 = 0;
	  signal(SIGUSR1, sig_handler);
	}

      if (do_poll &&
	  (stat(resolv, &statbuf) == 0) && 
	  (statbuf.st_mtime > resolv_changed) &&
	  (statbuf.st_mtime < time(NULL) || resolv_changed == 0))
	{
	  resolv_changed = statbuf.st_mtime;
	  num_servers = reload_servers(resolv, interfaces, peerfd, peerfd6);
	}

      if (lease_file && (stat(lease_file, &statbuf) == 0) &&
	  ((lease_file_size == (off_t)0) ||
	   (statbuf.st_size > lease_file_size) ||
	   (statbuf.st_ino != lease_file_inode) ||
	   (statbuf.st_mtime != lease_file_mtime)))
	{
	  lease_file_size = statbuf.st_size;
	  lease_file_inode = statbuf.st_ino;
	  lease_file_mtime = statbuf.st_mtime;
	  load_dhcp(lease_file, domain_suffix);
	}
		
      if (ready == 0)
	continue; /* no sockets ready */

      if (peerfd != -1 && FD_ISSET(peerfd, &rset))
	reply_query(peerfd, packet, cachesize);
      if (peerfd6 != -1 && FD_ISSET(peerfd6, &rset))
	reply_query(peerfd6, packet, cachesize);
      
      for (iface = interfaces; iface; iface = iface->next)
	{
	  if (FD_ISSET(iface->fd, &rset))
	    {
	      /* request packet, deal with query */
	      union mysockaddr udpaddr;
	      socklen_t udplen = sizeof(udpaddr);
	      union mysockaddr myaddr;
	      unsigned int ifindex;
	      int m, n = recvto(iface->fd, packet, PACKETSZ, 0, &udpaddr.sa, &udplen, &myaddr, &ifindex); 
	      udpaddr.sa.sa_family = iface->addr.sa.sa_family;
#ifdef HAVE_IPV6
	      if (udpaddr.sa.sa_family == AF_INET6)
		udpaddr.in6.sin6_flowinfo = htonl(0);
#endif
	      
	      header = (HEADER *)packet;
	      if (n >= (int)sizeof(HEADER) && !header->qr)
		{
		  unsigned int add;
		  add = ((struct sockaddr_in *)&udpaddr)->sin_addr.s_addr;
		  m = answer_request (header, ((char *) header) + PACKETSZ, n, mxname, mxtarget, boguspriv, filterwin2k);
		  if (m >= 1)
		    {
		      /* answered from cache, send reply */
		      sendfrom(iface->fd, (char *)header, m, 0, 
			     &udpaddr.sa, sa_len(&udpaddr), &myaddr, ifindex);
		    }
		  else 
		    {
		      /* cannot answer from cache, send on to real nameserver */
		      forward_query(iface->fd, peerfd, peerfd6, &udpaddr,
				    &myaddr, ifindex,
				    header, n);
		    }
		}
	      
	    }
	}
    }
  
  return 0;
}

/* for use during startup */
static void *safe_malloc(int size)
{
  void *ret = malloc(size);
  
  if (!ret)
    {
      fprintf(stderr, "dnsmasq: could not get memory\n");
      exit(1);
    }
 
  return ret;
}
    
static char *safe_string_alloc(const char *cp)
{
  char *ret = safe_malloc(strlen(cp)+1);
  strcpy(ret, cp);
  return ret;
}

static int sa_len(union mysockaddr *addr)
{
#ifdef HAVE_SOCKADDR_SA_LEN
  return addr->sa.sa_len;
#else
#ifdef HAVE_IPV6
  if (addr->sa.sa_family == AF_INET)
#endif
    return sizeof(addr->in);
#ifdef HAVE_IPV6
  else
    return sizeof(addr->in6); 
#endif
#endif /*HAVE_SOCKADDR_SA_LEN*/
}

static struct irec *add_iface(struct irec *list, unsigned int flags, 
			      char *name, union mysockaddr *addr, 
			      struct iname *names, struct iname *addrs)
{
  struct irec *iface;

  /* we may need to check the whitelist */
  if (names)
    { 
      struct iname *tmp;
      for(tmp = names; tmp; tmp = tmp->next)
	if (strcmp(tmp->name, name) == 0)
	  {
	    tmp->found = 1;
	    break;
	  }
      if (!(flags & IFF_LOOPBACK) && !tmp) 
	/* not on whitelist and not loopback */
	return list;
    }
  
  if (addrs)
    { 
      struct iname *tmp;
      for(tmp = addrs; tmp; tmp = tmp->next)
	if (sockaddr_isequal(&tmp->addr, addr))
	  {
	    tmp->found = 1;
	    break;
	  }
      
      if (!tmp) 
	/* not on whitelist */
	return list;
    }
  
  /* check whether the interface IP has been added already 
     it is possible to have multiple interfaces with the same address. */
  for (iface = list; iface; iface = iface->next) 
    if (sockaddr_isequal(&iface->addr, addr))
      break;
  if (iface) 
    return list;
  
  /* If OK, add it to the head of the list */
  iface = safe_malloc(sizeof(struct irec));
  iface->addr = *addr;
  iface->next = list;
  return iface;
}

static struct irec *find_all_interfaces(struct iname *names,
					struct iname *addrs,
					int fd, int port)
{
  /* this code is adapted from Stevens, page 434. It finally
     destroyed my faith in the C/unix API */
  int len = 100 * sizeof(struct ifreq);
  int lastlen = 0;
  char *buf, *ptr;
  struct ifconf ifc;
  struct irec *ret = NULL;

  while (1)
    {
      buf = safe_malloc(len);
      ifc.ifc_len = len;
      ifc.ifc_buf = buf;
      if (ioctl(fd, SIOCGIFCONF, &ifc) < 0)
	{
	  if (errno != EINVAL || lastlen != 0)
	    {
	      perror("dnsmasq: ioctl error while enumerating interfaces");
	      exit(1);
	    }
	}
      else
	{
	  if (ifc.ifc_len == lastlen)
	    break; /* got a big enough buffer now */
	  lastlen = ifc.ifc_len;
	}
      len += 10* sizeof(struct ifreq);
      free(buf);
    }

  for (ptr = buf; ptr < buf + ifc.ifc_len; )
    {
      struct ifreq *ifr = (struct ifreq *) ptr;
#ifdef HAVE_SOCKADDR_SA_LEN
      ptr += ifr->ifr_addr.sa_len + IF_NAMESIZE;
#else
      ptr += sizeof(struct ifreq);
#endif

      if (ifr->ifr_addr.sa_family == AF_INET || ifr->ifr_addr.sa_family == AF_INET6)
	{
	  /* copy since getting flags overwrites */
	  union mysockaddr addr;
#ifdef HAVE_IPV6
	  if (ifr->ifr_addr.sa_family == AF_INET6)
	    {
#ifdef HAVE_BROKEN_SOCKADDR_IN6
	      addr.in6 = *((struct my_sockaddr_in6 *) &ifr->ifr_addr);
#else
	      addr.in6 = *((struct sockaddr_in6 *) &ifr->ifr_addr);
#endif
	      addr.in6.sin6_port = htons(port);
	      addr.in6.sin6_flowinfo = htonl(0);
	    }
	  else
#endif
	    {
	      addr.in = *((struct sockaddr_in *) &ifr->ifr_addr);
	      addr.in.sin_port = htons(port);
	    }
	  /* get iface flags, since we need to distinguish loopback interfaces */
	  if (ioctl(fd, SIOCGIFFLAGS, ifr) < 0)
	    {
	      perror("dnsmasq: ioctl error getting interface flags");
	      exit(1);
	    }
	  
	  ret = add_iface(ret, ifr->ifr_flags, ifr->ifr_name, &addr, 
			  names, addrs);
	}
    }
  free(buf);

#if defined(HAVE_LINUX_IPV6_PROC) && defined(HAVE_IPV6)
  /* IPv6 addresses don't seem to work with SIOCGIFCONF. Barf */
  /* This code snarfed from net-tools 1.60 and certainly linux specific, though
     it shouldn't break on other Unices, and their SIOGIFCONF might work. */
  {
    FILE *f = fopen(IP6INTERFACES, "r");
    
    if (f)
      {
	union mysockaddr addr;
	unsigned int plen, scope, flags, if_idx;
	char devname[20], addrstring[32];
	
	while (fscanf(f, "%32s %02x %02x %02x %02x %20s\n",
		      addrstring, &if_idx, &plen, &scope, &flags, devname) != EOF) 
	  {
	    int i;
	    unsigned char *addr6p = (unsigned char *) &addr.in6.sin6_addr;
	    memset(&addr, 0, sizeof(addr));
	    addr.sa.sa_family = AF_INET6;
	    for (i=0; i<16; i++)
	      {
		unsigned int byte;
		sscanf(addrstring+i+i, "%02x", &byte);
		addr6p[i] = byte;
	      }
#ifdef HAVE_SOCKADDR_SA_LEN 
	    /* For completeness - should never be defined on Linux. */
	    addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	    addr.in6.sin6_port = htons(port);
	    addr.in6.sin6_flowinfo = htonl(0);
	    addr.in6.sin6_scope_id = htonl(scope);
	    
	    ret = add_iface(ret, flags, devname, &addr, names, addrs);
	  }
	
	fclose(f);
      }
  }
#endif /* LINUX */

  /* if a whitelist provided, make sure the if names on it were OK */
  while(names)
    {
      if (!names->found)
	{
	  fprintf(stderr, "dnsmasq: unknown interface %s\n", names->name);
	  exit(1);
	}
      names = names->next;
    }
   
  while(addrs)
    {
      if (!addrs->found)
	{
	  char addrbuff[INET6_ADDRSTRLEN];
#ifdef HAVE_IPV6
	  if (addrs->addr.sa.sa_family == AF_INET6)
	    inet_ntop(AF_INET6, &addrs->addr.in6.sin6_addr,
		      addrbuff, INET6_ADDRSTRLEN);
	  else
#endif
	    inet_ntop(AF_INET, &addrs->addr.in.sin_addr,
		      addrbuff, INET_ADDRSTRLEN);
	  fprintf(stderr, "dnsmasq: no interface with address %s\n", addrbuff);
	  exit(1);
	}
      addrs = addrs->next;
    }
    
  return ret;
}

#ifndef BIND_EACH_INTERFACE
/* Just bind to AF_INET, INADDR_ANY */
static struct irec *bind_any_interface(int port)
{
  struct irec *iface;
  int opt = 1;

  iface = safe_malloc(sizeof(struct irec));
  memset(iface, 0, sizeof(struct irec));

#ifdef HAVE_IPV6
  iface->addr.in6.sin6_family = AF_INET6;
  iface->addr.in6.sin6_addr = in6addr_any;
  iface->addr.in6.sin6_port = htons(port);
#ifdef HAVE_SOCKADDR_SA_LEN 
  iface->addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
  if ((iface->fd = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
    {
      perror("dnsmasq: cannot create socket");
      exit(1);
    }
  if (setsockopt(iface->fd, SOL_IPV6, IPV6_PKTINFO, &opt, sizeof(opt)) == -1)
    {
      perror("dnsmasq: cannot setsockopt IPV6_PKTINFO");
      exit(1);
    }
#else
  iface->addr.in.sin_family = AF_INET;
  iface->addr.in.sin_addr.s_addr = INADDR_ANY;
  iface->addr.in.sin_port = htons(port);
#ifdef HAVE_SOCKADDR_SA_LEN 
  iface->addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
  if ((iface->fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {
      perror("dnsmasq: cannot create socket");
      exit(1);
    }
#endif
      
  if (setsockopt(iface->fd, SOL_IP, IP_PKTINFO, &opt, sizeof(opt)) == -1)
    {
      perror("dnsmasq: cannot setsockopt IP_PKTINFO");
      exit(1);
    }
  if (bind(iface->fd, &iface->addr.sa, sa_len(&iface->addr)) == -1)
    {
      perror("dnsmasq: bind failed");
      exit(1);
    }

  return iface;
}
#endif

static void sig_handler(int sig)
{
  if (sig == SIGHUP)
    sighup = 1;
  else if (sig == SIGUSR1)
    sigusr1 = 1;
}

static int reload_servers(char *fname, struct irec *interfaces,
			   int peerfd, int peerfd6)
{
  FILE *f;
  char *line, buff[MAXLIN];
  int i;
  struct server *first_server = NULL;

  f = fopen(fname, "r");
  if (!f)
    {
      syslog(LOG_ERR, "failed to read %s: %m", fname);
      return 0;
    }
  
  syslog(LOG_INFO, "reading %s", fname);

  /* forward table rules reference servers, so have to blow 
     them away */
  for (i=0; i<FTABSIZ; i++)
    ftab[i].new_id = 0;
  
  /* delete existing ones */
  if (last_server)
    {
      struct server *s = last_server;
      while (1)
	{
	  struct server *tmp = s->next;
	  free(s);
	  if (tmp == last_server)
	    break;
	  s = tmp;
	}
      last_server = NULL;
    }
	
  i = 0; /* # servers */

  while ((line = fgets(buff, MAXLIN, f)))
    {
      union  mysockaddr addr;
      char *token = strtok(line, " \t\n");
      struct server *serv;
      struct irec *iface;

      if (!token || strcmp(token, "nameserver") != 0)
	continue;
      if (!(token = strtok(NULL, " \t\n")))
	continue;
      
      if (inet_pton(AF_INET, token, &addr.in.sin_addr))
	{
	  if (addr.in.sin_addr.s_addr == htonl(INADDR_LOOPBACK))
	    continue;
	  if (peerfd == -1)
	    {
	      syslog(LOG_WARNING, 
		     "ignoring nameserver %s - no IPv4 kernel support", token);
	      continue;
	    }
#ifdef HAVE_SOCKADDR_SA_LEN
	  addr.in.sin_len = sizeof(struct sockaddr_in);
#endif
	  addr.in.sin_family = AF_INET;
	  addr.in.sin_port = htons(NAMESERVER_PORT);
	}
#ifdef HAVE_IPV6
      else if (inet_pton(AF_INET6, token, &addr.in6.sin6_addr))
	{
	  if (IN6_IS_ADDR_LOOPBACK(&addr.in6.sin6_addr))
	    continue;
	  if (peerfd6 == -1)
	    {
	      syslog(LOG_WARNING, 
		     "ignoring nameserver %s - no IPv6 kernel support", token);
	      continue;
	    }
#ifdef HAVE_SOCKADDR_SA_LEN
	  addr.in6.sin6_len = sizeof(struct sockaddr_in6);
#endif
	  addr.in6.sin6_family = AF_INET6;
	  addr.in6.sin6_port = htons(NAMESERVER_PORT);
	  addr.in6.sin6_flowinfo = htonl(0);
	}
#endif
      else
	continue;
      
	  /* Avoid loops back to ourself */
#ifdef BIND_EACH_INTERFACE
      for (iface = interfaces; iface; iface = iface->next)
	if (sockaddr_isequal(&addr, &iface->addr))
	  {
	    syslog(LOG_WARNING, "ignoring nameserver %s - local interface", token);
	    break;
	  }
      if (iface)
	continue;
#else
	  {
		struct irec *current_interfaces;
		struct irec *p, *next_p;
		/* need to rebuild a list of the current interfaces */

		current_interfaces = find_all_interfaces(NULL, NULL,
				peerfd == -1 ? peerfd6 : peerfd, NAMESERVER_PORT);
		for (iface = current_interfaces; iface; iface = iface->next) {
			if (sockaddr_isequal(&addr, &iface->addr)) {
				syslog(LOG_WARNING, "ignoring nameserver %s - local interface", token);
				break;
			}
		}
		/* free the list of current_interfaces */
		for (p = current_interfaces; p; p = next_p) {
			next_p = p->next;
			free(p);
		}
		if (iface)
			continue;
	}
#endif
    
      if (!(serv = malloc(sizeof (struct server))))
	continue;

      if (last_server)
	last_server->next = serv;
      else
	first_server = last_server = serv;
      
      last_server = serv;
      serv->addr = addr;
      syslog(LOG_INFO, "using nameserver %s", token); 
      i++;
    }
  
  fclose(f);
  if (!last_server)
      return 0;

  last_server->next = first_server;
  return i;
}

static int sockaddr_isequal(union mysockaddr *s1, union mysockaddr *s2)
{
  if (s1->sa.sa_family == s2->sa.sa_family)
    { 
      if (s1->sa.sa_family == AF_INET &&
	  s1->in.sin_port == s2->in.sin_port &&
	  memcmp(&s1->in.sin_addr, &s2->in.sin_addr, sizeof(struct in_addr)) == 0)
	return 1;
      
#ifdef HAVE_IPV6
      if (s1->sa.sa_family == AF_INET6 &&
	  s1->in6.sin6_port == s2->in6.sin6_port &&
	  s1->in6.sin6_flowinfo == s2->in6.sin6_flowinfo &&
	  memcmp(&s1->in6.sin6_addr, &s2->in6.sin6_addr, sizeof(struct in6_addr)) == 0)
	return 1;
#endif
    }
  return 0;
}

	
static void forward_query(int udpfd,
			  int peerfd,
			  int peerfd6,
			  union mysockaddr *udpaddr, 
			  union mysockaddr *myaddr,
			  int ifindex,
			  HEADER *header,
			  int plen)
{
  time_t now = time(NULL);
  struct frec *forward;

   /* may be no available servers or recursion not speced */
  if (!last_server || !header->rd)
    forward = NULL;
  else if ((forward = lookup_frec_by_sender(ntohs(header->id), udpaddr)))
    {
      /* keep waiting */
      if (wait_timeout)
	return;

      /* retry on existing query, send to next server */
      forward->sentto = forward->sentto->next;
      header->id = htons(forward->new_id);
    }
  else
    {
      /* new query, pick nameserver and send */
      forward = get_new_frec(now);
      forward->source = *udpaddr;
      forward->dest = *myaddr;
      forward->ifindex = ifindex;
      forward->new_id = get_id();
      forward->fd = udpfd;
      forward->orig_id = ntohs(header->id);
      header->id = htons(forward->new_id);
      forward->sentto = last_server;
      last_server = last_server->next;
      forward->forward_count = 0;
      forward->packet_size = 0;
    }

  /* check for sendto errors here (no route to host) 
     if we fail to send to all nameservers, send back an error
     packet straight away (helps modem users when offline) */
  
  if (forward)
    {
      struct server *firstsentto = forward->sentto;
      while (1)
	{ 
	  int fd = forward->sentto->addr.sa.sa_family == AF_INET ? peerfd : peerfd6;
	  if (sendto(fd, (char *)header, plen, 0, 
		     &forward->sentto->addr.sa, 
		     sa_len(&forward->sentto->addr)) != -1)
	    {
	      if (!wait_timeout)
		return;
	      forward->forward_count++;
	    }
	  
	  forward->sentto = forward->sentto->next;
	  /* check if we tried all without success */
	  if (forward->sentto == firstsentto)
	    {
	      if (wait_timeout && forward->forward_count)
		return;
	      break;
	    }
	}
      
      /* could not send on, prepare to return */ 
      header->id = htons(forward->orig_id);
      forward->new_id = 0; /* cancel */
    }	  
  
  /* could not send on, return empty answer */
  header->qr = 1; /* response */
  header->aa = 0; /* authoritive - never */
  header->ra = 1; /* recursion if available */
  header->tc = 0; /* not truncated */
  header->rcode = NOERROR; /* no error */
  header->ancount = htons(0); /* no answers */
  header->nscount = htons(0);
  header->arcount = htons(0);
  sendfrom(udpfd, (char *)header, plen, 0, &udpaddr->sa, sa_len(udpaddr), myaddr, ifindex);
}

static void reply_query(int fd, char *packet, int cachesize)
{
  /* packet from peer server, extract data for cache, and send to
     original requester */
  struct frec *forward;
  HEADER *header;
  int n = recvfrom(fd, packet, PACKETSZ, 0, NULL, NULL);
  
  header = (HEADER *)packet;
  if (n >= (int)sizeof(HEADER) && header->qr)
    {
      if ((forward = lookup_frec(ntohs(header->id))))
	{
	  if (response_acceptable(header))
	    {
	      last_server = forward->sentto; /* known good */
	      if (cachesize != 0 && header->opcode == QUERY)
		extract_addresses(header, n);
	      forward_reply(forward, packet, n);
	    }
	  else if (!wait_timeout)
	    {
	      forward_reply(forward, packet, n);
	    }
	  else
	    {
	      /* If this reply is the best so far then save it */
	      if (response_better_than(forward, header))
		{
		  if (forward->packet_alloc < n)
		    {
		      if (forward->packet)
			free(forward->packet);
		      forward->packet = malloc(n);
		      if (!forward->packet)
			{
			  /* Forward this reply; it may be the best we'll get */
			  forward->packet_alloc = 0;
			  forward_reply(forward, packet, n);
			  return;
			}
		      forward->packet_alloc = n;
		    }
		  forward->packet_size = n;
	          memcpy(forward->packet, packet, n);
		}

	      /* If all replies received then forward the best */
	      forward->forward_count--;
	      if (forward->forward_count <= 0)
		forward_reply(forward, forward->packet, forward->packet_size);
	    }
	}
    }
}
	  
static void forward_reply(struct frec *forward, char *packet, int n)
{
  HEADER *header;
  
  header = (HEADER *)packet;
  header->id = htons(forward->orig_id);
  /* There's no point returning an upstream reply marked as truncated,
     since that will prod the resolver into moving to TCP - which we
     don't support. */
  header->tc = 0; /* goodbye truncate */
  sendfrom(forward->fd, packet, n, 0, 
	  &forward->source.sa, sa_len(&forward->source),
	  &forward->dest, forward->ifindex);
  forward->new_id = 0; /* cancel */
}

static struct frec *get_new_frec(time_t now)
{
  int i;
  struct frec *oldest = &ftab[0];
  time_t oldtime = now;

  for(i=0; i<FTABSIZ; i++)
    {
      struct frec *f = &ftab[i];
      if (f->time <= oldtime)
	{
	  oldtime = f->time;
	  oldest = f;
	}
      if (f->new_id == 0)
	{
	  f->time = now;
	  return f;
	}
    }

  /* table full, use oldest */

  oldest->time = now;
  return oldest;
}
 
static struct frec *lookup_frec(unsigned short id)
{
  int i;
  for(i=0; i<FTABSIZ; i++)
    {
      struct frec *f = &ftab[i];
      if (f->new_id == id)
	return f;
    }
  return NULL;
}

static struct frec *lookup_frec_by_sender(unsigned short id,
					  union mysockaddr *addr)
{
  int i;
  for(i=0; i<FTABSIZ; i++)
    {
      struct frec *f = &ftab[i];
      if (f->new_id &&
	  f->orig_id == id && 
	  sockaddr_isequal(&f->source, addr))
	return f;
    }
  return NULL;
}


/* return unique ids between 1 and 65535 */
/* These are now random, FSVO random, to frustrate DNS spoofers */
/* code adapted from glibc-2.1.3 */ 
static unsigned short get_id(void)
{
#ifndef HAVE_ARC4RANDOM
  struct timeval now;
  static int salt = 0;
#endif
  unsigned short ret = 0;

  /* salt stops us spinning wasting cpu on a host with
     a low resolution clock and avoids sending requests
     with the same id which are close in time. */

  while (ret == 0)
    {
#ifdef HAVE_ARC4RANDOM
      ret = (unsigned short) arc4random();
#else
      gettimeofday(&now, NULL);
      ret = salt-- ^ now.tv_sec ^ now.tv_usec ^ getpid();
#endif
      
      /* scrap ids already in use */
      if ((ret != 0) && lookup_frec(ret))
	ret = 0;
    }

  return ret;
}


/*
 * Return whether the new is a better response to old.
 */
static int response_better_than(struct frec *forward, HEADER *new)
{
  HEADER *old;

  if (!forward->packet || !forward->packet_size)
    return 1;

  old = (HEADER *)forward->packet;
  if (old->rcode == DNS_WORST)
    return 1;

  if ((old->rcode == NOERROR) && (old->ancount == 0))
    {
      if ((new->rcode == NOERROR) && (old->ancount > 0))
	return 1;
      return 0;
    }

  if (old->rcode == NXDOMAIN) /*NXDOMAIN - at least it isn't an error*/
    return 0;

  /*lets assume the rest don't matter for the time being*/
  return (old->rcode > new->rcode);
}

/*
 * Is the response we got from the server acceptable
 */
static int response_acceptable(HEADER *header)
{
  if ((header->rcode == NOERROR) && (cache_failures || header->ancount))
    return 1;
  if ((header->rcode == NXDOMAIN) && cache_failures)
    return 1;
  return 0;
}

/*
 * timeout anything that has a response that we haven't sent to the user
 * yet.
 */
static void timeout_responses(int cachesize)
{
  int i;
  time_t now = time(NULL);

  for(i=0; i<FTABSIZ; i++)
    {
      struct frec *f = &ftab[i];
      if (f->new_id && (now - f->time >= wait_timeout) && f->packet_size)
	forward_reply(f, f->packet, f->packet_size);
    }
}

static int recvto(int s, void *buf, size_t len, int flags,
		  struct sockaddr *from, socklen_t *fromlen,
		  union mysockaddr *to,
		  unsigned int *ifindex)
{
  struct iovec iov;
  struct msghdr msg;
  union {
    struct cmsghdr hdr;
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#ifdef HAVE_IPV6
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif
  } control;
  struct cmsghdr *cmsg;
  int ret;

  iov.iov_base = buf;
  iov.iov_len = len;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = from;
  msg.msg_namelen = fromlen ? *fromlen: 0;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;
  msg.msg_control = &control;
  msg.msg_controllen = sizeof(control);

  ret = recvmsg(s, &msg, flags);
  if (ret == -1)
    return ret;

  if (fromlen)
    *fromlen = msg.msg_namelen;

  for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
      if (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_PKTINFO)
	{
	  struct in_pktinfo *pkt;

	  pkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
	  if (to)
	    {
	      to->in.sin_family = AF_INET;
	      to->in.sin_addr = pkt->ipi_addr;
	    }
	  if (ifindex)
	    *ifindex = pkt->ipi_ifindex;

	  return ret;
	}
#ifdef HAVE_IPV6
      else if (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
	{
	  struct in6_pktinfo *pkt;

	  pkt = (struct in6_pktinfo *)CMSG_DATA(cmsg);
	  if (to)
	    {
	      to->in6.sin6_family = AF_INET6;
	      to->in6.sin6_addr = pkt->ipi6_addr;
	    }
	  if (ifindex)
	    *ifindex = pkt->ipi6_ifindex;

	  return ret;
	}
#endif
    }

  if (to)
    to->sa.sa_family = AF_UNSPEC;
  if (ifindex)
    *ifindex = 0;

  return ret;
}

static int sendfrom(int s, void *buf, size_t len, int flags,
    		    struct sockaddr *to, socklen_t tolen,
		    union mysockaddr *from,
		    unsigned int ifindex)
{
  struct iovec iov;
  struct msghdr msg;
  union {
    struct cmsghdr hdr;
    char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
#ifdef HAVE_IPV6
    char control6[CMSG_SPACE(sizeof(struct in6_pktinfo))];
#endif
  } control;
  struct cmsghdr *cmsg;

  iov.iov_base = buf;
  iov.iov_len = len;

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = to;
  msg.msg_namelen = tolen;
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  msg.msg_flags = 0;

  if (from->sa.sa_family == AF_INET)
    {
      struct in_pktinfo *pkt;

      memset(&control, 0, sizeof(control));
      msg.msg_control = &control;
      msg.msg_controllen = CMSG_LEN(sizeof(*pkt));

      cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));
      cmsg->cmsg_level = SOL_IP;
      cmsg->cmsg_type = IP_PKTINFO;

      pkt = (struct in_pktinfo *)CMSG_DATA(cmsg);
      pkt->ipi_ifindex = ifindex;
      pkt->ipi_spec_dst = from->in.sin_addr;
    }
#ifdef HAVE_IPV6
  else if (from->sa.sa_family == AF_INET6)
    {
      struct in6_pktinfo *pkt;

      memset(&control, 0, sizeof(control));
      msg.msg_control = &control;
      msg.msg_controllen = CMSG_LEN(sizeof(*pkt));

      cmsg = CMSG_FIRSTHDR(&msg);
      cmsg->cmsg_len = CMSG_LEN(sizeof(*pkt));
      cmsg->cmsg_level = SOL_IPV6;
      cmsg->cmsg_type = IPV6_PKTINFO;

      pkt = (struct in6_pktinfo *)CMSG_DATA(cmsg);
      pkt->ipi6_ifindex = ifindex;
      pkt->ipi6_addr = from->in6.sin6_addr;
    }
#endif
  else
    {
      msg.msg_control = NULL;
      msg.msg_controllen = 0;
    }

  return sendmsg(s, &msg, flags);
}

static void die(const char *message, ...)
{
	va_list ap;

	va_start(ap, message);
  
  fprintf(stderr, "dnsmasq: ");
  vfprintf(stderr, message, ap);
  fprintf(stderr, "\n");
  
  vsyslog(LOG_CRIT, message, ap);
  syslog(LOG_CRIT, "FAILED to start up");
  exit(1);
}
