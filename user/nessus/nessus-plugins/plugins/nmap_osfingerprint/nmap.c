
/***********************************************************************
* nmap.c -- Currently handles some of Nmap's port scanning            *
* features as well as the command line user interface.  Note that the *
* actual main() function is in main.c                                 *
*                                                                     *
***********************************************************************
*  The Nmap Security Scanner is (C) 1995-2001 Insecure.Com LLC. This  *
*  program is free software; you can redistribute it and/or modify    *
*  it under the terms of the GNU General Public License as published  *
*  by the Free Software Foundation; Version 2.  This guarantees your  *
*  right to use, modify, and redistribute this software under certain *
*  conditions.  If this license is unacceptable to you, we may be     *
*  willing to sell alternative licenses (contact sales@insecure.com). *
*                                                                     *
*  If you received these files with a written license agreement       *
*  stating terms other than the (GPL) terms above, then that          *
*  alternative license agreement takes precendence over this comment. *
*                                                                     *
*  Source is provided to this software because we believe users have  *
*  a right to know exactly what a program is going to do before they  *
*  run it.  This also allows you to audit the software for security   *
*  holes (none have been found so far).                               *
*                                                                     *
*  Source code also allows you to port Nmap to new platforms, fix     *
*  bugs, and add new features.  You are highly encouraged to send     *
*  your changes to fyodor@insecure.org for possible incorporation     *
*  into the main distribution.  By sending these changes to Fyodor or *
*  one the insecure.org development mailing lists, it is assumed that *
*  you are offering Fyodor the unlimited, non-exclusive right to      *
*  reuse, modify, and relicense the code.  This is important because  *
*  the inability to relicense code has caused devastating problems    *
*  for other Free Software projects (such as KDE and NASM).  Nmap     *
*  will always be available Open Source.  If you wish to specify      *
*  special license conditions of your contributions, just say so      *
*  when you send them.                                                *
*                                                                     *
*  This program is distributed in the hope that it will be useful,    *
*  but WITHOUT ANY WARRANTY; without even the implied warranty of     *
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  *
*  General Public License for more details (                          *
*  http://www.gnu.org/copyleft/gpl.html ).                            *
*                                                                     *
***********************************************************************/

/* $Id: nmap.c,v 1.2 2003/10/01 16:00:11 renaud Exp $ */

#include "nmap.h"
#include "osscan.h"
#include "timing.h"

/* global options */
struct ops o;			/* option structure */

int nmap_main(int iopenport, int iclosedport, char * host, struct arglist * desc)
{
	int i;
	FILE *fp;
	int numhosts_scanned = 0;
	char **host_exp_group;
	int num_host_exp_groups = 0;
	struct hostgroup_state hstate;
	int numhosts_up = 0;
	int starttime;
	char myname[MAXHOSTNAMELEN + 1];
	struct hostent *target = NULL;
	struct hoststruct *currenths;
	char emptystring[1];
	int sourceaddrwarning = 0;	/* Have we warned them yet about unguessable
					   source addresses? */
	time_t timep;
	u16 closedport = iclosedport;
	u16 openport = iopenport;
	
	
	

	

	emptystring[0] = '\0';	/* It wouldn't be an emptystring w/o this ;) */

	

	

	/* Now we check the option sanity */
	/* Insure that at least one scantype is selected */

	/* By now, we've got our port lists.  Give the user a warning if no
	 * ports are specified for the type of scan being requested.  Other things
	 * (such as OS ident scan) might break cause no ports were specified,  but
	 * we've given our warning...
	 */

	assert(o.osscan);	/*Always On */
	
	/*Test if nmap-os-fingerprints file available*/	
	fp=fetch_fingerprint_file();
	if(fp==NULL) {
		fatal("can not find nmap-os-fingerprints file");
	} else {
		fclose(fp);
	}

	if ((openport == 0) || (closedport == 0)) {

		fatal("openport/closedport can not be zero");
	}

	/* We start with stuff users should not do if they are not root */
	if (!o.isr00t) {
		fatal("TCP/IP fingerprinting (for OS scan) requires root privileges which you do not appear to possess.  Sorry, dude.\n");
	}

	/* We need to find what interface to route through if:
	 * --None have been specified AND
	 * --We are root and doing tcp ping OR
	 * --We are doing a raw sock scan and NOT pinging anyone */
	if (o.source && !*o.device) {
		if (ipaddr2devname(o.device, o.source) != 0) {
			fatal
			    ("Could not figure out what device to send the packet out on with the source address you gave me!  If you are trying to sp00f your scan, this is normal, just give the -e eth0 or -e ppp0 or whatever.  Otherwise you can still use -e, but I find it kindof fishy.");
		}
	}

	if (*o.device && !o.source) {
		o.source = (struct in_addr *) safe_malloc(sizeof(struct in_addr));
		if (devname2ipaddr(o.device, o.source) == -1) {
			fatal("I cannot figure out what source address to use for device %s, does it even exist?", o.device);
		}
	}

	/* Set up our array of decoys! */
	if (o.decoyturn == -1) {
		o.decoyturn = (o.numdecoys == 0) ? 0 : get_random_uint() % o.numdecoys;
		o.numdecoys++;
		for (i = o.numdecoys - 1; i > o.decoyturn; i--)
			o.decoys[i] = o.decoys[i - 1];
	}

	timep = time(NULL);

#if HAVE_SIGNAL
	signal(SIGPIPE, SIG_IGN);	/* ignore SIGPIPE so our program doesn't crash because
					   of it, but we really shouldn't get an unsuspected
					   SIGPIPE */
#endif

	starttime = time(NULL);

	/* Time to create a hostgroup state object filled with all the requested
	   machines */
	host_exp_group = (char **) safe_malloc(o.host_group_sz * sizeof(char *));

	do {
		num_host_exp_groups = 0;
		host_exp_group[0] = strdup(host);
		num_host_exp_groups++;
		if (num_host_exp_groups == 0)
			break;

		hostgroup_state_init(&hstate, o.host_group_sz, o.randomize_hosts, host_exp_group, num_host_exp_groups);

		while ((currenths = nexthost(&hstate, NULL, &(o.pingtype)))) {
			numhosts_scanned++;
			if (currenths->flags & HOST_UP && !o.listscan)
				numhosts_up++;

			/* Set timeout info */
			currenths->timedout = 0;
			if (o.host_timeout) {
				gettimeofday(&currenths->host_timeout, NULL);

				/* Must go through all this to avoid int overflow */
				currenths->host_timeout.tv_sec += o.host_timeout / 1000;
				currenths->host_timeout.tv_usec += (o.host_timeout % 1000) * 1000;
				currenths->host_timeout.tv_sec += currenths->host_timeout.tv_usec / 1000000;
				currenths->host_timeout.tv_usec %= 1000000;
			}

			/*    printf("Nexthost() returned: %s\n", inet_ntoa(currenths->host)); */
			target = NULL;
			if (((currenths->flags & HOST_UP)) && !o.noresolve)
				target = gethostbyaddr((char *) &currenths->host, 4, AF_INET);
			if (target && *target->h_name) {
				currenths->name = strdup(target->h_name);
			} else {
				currenths->name = emptystring;
			}

			if (!currenths->source_ip.s_addr) {
				if (gethostname(myname, MAXHOSTNAMELEN)
				    || !(target = gethostbyname(myname)))
					fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n");
				memcpy(&currenths->source_ip, target->h_addr_list[0], sizeof(struct in_addr));
				if (!sourceaddrwarning) {
					fprintf(stderr,
						"WARNING:  We could not determine for sure which interface to use, so we are guessing %s .  If this is wrong, use -S <my_IP_address>.\n",
						inet_ntoa(currenths->source_ip));
					sourceaddrwarning = 1;
				}
			}

			/* Figure out what link-layer device (interface) to use (ie eth0, ppp0, etc) */
			if (!*currenths->device && currenths->flags & HOST_UP && (ipaddr2devname(currenths->device, &currenths->source_ip) != 0))
				fatal
				    ("Could not figure out what device to send the packet out on!  You might possibly want to try -S (but this is probably a bigger problem).  If you are trying to sp00f the source of a SYN/FIN scan with -S <fakeip>, then you must use -e eth0 (or other devicename) to tell us what interface to use.\n");

			/* Set up the decoy */
			o.decoys[o.decoyturn] = currenths->source_ip;

			/* Time for some actual scanning! */
			assert(o.osscan && (openport != 0) && (closedport != 0));
			addport(&currenths->ports, openport, IPPROTO_TCP, NULL, PORT_OPEN);

			addport(&currenths->ports, closedport, IPPROTO_TCP, NULL, PORT_CLOSED);
			os_scan(currenths);
			resetportlist(&currenths->ports);

			if (currenths->timedout) {
				log_write(LOG_NORMAL | LOG_SKID | LOG_STDOUT, "Skipping host  %s (%s) due to host timeout\n", currenths->name, inet_ntoa(currenths->host));

				log_write(LOG_MACHINE, "Host: %s (%s)\tStatus: Timeout", inet_ntoa(currenths->host), currenths->name);
			} else {
				printosscanoutput(currenths, desc);
			}


			log_flush_all();
			hoststruct_free(currenths);
		} 

		hostgroup_state_destroy(&hstate);

		/* Free my host expressions */
		for (i = 0; i < num_host_exp_groups; i++)
			free(host_exp_group[i]);
		num_host_exp_groups = 0;
	} while(0);

	free(host_exp_group);

	

	return 0;
}

void options_init()
{

	bzero((char *) &o, sizeof(struct ops));

	o.isr00t = !(geteuid());

	o.debugging = DEBUGGING;
	o.verbose = DEBUGGING;
	/*o.max_parallelism = MAX_SOCKETS; */
	o.magic_port = 33000 + (get_random_uint() % 31000);
	o.pingtype = PINGTYPE_UNKNOWN;
	o.decoyturn = -1;
	o.nmap_stdout = stdout;
	o.host_group_sz = HOST_GROUP_SZ;
	o.min_rtt_timeout = MIN_RTT_TIMEOUT;
	o.max_rtt_timeout = MAX_RTT_TIMEOUT;
	o.initial_rtt_timeout = INITIAL_RTT_TIMEOUT;
	o.host_timeout = HOST_TIMEOUT;
	o.scan_delay = 0;
	o.scanflags = -1;
	o.extra_payload_length = 0;
	o.extra_payload = NULL;
	o.tcp_probe_port = DEFAULT_TCP_PROBE_PORT;
	o.osscan = 1;		/*It`s os fingerprint tool, right? */
}


void printusage(char *name, int rc)
{
	printf("osfinger V. %s Usage: osfinger --openport <opentcpport> --closedport <closedtcpport> <host or net list>\n"
	       "Example: osfinger -v --openport 22 --closedport 5999 www.my.com 192.168.0.0/16 '192.88-90.*.*'\n"
	       "SEE THE MAN PAGE FOR MANY MORE OPTIONS, DESCRIPTIONS, AND EXAMPLES \n", NMAP_VERSION);
	exit(rc);
}


char *grab_next_host_spec(char * target)
{
	return (target); /* Duh */
}

void reaper(int signo)
{
	int status;
	pid_t pid;

	if ((pid = wait(&status)) == -1) {
		gh_perror("waiting to reap child");
	} else {
		fprintf(stderr, "\n[%d finished status=%d (%s)]\nnmap> ", (int) pid, status, (status == 0) ? "success" : "failure");
	}
}

void sigdie(int signo)
{
	switch (signo) {
	case SIGINT:
		fprintf(stderr, "caught SIGINT signal, cleaning up\n");
		break;
	case SIGTERM:
		fprintf(stderr, "caught SIGTERM signal, cleaning up\n");
		break;
	case SIGHUP:
		fprintf(stderr, "caught SIGHUP signal, cleaning up\n");
		break;
	case SIGSEGV:
		fprintf(stderr, "caught SIGSEGV signal, cleaning up\n");
		if (o.debugging)
			abort();
		break;
	case SIGBUS:
		fprintf(stderr, "caught SIGBUS signal, cleaning up\n");
		break;
	default:
		fprintf(stderr, "caught signal %d, cleaning up\n", signo);
		break;
	}
	fflush(stdout);
	log_close(LOG_MACHINE | LOG_NORMAL | LOG_SKID);
	exit(1);
}
