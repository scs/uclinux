
/***********************************************************************
 * nmap.h -- Currently handles some of Nmap's port scanning            *
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

/* $Id: nmap.h,v 1.1 2003/02/24 14:46:18 renaud Exp $ */

#ifndef NMAP_H
#define NMAP_H

#include <includes.h>

/************************INCLUDES**********************************/

#ifdef WIN32
#include "mswin32\winclude.h"
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#ifdef WIN32
#include "nmap_winconfig.h"
#endif				/* WIN32 */
#endif				/* HAVE_CONFIG_H */



#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef STDC_HEADERS
#include <stdlib.h>
#else
void *malloc();
void *realloc();
#endif

#if STDC_HEADERS || HAVE_STRING_H
#include <string.h>
#if !STDC_HEADERS && HAVE_MEMORY_H
#include <memory.h>
#endif
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#endif

#ifdef HAVE_BSTRING_H
#include <bstring.h>
#endif

#include <ctype.h>
#include <sys/types.h>

#ifndef WIN32			/* from nmapNT -- seems to work */
#include <sys/wait.h>
#endif				/* !WIN32 */

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>		/* Defines MAXHOSTNAMELEN on BSD */
#endif

/* Linux uses these defines in netinet/ip.h and netinet/tcp.h to
   use the correct struct ip and struct tcphdr */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef __USE_BSD
#define __USE_BSD
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif

/* BSDI needs this to insure the correct struct ip */
#undef _IP_VHL

#if HAVE_STRINGS_H
#include <strings.h>
#endif

#include <stdio.h>

#if HAVE_RPC_TYPES_H
#include <rpc/types.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <sys/stat.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <errno.h>

#if HAVE_NETDB_H
#include <netdb.h>
#endif

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <fcntl.h>
#include <stdarg.h>

#ifdef HAVE_PWD_H
#include <pwd.h>
#endif

#ifndef NETINET_IN_SYSTEM_H	/* why the HELL does OpenBSD not do this? */
#include <netinet/in_systm.h>	/* defines n_long needed for netinet/ip.h */
#define NETINET_IN_SYSTEM_H
#endif
#ifndef NETINET_IP_H		/* why the HELL does OpenBSD not do this? */
#include <netinet/ip.h>
#define NETINET_IP_H
#endif
#include <netinet/ip_icmp.h>

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <math.h>
#include <assert.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H		/* why the HELL does OpenBSD not do this? */
#include <netinet/tcp.h>	/*#include <netinet/ip_tcp.h> */
#define NETINET_TCP_H
#endif

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

			    /*#include <net/if_arp.h> *//* defines struct arphdr needed for if_ether.h */
#ifndef NET_IF_H		/* why the HELL does OpenBSD not do this? */
#include <net/if.h>
#define NET_IF_H
#endif
#if HAVE_NETINET_IF_ETHER_H
#ifndef NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#define NETINET_IF_ETHER_H
#endif				/* NETINET_IF_ETHER_H */
#endif				/* HAVE_NETINET_IF_ETHER_H */

/*******  DEFINES  ************/

/* User configurable #defines: */
#ifndef VERSION
#define VERSION "1.60-Beta"
#endif
#ifndef DEBUGGING
#define DEBUGGING 0
#endif
/* Default number of ports in parallel.  Doesn't always involve actual 
   sockets.  Can also adjust with the -M command line option.  */
#define MAX_SOCKETS 36
/* As an optimisation we limit the maximum value of MAX_SOCKETS to a very
   high value (avoids dynamic memmory allocation */
#define MAX_SOCKETS_ALLOWED 1025
/* How many hosts do we ping in parallel to see if they are up? */
#define LOOKAHEAD 25
/* If reads of a UDP port keep returning EAGAIN (errno 13), do we want to 
   count the port as valid? */
#define RISKY_UDP_SCAN 0
/* How many syn packets do we send to TCP sequence a host? */
#define NUM_SEQ_SAMPLES 6
 /* This ideally should be a port that isn't in use for any protocol on our machine or on the target */
#define MAGIC_PORT 49724
/* How many udp sends without a ICMP port unreachable error does it take before we consider the port open? */
#define UDP_MAX_PORT_RETRIES 4
 /*How many seconds before we give up on a host being alive? */

#define FAKE_ARGV "pine"	/* What ps and w should show if you use -q */
/* How do we want to log into ftp sites for */
#define FTPUSER "anonymous"
#define FTPPASS "-wwwuser@"
#define FTP_RETRIES 2		/* How many times should we relogin if we lose control
				   connection? */
#define MAX_TIMEOUTS MAX_SOCKETS	/* How many timed out connection attempts 
					   in a row before we decide the host is 
					   dead? */
#define DEFAULT_TCP_PROBE_PORT 80	/* The port TCP probes go to if unspecified
					   by user -- uber hackers change this
					   to 113 */

#define MAX_DECOYS 128		/* How many decoys are allowed? */

#ifndef MAX_RTT_TIMEOUT
#define MAX_RTT_TIMEOUT 10000	/* Never allow more than 10 secs for packet round
				   trip */
#endif

#ifndef MIN_RTT_TIMEOUT
#define MIN_RTT_TIMEOUT 300	/* We will always wait at least 300 ms for a response */
#endif

#define INITIAL_RTT_TIMEOUT 6000	/* Allow 6 seconds at first for packet responses */
#define HOST_TIMEOUT    0	/* By default allow unlimited time to scan each host */

/* If nmap is called with one of the names below, it will start up in interactive mode -- alternatively, you can rename Nmap any of the following names to have it start up interactivey by default.  */
#define INTERACTIVE_NAMES { "BitchX", "Calendar", "X", "awk", "bash", "bash2", "calendar", "cat", "csh", "elm", "emacs", "ftp", "fvwm", "g++", "gcc", "gimp", "httpd", "irc", "man", "mutt", "nc", "ncftp", "netscape", "perl", "pine", "ping", "sleep", "slirp", "ssh", "sshd", "startx", "tcsh", "telnet", "telnetd", "tia", "top", "vi", "vim", "xdvi", "xemacs", "xterm", "xv" }

/* Number of hosts we pre-ping and then scan.  We do a lot more if
   randomize_hosts is set.  Every one you add to this leads to ~1K of
   extra always-resident memory in nmap */
#define HOST_GROUP_SZ 256

/* DO NOT change stuff after this point */
#define UC(b)   (((int)b)&0xff)
#define SA    struct sockaddr	/*Ubertechnique from R. Stevens */

#define HOST_UP 1
#define HOST_DOWN 2
#define HOST_FIREWALLED 4
#define HOST_BROADCAST 8	/* use the wierd_responses member of hoststruct instead */

#define PINGTYPE_UNKNOWN 0
#define PINGTYPE_NONE 1
#define PINGTYPE_ICMP_PING 2
#define PINGTYPE_ICMP_MASK 4
#define PINGTYPE_ICMP_TS 8
#define PINGTYPE_TCP  16
#define PINGTYPE_TCP_USE_ACK 32
#define PINGTYPE_TCP_USE_SYN 64
#define PINGTYPE_RAWTCP 128
#define PINGTYPE_CONNECTTCP 256

/* TCP/IP ISN sequence prediction classes */
#define SEQ_UNKNOWN 0
#define SEQ_64K 1
#define SEQ_TD 2
#define SEQ_RI 4
#define SEQ_TR 8
#define SEQ_i800 16
#define SEQ_CONSTANT 32

/* TCP Timestamp Sequence */
#define TS_SEQ_UNKNOWN 0
#define TS_SEQ_ZERO 1		/* At least one of the timestamps we received back was 0 */
#define TS_SEQ_2HZ 2
#define TS_SEQ_100HZ 3
#define TS_SEQ_1000HZ 4
#define TS_SEQ_UNSUPPORTED 5	/* System didn't send back a timestamp */

#define IPID_SEQ_UNKNOWN 0
#define IPID_SEQ_INCR 1		/* simple increment by one each time */
#define IPID_SEQ_BROKEN_INCR 2	/* Stupid MS -- forgot htons() so it 
				   counts by 256 on little-endian platforms */
#define IPID_SEQ_RPI 3		/* Goes up each time but by a "random" positive 
				   increment */
#define IPID_SEQ_RD 4		/* Appears to select IPID using a "random" distributions (meaning it can go up or down) */
#define IPID_SEQ_CONSTANT 5	/* Contains 1 or more sequential duplicates */
#define IPID_SEQ_ZERO 6		/* Every packet that comes back has an IP.ID of 0 (eg Linux 2.4 does this) */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#ifndef BSDFIX
#if FREEBSD || BSDI || NETBSD
#define BSDFIX(x) x
#define BSDUFIX(x) x
#else
#define BSDFIX(x) htons(x)
#define BSDUFIX(x) ntohs(x)
#endif
#endif				/* BSDFIX */

/* Funny story about this one in /usr/include/apache/ap_config.h */
#if defined(AIX)
#  if AIX >= 42
#    define NET_SIZE_T size_t
#  endif
#elif defined(LINUX)
#  if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ > 0))
#  define NET_SIZE_T socklen_t
#  endif
#elif defined(SEQUENT)
#  if SEQUENT < 44
#    define NO_KILLPG 1
#    define NET_SIZE_T int
#  endif
#  if SEQUENT >= 44
#    undef NO_KILLPG
#    define NET_SIZE_T size_t
#  endif
#elif defined(SVR4)
#  define NET_SIZE_T size_t
#elif defined(UW)
#  define NET_SIZE_T size_t
#elif defined(__FreeBSD__)
  /* XXX: Apache didn't have this one,
     so watch it be wrong :)... */
#  define NET_SIZE_T size_t
#elif defined(OS390)
#  define NET_SIZE_T size_t
#endif

#ifndef NET_SIZE_T
#  define NET_SIZE_T int
#endif

/********************** LOCAL INCLUDES *****************************/


#include "output.h"
#include "portlist.h"
#include "tcpip.h"
#include "global_structures.h"
#include "nmap_error.h"
#include "utils.h"
#include "targets.h"


/***********************STRUCTURES**********************************/

/* Moved to global_structures.h */

/***********************PROTOTYPES**********************************/

/* print usage information and exit */
void printusage(char *name, int rc);

/* Scan helper functions */
unsigned long calculate_sleep(struct in_addr target);

/* Renamed main so that interactive mode could preprocess when neccessary */
int nmap_main(int, int, char *, struct arglist *);

/* general helper functions */
void *safe_malloc(int size);
char *grab_next_host_spec(char *);
int parse_targets(struct targets *targets, char *h);
void options_init();
void sigdie(int signo);
void reaper(int signo);

/* Convert a TCP sequence prediction difficulty index like 1264386
   into a difficulty string like "Worthy Challenge */
const char *seqidx2difficultystr(unsigned long idx);
int fileexistsandisreadable(char *pathname);

/* From glibc 2.0.6 because Solaris doesn't seem to have this function */
#ifndef HAVE_INET_ATON
int inet_aton(register const char *, struct in_addr *);
#endif

/* Sets a pcap filter function -- makes SOCK_RAW reads easier */
#ifndef WINIP_H
typedef int (*PFILTERFN) (const char *packet, int len);	/* 1 to keep */
void set_pcap_filter(struct hoststruct *target, pcap_t * pd, PFILTERFN filter, char *bpf, ...);
#endif

int flt_icmptcp(const char *packet, int len);
int flt_icmptcp_2port(const char *packet, int len);
int flt_icmptcp_5port(const char *packet, int len);

#endif				/* NMAP_H */
