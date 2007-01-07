
/***********************************************************************
 * tcpip.h -- Various functions relating to low level TCP/IP handling, *
 * including sending raw packets, routing, printing packets, reading   *
 * from libpcap, etc.                                                  *
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

/* $Id: tcpip.h,v 1.1 2003/02/24 14:46:20 renaud Exp $ */


#ifndef TCPIP_H
#define TCPIP_H

#include <includes.h>



#ifdef WIN32
#include "mswin32\winclude.h"
#else

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

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>		/* Defines MAXHOSTNAMELEN on BSD */
#endif

/* Linux uses these defines in netinet/ip.h and netinet/tcp.h to
   use the correct struct ip and struct tcphdr */
#ifndef __FAVOR_BSD
#define __FAVOR_BSD 1
#endif
#ifndef __BSD_SOURCE
#define __BSD_SOURCE 1
#endif
#ifndef __USE_BSD
#define __USE_BSD 1
#endif
/* BSDI needs this to insure the correct struct ip */
#undef _IP_VHL

#include <stdio.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_RPC_TYPES_H
#include <rpc/types.h>
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#include <arpa/inet.h>
#ifndef NETINET_IN_SYSTEM_H	/* why the HELL does OpenBSD not do this? */
#include <netinet/in_systm.h>	/* defines n_long needed for netinet/ip.h */
#define NETINET_IN_SYSTEM_H
#endif
#ifndef NETINET_IP_H		/* why the HELL does OpenBSD not do this? */
#include <netinet/ip.h>
#define NETINET_IP_H
#endif
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#ifndef NETINET_TCP_H		/* why the HELL does OpenBSD not do this? */
#include <netinet/tcp.h>	/*#include <netinet/ip_tcp.h> */
#define NETINET_TCP_H
#endif
#ifndef NETINET_UDP_H
#include <netinet/udp.h>
#define NETINET_UDP_H
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <fcntl.h>
#ifndef NET_IF_H		/* why the HELL does OpenBSD not do this? */
#include <sys/socket.h>
#include <net/if.h>
#define NET_IF_H
#endif
#if HAVE_NETINET_IF_ETHER_H
#ifndef NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#define NETINET_IF_ETHER_H
#endif				/* NETINET_IF_ETHER_H */
#endif				/* HAVE_NETINET_IF_ETHER_H */

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

#include <sys/ioctl.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <pcap.h>
#ifdef __cplusplus
}
#endif
#include <setjmp.h>
#include <errno.h>
#include <signal.h>
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>		/* SIOCGIFCONF for Solaris */
#endif
#endif				/* WIN32 */
#include "nmap_error.h"
#include "utils.h"
#include "nmap.h"
#include "global_structures.h"
#ifndef DEBUGGING
#define DEBUGGING 0
#endif
#ifndef TCPIP_DEBUGGING
#define TCPIP_DEBUGGING 0
#endif
#ifndef BSDFIX
#if FREEBSD || BSDI || NETBSD
#define BSDFIX(x) x
#define BSDUFIX(x) x
#else
#define BSDFIX(x) htons(x)
#define BSDUFIX(x) ntohs(x)
#endif
#endif
/* Bogus TCP flag!!!  Krad! */
#define TH_BOGUS 64
#define TH_BOG 64
#define MORE_FRAGMENTS 8192	/*NOT a user serviceable parameter */
struct interface_info {
	char name[64];
	struct in_addr addr;
};




#ifndef HAVE_STRUCT_IP
#define HAVE_STRUCT_IP

/* From Linux glibc, which apparently borrowed it from
   BSD code.  Slightly modified for portability --fyodor@insecure.org */
/*
 * Structure of an internet header, naked of options.
 */
struct ip {
#if WORDS_BIGENDIAN
	u_int8_t ip_v:4;	/* version */
	u_int8_t ip_hl:4;	/* header length */
#else
	u_int8_t ip_hl:4;	/* header length */
	u_int8_t ip_v:4;	/* version */
#endif
	u_int8_t ip_tos;	/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_int8_t ip_ttl;	/* time to live */
	u_int8_t ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src, ip_dst;	/* source and dest address */
};

#endif				/* HAVE_STRUCT_IP */

#ifdef LINUX
typedef struct udphdr_bsd {
	unsigned short uh_sport;	/* source port */
	unsigned short uh_dport;	/* destination port */
	unsigned short uh_ulen;	/* udp length */
	unsigned short uh_sum;	/* udp checksum */
} udphdr_bsd;
#else
typedef struct udphdr udphdr_bsd;
#endif


#ifndef HAVE_STRUCT_ICMP
#define HAVE_STRUCT_ICMP
/* From Linux /usr/include/netinet/ip_icmp.h GLIBC */

/*
 * Internal of an ICMP Router Advertisement
 */
struct icmp_ra_addr {
	u_int32_t ira_addr;
	u_int32_t ira_preference;
};

struct icmp {
	u_int8_t icmp_type;	/* type of message, see below */
	u_int8_t icmp_code;	/* type sub code */
	u_int16_t icmp_cksum;	/* ones complement checksum of struct */
	union {
		u_char ih_pptr;	/* ICMP_PARAMPROB */
		struct in_addr ih_gwaddr;	/* gateway address */
		struct ih_idseq {	/* echo datagram */
			u_int16_t icd_id;
			u_int16_t icd_seq;
		} ih_idseq;
		u_int32_t ih_void;

		/* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
		struct ih_pmtu {
			u_int16_t ipm_void;
			u_int16_t ipm_nextmtu;
		} ih_pmtu;

		struct ih_rtradv {
			u_int8_t irt_num_addrs;
			u_int8_t irt_wpa;
			u_int16_t irt_lifetime;
		} ih_rtradv;
	} icmp_hun;
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
	union {
		struct {
			u_int32_t its_otime;
			u_int32_t its_rtime;
			u_int32_t its_ttime;
		} id_ts;
		struct {
			struct ip idi_ip;
			/* options and then 64 bits of data */
		} id_ip;
		struct icmp_ra_addr id_radv;
		u_int32_t id_mask;
		u_int8_t id_data[1];
	} icmp_dun;
#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
};
#endif				/* HAVE_STRUCT_ICMP */

 /* This ideally should be a port that isn't in use for any protocol on our machine or on the target */
#define MAGIC_PORT 49724
#define TVAL2LONG(X)  X.tv_sec * 1e6 + X.tv_usec
#define SA struct sockaddr

/* Prototypes */

/* Tries to resolve given hostname and stores
   result in ip .  returns 0 if hostname cannot
   be resolved */
int resolve(char *hostname, struct in_addr *ip);
/* An awesome function to determine what interface a packet to a given
   destination should be routed through.  It returns NULL if no appropriate
   interface is found, oterwise it returns the device name and fills in the
   source parameter */
char *routethrough(struct in_addr *dest, struct in_addr *source);
unsigned short in_cksum(u16 * ptr, int nbytes);
int send_tcp_raw(int sd, struct in_addr *source, struct in_addr *victim, u16 sport, u16 dport, u32 seq, u32 ack, u8 flags, u16 window, u8 * options, int optlen, char *data, u16 datalen);

/* Decoy versions of the raw packet sending functions ... */
int send_tcp_raw_decoys(int sd, struct in_addr *victim, u16 sport, u16 dport, u32 seq, u32 ack, u8 flags, u16 window, u8 * options, int optlen, u8 * data, u16 datalen);

int send_udp_raw_decoys(int sd, struct in_addr *victim, u16 sport, u16 dport, u8 * data, u16 datalen);


/* Calls pcap_open_live and spits out an error (and quits) if the call fails.
   So a valid pcap_t will always be returned. */
pcap_t *my_pcap_open_live(char *device, int snaplen, int promisc, int to_ms);

/* Convert an IP address to the device (IE ppp0 eth0) using that address */
int ipaddr2devname(char *dev, struct in_addr *addr);
/* And vice versa */
int devname2ipaddr(char *dev, struct in_addr *addr);
/* Where the above 2 functions get their info */
struct interface_info *getinterfaces(int *howmany);
void sethdrinclude(int sd);
int getsourceip(struct in_addr *src, struct in_addr *dst);
/* Get the source IP and interface name that a packet
   to dst should be sent to.  Interface name is dynamically
   assigned and thus should be freed */
char *getsourceif(struct in_addr *src, struct in_addr *dst);
int islocalhost(struct in_addr *addr);
int unblock_socket(int sd);
int Sendto(char *functionname, int sd, const unsigned char *packet, int len, unsigned int flags, struct sockaddr *to, int tolen);
/* Standard swiped internet checksum routine */
unsigned short in_cksum(unsigned short *ptr, int nbytes);
/* Hex dump */
int get_link_offset(char *device);
char *readip_pcap(pcap_t * pd, unsigned int *len, long to_usec);
#ifndef HAVE_INET_ATON
int inet_aton(register const char *, struct in_addr *);
#endif

/* Examines the given tcp packet and obtains the TCP timestamp option
   information if available.  Note that the CALLER must ensure that
   "tcp" contains a valid header (in particular the th_off must be the
   true packet length and tcp must contain it).  If a valid timestamp
   option is found in the header, nonzero is returned and the
   'timestamp' and 'echots' parameters are filled in with the
   appropriate value (if non-null).  Otherwise 0 is returned and the
   parameters (if non-null) are filled with 0.  Remember that the
   correct way to check for errors is to look at the return value
   since a zero ts or echots could possibly be valid. */
int gettcpopt_ts(struct tcphdr *tcp, u32 * timestamp, u32 * echots);

/* Maximize the receive buffer of a socket descriptor (up to 500K) */
void max_rcvbuf(int sd);

/* Maximize the open file descriptor limit for this process go up to the
   max allowed  */
int max_sd();

/* Convert a socket to blocking mode */
int block_socket(int sd);

/* Give broadcast permission to a socket */
void broadcast_socket(int sd);

/* Do a receive (recv()) on a socket and stick the results (upt to
   len) into buf .  Give up after 'seconds'.  Returns the number of
   bytes read (or -1 in the case of an error.  It only does one recv
   (it will not keep going until len bytes are read */
int recvtime(int sd, char *buf, int len, int seconds);

/* This attempts to calculate the round trip time (rtt) to a host by timing a
   connect() to a port which isn't listening.  A better approach is to time a
   ping (since it is more likely to get through firewalls (note, this isn't
   always true nowadays --fyodor).  This is now 
   implemented in isup() for users who are root.  */
unsigned long calculate_sleep(struct in_addr target);

#endif				/*TCPIP_H */
