
/***********************************************************************
 * tcpip.c -- Various functions relating to low level TCP/IP handling, *
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

/* $Id: tcpip.c,v 1.4 2003/10/01 16:00:11 renaud Exp $ */


#include "includes.h"
#include "tcpip.h"

#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif

#if HAVE_UNISTD_H
/* #include <sys/unistd.h> */
#include <unistd.h>
#endif

extern struct ops o;

/*  predefined filters -- I need to kill these globals at some pont. */
extern unsigned long flt_dsthost, flt_srchost;
extern unsigned short flt_baseport;

#ifndef WIN32			/* Already defined in wintcpip.c for now */
void sethdrinclude(int sd)
{
#ifdef IP_HDRINCL
	int one = 1;
	setsockopt(sd, IPPROTO_IP, IP_HDRINCL, (const char *) &one, sizeof(one));
#endif
}
#endif				/* WIN32 */

/* Tests whether a packet sent to  IP is LIKELY to route
 through the kernel localhost interface */
#ifndef WIN32			/* This next group of functions are already defined in
				   wintcpip.c for now */
int islocalhost(struct in_addr *addr)
{
	char dev[128];
	/* If it is 0.0.0.0 or starts with 127.0.0.1 then it is
	   probably localhost */
	if ((addr->s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
		return 1;

	if (!addr->s_addr)
		return 1;

	/* If it is the same addy as a local interface, then it is
	   probably localhost */

	if (ipaddr2devname(dev, addr) != -1)
		return 1;

	/* OK, so to a first approximation, this addy is probably not
	   localhost */
	return 0;
}


/* Calls pcap_open_live and spits out an error (and quits) if the call faile.
   So a valid pcap_t will always be returned. */
pcap_t *my_pcap_open_live(char *device, int snaplen, int promisc, int to_ms)
{
	char err0r[PCAP_ERRBUF_SIZE];
	pcap_t *pt;
	if (!((pt = pcap_open_live(device, snaplen, promisc, to_ms, err0r)))) {
		fatal("pcap_open_live: %s\nThere are several possible reasons for this, depending on your operating system:\n"
		      "LINUX: If you are getting Socket type not supported, try modprobe af_packet or recompile your kernel with SOCK_PACKET enabled.\n"
		      "*BSD:  If you are getting device not configured, you need to recompile your kernel with Berkeley Packet Filter support.  If you are getting No such file or directory, try creating the device (eg cd /dev; MAKEDEV <device>; or use mknod).\n"
		      "SOLARIS:  If you are trying to scan localhost and getting '/dev/lo0: No such file or directory', complain to Sun.  I don't think Solaris can support advanced localhost scans.  You can probably use \"-P0 -sT localhost\" though.\n\n",
		      err0r);
	}
	return pt;
}

/* Standard BSD internet checksum routine */
unsigned short in_cksum(u16 * ptr, int nbytes)
{

	register u32 sum;
	u16 oddbyte;
	register u16 answer;

/*
 * Our algorithm is simple, using a 32-bit accumulator (sum),
 * we add sequential 16-bit words to it, and at the end, fold back
 * all the carry bits from the top 16 bits into the lower 16 bits.
 */

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}

/* mop up an odd byte, if necessary */
	if (nbytes == 1) {
		oddbyte = 0;	/* make sure top half is zero */
		*((u_char *) & oddbyte) = *(u_char *) ptr;	/* one byte only */
		sum += oddbyte;
	}

/*
 * Add back carry outs from top 16 bits to low 16 bits.
 */

	sum = (sum >> 16) + (sum & 0xffff);	/* add high-16 to low-16 */
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;		/* ones-complement, then truncate to 16 bits */
	return (answer);
}




/* Tries to resolve given hostname and stores
   result in ip .  returns 0 if hostname cannot
   be resolved */
int resolve(char *hostname, struct in_addr *ip)
{
	struct hostent *h;

	if (!hostname || !*hostname)
		fatal("NULL or zero-length hostname passed to resolve()");

	if (inet_aton(hostname, ip))
		return 1;	/* damn, that was easy ;) */
	if ((h = gethostbyname(hostname))) {
		memcpy(ip, h->h_addr_list[0], sizeof(struct in_addr));
		return 1;
	}
	return 0;
}

int send_tcp_raw_decoys(int sd, struct in_addr *victim, u16 sport, u16 dport, u32 seq, u32 ack, u8 flags, u16 window, u8 * options, int optlen, u8 * data, u16 datalen)
{
	int decoy;

	for (decoy = 0; decoy < o.numdecoys; decoy++)
		if (send_tcp_raw(sd, &o.decoys[decoy], victim, sport, dport, seq, ack, flags, window, options, optlen, data, datalen) == -1)
			return -1;

	return 0;
}


int send_tcp_raw(int sd, struct in_addr *source, struct in_addr *victim, u16 sport, u16 dport, u32 seq, u32 ack, u8 flags, u16 window, u8 * options, int optlen, char *data, u16 datalen)
{

	struct pseudo_header {
		/*for computing TCP checksum, see TCP/IP Illustrated p. 145 */
		u32 s_addy;
		u32 d_addr;
		u8 zer0;
		u8 protocol;
		u16 length;
	};
	u8 *packet = (u8 *) safe_malloc(sizeof(struct ip) + sizeof(struct tcphdr) + optlen + datalen);
	struct ip *ip = (struct ip *) packet;
	struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof(struct ip));
	struct pseudo_header *pseudo = (struct pseudo_header *) (packet + sizeof(struct ip) - sizeof(struct pseudo_header));
	static int myttl = 0;

	/*With these placement we get data and some field alignment so we aren't
	   wasting too much in computing the checksum */
	int res = -1;
	struct sockaddr_in sock;
	char myname[MAXHOSTNAMELEN + 1];
	struct hostent *myhostent = NULL;
	int source_malloced = 0;

/* check that required fields are there and not too silly */
/* We used to check that sport and dport were nonzer0, but scr3w that! */
	if (!victim || sd < 0) {
		fprintf(stderr, "send_tcp_raw: One or more of your parameters suck!\n");
		free(packet);
		return -1;
	}

	if (optlen % 4) {
		fatal("send_tcp_raw called with an option length argument of %d which is illegal because it is not divisible by 4", optlen);
	}


	if (!myttl)
		myttl = (get_random_uint() % 23) + 37;

/* It was a tough decision whether to do this here for every packet
   or let the calling function deal with it.  In the end I grudgingly decided
   to do it here and potentially waste a couple microseconds... */
	sethdrinclude(sd);

/* if they didn't give a source address, fill in our first address */
	if (!source) {
		source_malloced = 1;
		source = (struct in_addr *) safe_malloc(sizeof(struct in_addr));
		if (gethostname(myname, MAXHOSTNAMELEN) || !(myhostent = gethostbyname(myname)))
			fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n");
		memcpy(source, myhostent->h_addr_list[0], sizeof(struct in_addr));
#if ( TCPIP_DEBUGGING )
		printf("We skillfully deduced that your address is %s\n", inet_ntoa(*source));
#endif
	}


/*do we even have to fill out this damn thing?  This is a raw packet,
  after all */
	sock.sin_family = AF_INET;
	sock.sin_port = htons(dport);
	sock.sin_addr.s_addr = victim->s_addr;


	bzero((char *) packet, sizeof(struct ip) + sizeof(struct tcphdr));

	pseudo->s_addy = source->s_addr;
	pseudo->d_addr = victim->s_addr;
	pseudo->protocol = IPPROTO_TCP;
	pseudo->length = htons(sizeof(struct tcphdr) + optlen + datalen);

	tcp->th_sport = htons(sport);
	tcp->th_dport = htons(dport);
	if (seq) {
		tcp->th_seq = htonl(seq);
	} else if (flags & TH_SYN) {
		get_random_bytes(&(tcp->th_seq), 4);
	}

	if (ack)
		tcp->th_ack = htonl(ack);
/*else if (flags & TH_ACK)
  tcp->th_ack = rand() + rand();*/

	tcp->th_off = 5 + (optlen / 4) /*words */ ;
	tcp->th_flags = flags;

	if (window)
		tcp->th_win = htons(window);
	else
		tcp->th_win = htons(1024 * (myttl % 4 + 1));	/* Who cares */

	/* We should probably copy the data over too */
	if (data && datalen)
		memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr) + optlen, data, datalen);
	/* And the options */
	if (optlen) {
		memcpy(packet + sizeof(struct ip) + sizeof(struct tcphdr), options, optlen);
	}
#if STUPID_SOLARIS_CHECKSUM_BUG
	tcp->th_sum = sizeof(struct tcphdr) + optlen + datalen;
#else
	tcp->th_sum = in_cksum((unsigned short *) pseudo, sizeof(struct tcphdr) + optlen + sizeof(struct pseudo_header) + datalen);
#endif
/* Now for the ip header */

	bzero(packet, sizeof(struct ip));
	ip->ip_v = 4;
	ip->ip_hl = 5;
	ip->ip_len = BSDFIX(sizeof(struct ip) + sizeof(struct tcphdr) + optlen + datalen);
	get_random_bytes(&(ip->ip_id), 2);
	ip->ip_ttl = myttl;
	ip->ip_p = IPPROTO_TCP;
	ip->ip_src.s_addr = source->s_addr;
	ip->ip_dst.s_addr = victim->s_addr;
#if HAVE_IP_IP_SUM
	ip->ip_sum = in_cksum((unsigned short *) ip, sizeof(struct ip));
#endif

	res = Sendto("send_tcp_raw", sd, packet, BSDUFIX(ip->ip_len), 0, (struct sockaddr *) &sock, (int) sizeof(struct sockaddr_in));

	if (source_malloced)
		free(source);
	free(packet);
	return res;
}

int Sendto(char *functionname, int sd, const unsigned char *packet, int len, unsigned int flags, struct sockaddr *to, int tolen)
{

	struct sockaddr_in *sin = (struct sockaddr_in *) to;
	int res;
	int retries = 0;
	int sleeptime = 0;

	do {
		if (TCPIP_DEBUGGING > 1) {
			log_write(LOG_STDOUT, "trying sendto(%d, packet, %d, 0, %s, %d)", sd, len, inet_ntoa(sin->sin_addr), tolen);
		}
		if ((res = sendto(sd, (const char *) packet, len, flags, to, tolen)) == -1) {
			error("sendto in %s: sendto(%d, packet, %d, 0, %s, %d) => %s", functionname, sd, len, inet_ntoa(sin->sin_addr), tolen, strerror(errno));
			if (retries > 2 || errno == EPERM)
				return -1;
			sleeptime = 15 * (1 << (2 * retries));
			error("Sleeping %d seconds then retrying", sleeptime);
			fflush(stderr);
			sleep(sleeptime);
		}
		retries++;
	} while (res == -1);

	if (TCPIP_DEBUGGING > 1)
		log_write(LOG_STDOUT, "successfully sent %d bytes of raw_tcp!\n", res);

	return res;
}


int unblock_socket(int sd)
{
	int options;
/*Unblock our socket to prevent recvfrom from blocking forever
  on certain target ports. */
	options = O_NONBLOCK | fcntl(sd, F_GETFL);
	fcntl(sd, F_SETFL, options);
	return 1;
}



#endif				/* WIN32 */

int getsourceip(struct in_addr *src, struct in_addr *dst)
{
	int sd;
	struct sockaddr_in sock;
	NET_SIZE_T socklen = sizeof(struct sockaddr_in);
	u16 p1;
	
	*src = socket_get_next_source_addr();
	if( src->s_addr != INADDR_ANY )
		return 1;

	get_random_bytes(&p1, sizeof(p1));
	if (p1 < 5000)
		p1 += 5000;

	if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Socket troubles");
		return 0;
	}
	sock.sin_family = AF_INET;
	sock.sin_addr = *dst;
	sock.sin_port = htons(p1);
	if (connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) == -1) {
		perror("UDP connect()");
		close(sd);
		return 0;
	}
	bzero(&sock, sizeof(sock));
	if (getsockname(sd, (SA *) & sock, &socklen) == -1) {
		perror("getsockname");
		close(sd);
		return 0;
	}

	src->s_addr = sock.sin_addr.s_addr;
	close(sd);
	return 1;		/* Calling function responsible for checking validity */
}



/* Read an IP packet using libpcap .  We return the packet and take
   a pcap descripter and a pointer to the packet length (which we set
   in the function. If you want a maximum length returned, you
   should specify that in pcap_open_live() */

/* to_usec is the timeout period in microseconds -- use 0 to skip the
   test and -1 to block forever.  Note that we don't interrupt pcap, so
   low values (and 0) degenerate to the timeout specified
   in pcap_open_live()
 */

#ifndef WIN32			/* Windows version of next few funcstions is currently 
				   in wintcpip.c.  Should be merged at some point. */
char *readip_pcap(pcap_t * pd, unsigned int *len, long to_usec)
{
	int offset = -1;
	struct pcap_pkthdr head;
	char *p;
	int datalink;
	int timedout = 0;
	struct timeval tv_start, tv_end;
	static char *alignedbuf = NULL;
	static int alignedbufsz = 0;

	if (!pd)
		fatal("NULL packet device passed to readip_pcap");

/* New packet capture device, need to recompute offset */
	if ((datalink = pcap_datalink(pd)) < 0)
		fatal("Cannot obtain datalink information: %s", pcap_geterr(pd));
	switch (datalink) {
	case DLT_EN10MB:
		offset = 14;
		break;
	case DLT_IEEE802:
		offset = 22;
		break;
#ifdef DLT_LOOP
	case DLT_LOOP:
#endif
	case DLT_NULL:
		offset = 4;
		break;
	case DLT_SLIP:
#ifdef DLT_SLIP_BSDOS
	case DLT_SLIP_BSDOS:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
		offset = 16;
#else
		offset = 24;	/* Anyone use this??? */
#endif
		break;
	case DLT_PPP:
#ifdef DLT_PPP_BSDOS
	case DLT_PPP_BSDOS:
#endif
#ifdef DLT_PPP_SERIAL
	case DLT_PPP_SERIAL:
#endif
#ifdef DLT_PPP_ETHER
	case DLT_PPP_ETHER:
#endif
#if (FREEBSD || OPENBSD || NETBSD || BSDI || MACOSX)
		offset = 4;
#else
#ifdef SOLARIS
		offset = 8;
#else
		offset = 24;	/* Anyone use this? */
#endif				/* ifdef solaris */
#endif				/* if freebsd || openbsd || netbsd || bsdi */
		break;
	case DLT_RAW:
		offset = 0;
		break;
	case DLT_FDDI:
		offset = 21;
		break;
#ifdef DLT_ENC
	case DLT_ENC:
		offset = 12;
		break;
#endif				/* DLT_ENC */
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		offset = 16;
		break;
#endif
	default:
		p = (char *) pcap_next(pd, &head);
		if (head.caplen == 0) {
			/* Lets sleep a brief time and try again to increase the chance of seeing
			   a real packet ... */
			usleep(500000);
			p = (char *) pcap_next(pd, &head);
		}
		if (head.caplen > 100000) {
			fatal("FATAL: readip_pcap: bogus caplen from libpcap (%d) on interface type %d", head.caplen, datalink);
		}
		error("FATAL:  Unknown datalink type (%d). Caplen: %d; Packet:\n", datalink, head.caplen);
		lamont_hdump(p, head.caplen);
		exit(1);
	}

	if (to_usec > 0) {
		gettimeofday(&tv_start, NULL);
	}
	do {
		p = (char *) pcap_next(pd, &head);
		if (p)
			p += offset;
		if (!p || (*p & 0x40) != 0x40) {
			/* Should we timeout? */
			if (to_usec == 0) {
				timedout = 1;
			} else if (to_usec > 0) {
				gettimeofday(&tv_end, NULL);
				if (TIMEVAL_SUBTRACT(tv_end, tv_start) >= to_usec) {
					timedout = 1;
				}
			}
		}
	} while (!timedout && (!p || (*p & 0x40) != 0x40));	/* Go until we get IPv4 packet */
	if (timedout) {
		*len = 0;
		return NULL;
	}
	*len = head.caplen - offset;
	if (*len > alignedbufsz) {
		alignedbuf = realloc(alignedbuf, *len);
		if (!alignedbuf) {
			fatal("Unable to realloc %d bytes of mem", *len);
		}
		alignedbufsz = *len;
	}
	memcpy(alignedbuf, p, *len);
	return alignedbuf;
}

/* Set a pcap filter */
void set_pcap_filter(struct hoststruct *target, pcap_t * pd, PFILTERFN filter, char *bpf, ...)
{
	va_list ap;
	char buf[512];
	struct bpf_program fcode;
	unsigned int localnet, netmask;
	char err0r[256];

	if (pcap_lookupnet(target->device, &localnet, &netmask, err0r) < 0)
		fatal("Failed to lookup device subnet/netmask: %s", err0r);

	va_start(ap, bpf);
	vsprintf(buf, bpf, ap);
	va_end(ap);

	if (o.debugging)
		log_write(LOG_STDOUT, "Packet capture filter (device %s): %s\n", target->device, buf);

	/* Due to apparent bug in libpcap */
	if (islocalhost(&(target->host)))
		buf[0] = '\0';

	if (pcap_compile(pd, &fcode, buf, 0, netmask) < 0)
		fatal("Error compiling our pcap filter: %s\n", pcap_geterr(pd));
	if (pcap_setfilter(pd, &fcode) < 0)
		fatal("Failed to set the pcap filter: %s\n", pcap_geterr(pd));
}

#endif				/* WIN32 */

/* This is ugly :(.  We need to get rid of these at some point */
unsigned long flt_dsthost, flt_srchost;	/* _net_ order */
unsigned short flt_baseport;	/*      _host_ order */

int flt_icmptcp(const char *packet, int len)
{
	struct ip *ip = (struct ip *) packet;
	if (ip->ip_dst.s_addr != flt_dsthost)
		return 0;
	if (ip->ip_p == IPPROTO_ICMP)
		return 1;
	if (ip->ip_src.s_addr != flt_srchost)
		return 0;
	if (ip->ip_p == IPPROTO_TCP)
		return 1;
	return 0;
}

int flt_icmptcp_2port(const char *packet, int len)
{
	unsigned short dport;
	struct ip *ip = (struct ip *) packet;
	if (ip->ip_dst.s_addr != flt_dsthost)
		return 0;
	if (ip->ip_p == IPPROTO_ICMP)
		return 1;
	if (ip->ip_src.s_addr != flt_srchost)
		return 0;
	if (ip->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
		if (len < 4 * ip->ip_hl + 4)
			return 0;
		dport = ntohs(tcp->th_dport);
		if (dport == flt_baseport || dport == flt_baseport + 1)
			return 1;
	}

	return 0;
}

int flt_icmptcp_5port(const char *packet, int len)
{
	unsigned short dport;
	struct ip *ip = (struct ip *) packet;
	if (ip->ip_dst.s_addr != flt_dsthost)
		return 0;
	if (ip->ip_p == IPPROTO_ICMP)
		return 1;
	if (ip->ip_p == IPPROTO_TCP) {
		struct tcphdr *tcp = (struct tcphdr *) (((char *) ip) + 4 * ip->ip_hl);
		if (len < 4 * ip->ip_hl + 4)
			return 0;
		dport = ntohs(tcp->th_dport);
		if (dport >= flt_baseport && dport <= flt_baseport + 4)
			return 1;
	}

	return 0;
}


#ifndef WIN32			/* Currently the Windows code for next few functions is 
				   in wintcpip.c -- should probably be merged at some
				   point */
int ipaddr2devname(char *dev, struct in_addr *addr)
{
	struct interface_info *mydevs;
	int numdevs;
	int i;
	mydevs = getinterfaces(&numdevs);

	if (!mydevs)
		return -1;

	for (i = 0; i < numdevs; i++) {
		if (addr->s_addr == mydevs[i].addr.s_addr) {
			strcpy(dev, mydevs[i].name);
			return 0;
		}
	}
	return -1;
}

int devname2ipaddr(char *dev, struct in_addr *addr)
{
	struct interface_info *mydevs;
	int numdevs;
	int i;
	mydevs = getinterfaces(&numdevs);

	if (!mydevs)
		return -1;

	for (i = 0; i < numdevs; i++) {
		if (!strcmp(dev, mydevs[i].name)) {
			memcpy(addr, (char *) &mydevs[i].addr, sizeof(struct in_addr));
			return 0;
		}
	}
	return -1;
}
#endif				/* WIN32 */

#ifndef WIN32			/* ifdef'd out for now because 'doze apparently doesn't
				   support ioctl() */
struct interface_info *getinterfaces(int *howmany)
{
	static int initialized = 0;
	static struct interface_info mydevs[128];
	static int numinterfaces = 0;
	int sd;
	int len;
	char *p;
	char buf[10240];
	struct ifconf ifc;
	struct ifreq *ifr;
	struct sockaddr_in *sin;

	if (!initialized) {

		initialized = 1;
		/* Dummy socket for ioctl */
		sd = socket(AF_INET, SOCK_DGRAM, 0);
		if (sd < 0)
			pfatal("socket in getinterfaces");
		ifc.ifc_len = sizeof(buf);
		ifc.ifc_buf = buf;
		if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) {
			fatal("Failed to determine your configured interfaces!\n");
		}
		close(sd);
		ifr = (struct ifreq *) buf;
		if (ifc.ifc_len == 0)
			fatal("getinterfaces: SIOCGIFCONF claims you have no network interfaces!\n");
#if HAVE_SOCKADDR_SA_LEN
		/*    len = MAX(sizeof(struct sockaddr), ifr->ifr_addr.sa_len); */
		len = ifr->ifr_addr.sa_len + sizeof(ifr->ifr_name);
#else
		len = sizeof(struct ifreq);
		/* len = sizeof(SA); */
#endif

#if TCPIP_DEBUGGING
		printf("ifnet list length = %d\n", ifc.ifc_len);
		printf("sa_len = %d\n", len);
		hdump(buf, ifc.ifc_len);
		printf("ifr = %X\n", (unsigned int) (*(char **) &ifr));
		printf("Size of struct ifreq: %d\n", sizeof(struct ifreq));
#endif

		for (; ifr && *((char *) ifr) && ((char *) ifr) < buf + ifc.ifc_len; ((*(char **) &ifr) += len)) {
#if TCPIP_DEBUGGING
			printf("ifr_name size = %d\n", sizeof(ifr->ifr_name));
			printf("ifr = %X\n", (unsigned int) (*(char **) &ifr));
#endif

			/* skip any device with no name */
			if (!*((char *) ifr))
				continue;

			sin = (struct sockaddr_in *) &ifr->ifr_addr;
			memcpy(&(mydevs[numinterfaces].addr), (char *) &(sin->sin_addr), sizeof(struct in_addr));
			/* In case it is a stinkin' alias */
			if ((p = strchr(ifr->ifr_name, ':')))
				*p = '\0';
			strncpy(mydevs[numinterfaces].name, ifr->ifr_name, 63);
			mydevs[numinterfaces].name[63] = '\0';


#if TCPIP_DEBUGGING
			printf("Interface %d is %s\n", numinterfaces, mydevs[numinterfaces].name);
#endif

			numinterfaces++;
			if (numinterfaces == 127) {
				error("My God!  You seem to have WAY too many interfaces!  Things may not work right\n");
				break;
			}
#if HAVE_SOCKADDR_SA_LEN
			/* len = MAX(sizeof(struct sockaddr), ifr->ifr_addr.sa_len); */
			len = ifr->ifr_addr.sa_len + sizeof(ifr->ifr_name);
#endif
			mydevs[numinterfaces].name[0] = '\0';
		}
	}
	if (howmany)
		*howmany = numinterfaces;
	return mydevs;
}
#endif


/* An awesome function to determine what interface a packet to a given
   destination should be routed through.  It returns NULL if no appropriate
   interface is found, oterwise it returns the device name and fills in the
   source parameter.   Some of the stuff is
   from Stevens' Unix Network Programming V2.  He had an easier suggestion
   for doing this (in the book), but it isn't portable :( */
#ifndef WIN32			/* Windows functionality is currently in wintcpip.c --
				   should probably be merged at some point */

#define ROUTETHROUGH_MAXROUTES 1024
char *routethrough(struct in_addr *dest, struct in_addr *source)
{
	static int initialized = 0;
	int i;
	struct in_addr addy;
	static enum { procroutetechnique, connectsockettechnique, guesstechnique } technique = procroutetechnique;
	char buf[10240];
	struct interface_info *mydevs;
	static struct myroute {
		struct interface_info *dev;
		u32 mask;
		u32 dest;
	} myroutes[ROUTETHROUGH_MAXROUTES];
	int numinterfaces = 0;
	char *p, *endptr;
	char iface[64];
	static int numroutes = 0;
	FILE *routez;

	if (!dest)
		fatal("ipaddr2devname passed a NULL dest address");

	if (!initialized) {
		/* Dummy socket for ioctl */
		initialized = 1;
		mydevs = getinterfaces(&numinterfaces);

		/* Now we must go through several techniques to determine info */
		routez = fopen("/proc/net/route", "r");

		if (routez) {
			/* OK, linux style /proc/net/route ... we can handle this ... */
			/* Now that we've got the interfaces, we g0 after the r0ut3Z */

			fgets(buf, sizeof(buf), routez);	/* Kill the first line */
			while (fgets(buf, sizeof(buf), routez)) {
				p = strtok(buf, " \t\n");
				if (!p) {
					error("Could not find interface in /proc/net/route line");
					continue;
				}
				if (*p == '*')
					continue;	/* Deleted route -- any other valid reason for
							   a route to start with an asterict? */
				strncpy(iface, p, sizeof(iface));
				if ((p = strchr(iface, ':'))) {
					*p = '\0';	/* To support IP aliasing */
				}
				p = strtok(NULL, " \t\n");
				endptr = NULL;
				myroutes[numroutes].dest = strtoul(p, &endptr, 16);
				if (!endptr || *endptr) {
					error("Failed to determine Destination from /proc/net/route");
					continue;
				}
				for (i = 0; i < 6; i++) {
					p = strtok(NULL, " \t\n");
					if (!p)
						break;
				}
				if (!p) {
					error("Failed to find field %d in /proc/net/route", i + 2);
					continue;
				}
				endptr = NULL;
				myroutes[numroutes].mask = strtoul(p, &endptr, 16);
				if (!endptr || *endptr) {
					error("Failed to determine mask from /proc/net/route");
					continue;
				}
#if TCPIP_DEBUGGING
				printf("#%d: for dev %s, The dest is %X and the mask is %X\n", numroutes, iface, myroutes[numroutes].dest, myroutes[numroutes].mask);
#endif
				for (i = 0; i < numinterfaces; i++)
					if (!strcmp(iface, mydevs[i].name)) {
						myroutes[numroutes].dev = &mydevs[i];
						break;
					}
				if (i == numinterfaces)
					fatal("Failed to find interface %s mentioned in /proc/net/route\n", iface);
				numroutes++;
				if (numroutes == ROUTETHROUGH_MAXROUTES)
					fatal("My God!  You seem to have WAY too many routes!\n");
			}
			fclose(routez);
		} else {
			technique = connectsockettechnique;
		}
	} else {
		mydevs = getinterfaces(&numinterfaces);
	}
	/* WHEW, that takes care of initializing, now we have the easy job of 
	   finding which route matches */
	if (islocalhost(dest)) {
		if (source)
			source->s_addr = htonl(0x7F000001);
		/* Now we find the localhost interface name, assuming 127.0.0.1 is
		   localhost (it damn well better be!)... */
		for (i = 0; i < numinterfaces; i++) {
			if (mydevs[i].addr.s_addr == htonl(0x7F000001)) {
				return mydevs[i].name;
			}
		}
		return NULL;
	}

	if (technique == procroutetechnique) {
		for (i = 0; i < numroutes; i++) {
			if ((dest->s_addr & myroutes[i].mask) == myroutes[i].dest) {
				if (source) {
					source->s_addr = myroutes[i].dev->addr.s_addr;
				}
				return myroutes[i].dev->name;
			}
		}
	} else if (technique == connectsockettechnique) {
		if (!getsourceip(&addy, dest))
			return NULL;
		if (!addy.s_addr) {	/* Solaris 2.4 */
			struct hostent *myhostent = NULL;
			char myname[MAXHOSTNAMELEN + 1];
			if (gethostname(myname, MAXHOSTNAMELEN) || !(myhostent = gethostbyname(myname)))
				fatal("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n");
			memcpy(&(addy.s_addr), myhostent->h_addr_list[0], sizeof(struct in_addr));
#if ( TCPIP_DEBUGGING )
			printf("We skillfully deduced that your address is %s\n", inet_ntoa(*source));
#endif
		}

		/* Now we insure this claimed address is a real interface ... */
		for (i = 0; i < numinterfaces; i++)
			if (mydevs[i].addr.s_addr == addy.s_addr) {
				if (source) {
					struct in_addr r;
					r = socket_get_next_source_addr(NULL);
					if ( r.s_addr == INADDR_ANY )
						source->s_addr = addy.s_addr;
					else
						source->s_addr = r.s_addr;
				}
				return mydevs[i].name;
			}
		return NULL;
	} else
		fatal("I know sendmail technique ... I know rdist technique ... but I don't know what the hell kindof technique you are attempting!!!");
	return NULL;
}
#endif				/* WIN32 */

/* Maximize the receive buffer of a socket descriptor (up to 500K) */
void max_rcvbuf(int sd)
{
	int optval = 524288 /*2^19 */ ;
	NET_SIZE_T optlen = sizeof(int);

#ifndef WIN32
	if (setsockopt(sd, SOL_SOCKET, SO_RCVBUF, (const char *) &optval, optlen))
		if (o.debugging)
			perror("Problem setting large socket recieve buffer");
	if (o.debugging) {
		getsockopt(sd, SOL_SOCKET, SO_RCVBUF, (char *) &optval, &optlen);
		log_write(LOG_STDOUT, "Our buffer size is now %d\n", optval);
	}
#endif				/* WIN32 */
}

/* Maximize the open file descriptor limit for this process go up to the
   max allowed  */
int max_sd()
{
#ifndef WIN32
	struct rlimit r;
	static int maxfds = -1;

	if (maxfds > 0)
		return maxfds;

#if(defined(RLIMIT_NOFILE))
	if (!getrlimit(RLIMIT_NOFILE, &r)) {
		r.rlim_cur = r.rlim_max;
		if (setrlimit(RLIMIT_NOFILE, &r))
			if (o.debugging)
				perror("setrlimit RLIMIT_NOFILE failed");
		if (!getrlimit(RLIMIT_NOFILE, &r)) {
			maxfds = MIN(r.rlim_cur, MAX_SOCKETS_ALLOWED);
			/* I do not feel comfortable going over 255 for now .. */
			maxfds = MIN(maxfds, 250);
			return maxfds;
		} else
			return 0;
	}
#endif
#if(defined(RLIMIT_OFILE) && !defined(RLIMIT_NOFILE))
	if (!getrlimit(RLIMIT_OFILE, &r)) {
		r.rlim_cur = r.rlim_max;
		if (setrlimit(RLIMIT_OFILE, &r))
			if (o.debugging)
				perror("setrlimit RLIMIT_OFILE failed");
		if (!getrlimit(RLIMIT_OFILE, &r)) {
			maxfds = MIN(r.rlim_cur, MAX_SOCKETS_ALLOWED);
			/* I do not feel comfortable going over 255 for now .. */
			maxfds = MIN(maxfds, 250);
			return maxfds;
		} else
			return 0;
	}
#endif
#endif				/* WIN32 */
	return 0;
}

/* Convert a socket to blocking mode */
int block_socket(int sd)
{
#ifdef WIN32
	unsigned long options = 0;
	if (sd == 501)
		return 1;
	ioctlsocket(sd, FIONBIO, (unsigned long *) &options);
#else
	int options;
	options = (~O_NONBLOCK) & fcntl(sd, F_GETFL);
	fcntl(sd, F_SETFL, options);
#endif

	return 1;
}

/* Give broadcast permission to a socket */
void broadcast_socket(int sd)
{
	int one = 1;
#ifdef WIN32
	if (sd == 501)
		return;
#endif
	if (setsockopt(sd, SOL_SOCKET, SO_BROADCAST, (const char *) &one, sizeof(int)) != 0) {
		fprintf(stderr, "Failed to secure socket broadcasting permission\n");
		perror("setsockopt");
	}
}

/* Do a receive (recv()) on a socket and stick the results (upt to
   len) into buf .  Give up after 'seconds'.  Returns the number of
   bytes read (or -1 in the case of an error.  It only does one recv
   (it will not keep going until len bytes are read */
int recvtime(int sd, char *buf, int len, int seconds)
{

	int res;
	struct timeval timeout;
	fd_set readfd;

	timeout.tv_sec = seconds;
	timeout.tv_usec = 0;
	FD_ZERO(&readfd);
	FD_SET(sd, &readfd);
	res = select(sd + 1, &readfd, NULL, NULL, &timeout);
	if (res > 0) {
		res = recv(sd, buf, len, 0);
		if (res >= 0)
			return res;
		perror("recv in recvtime");
		return 0;
	} else if (!res)
		return 0;
	perror("select() in recvtime");
	return -1;
}

/* This attempts to calculate the round trip time (rtt) to a host by timing a
   connect() to a port which isn't listening.  A better approach is to time a
   ping (since it is more likely to get through firewalls (note, this isn't
   always true nowadays --fyodor).  This is now 
   implemented in isup() for users who are root.  */
unsigned long calculate_sleep(struct in_addr target)
{
	struct timeval begin, end;
	int sd;
	struct sockaddr_in sock;
	int res;

	if ((sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
		perror("Socket troubles");
		exit(1);
	}

	sock.sin_family = AF_INET;
	sock.sin_addr.s_addr = target.s_addr;
	sock.sin_port = htons(o.magic_port);

	gettimeofday(&begin, NULL);
	if ((res = connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in))) != -1)
		fprintf(stderr, "WARNING: You might want to use a different value of -g (or change o.magic_port in the include file), as it seems to be listening on the target host!\n");
	close(sd);
	gettimeofday(&end, NULL);
	if (end.tv_sec - begin.tv_sec > 5)	/*uh-oh! */
		return 0;
	return (end.tv_sec - begin.tv_sec) * 1000000 + (end.tv_usec - begin.tv_usec);
}


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
int gettcpopt_ts(struct tcphdr *tcp, u32 * timestamp, u32 * echots)
{

	unsigned char *p;
	int len = 0;
	int op;
	int oplen;

	/* first we find where the tcp options start ... */
	p = ((unsigned char *) tcp) + 20;
	len = 4 * tcp->th_off - 20;
	while (len > 0 && *p != 0 /* TCPOPT_EOL */ ) {
		op = *p++;
		if (op == 0 /* TCPOPT_EOL */ )
			break;
		if (op == 1 /* TCPOPT_NOP */ ) {
			len--;
			continue;
		}
		oplen = *p++;
		if (oplen < 2)
			break;	/* No infinite loops, please */
		if (oplen > len)
			break;	/* Not enough space */
		if (op == 8 /* TCPOPT_TIMESTAMP */  && oplen == 10) {
			/* Legitimate ts option */
			if (timestamp) {
				memcpy((char *) timestamp, p, 4);
				*timestamp = ntohl(*timestamp);
			}
			p += 4;
			if (echots) {
				memcpy((char *) echots, p, 4);
				*echots = ntohl(*echots);
			}
			return 1;
		}
		len -= oplen;
		p += oplen - 2;
	}

	/* Didn't find anything */
	if (timestamp)
		*timestamp = 0;
	if (echots)
		*echots = 0;
	return 0;
}
