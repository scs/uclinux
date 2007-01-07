
/***********************************************************************
 * global_structures.h -- Common structure definitions used by Nmap    *
 * components.                                                         *
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

/* $Id: global_structures.h,v 1.1 2003/02/24 14:46:18 renaud Exp $ */


#ifndef GLOBAL_STRUCTURES_H
#define GLOBAL_STRUCTURES_H

/* Stores "port info" which is TCP/UDP ports or RPC program ids */
struct portinfo {
	unsigned long portno;	/* TCP/UDP port or RPC program id or IP protocool */
	short trynum;
	int sd[3];		/* Socket descriptors for connect_scan */
	struct timeval sent[3];
	int state;
	int next;		/* not struct portinfo * for historical reasons */
	int prev;
};

struct portinfolist {
	struct portinfo *openlist;
	struct portinfo *firewalled;
	struct portinfo *testinglist;
};

struct udpprobeinfo {
	u16 iptl;
	u16 ipid;
	u16 ipck;
	u16 sport;
	u16 dport;
	u16 udpck;
	u16 udplen;
	u8 patternbyte;
	struct in_addr target;
};

struct connectsockinfo {
	fd_set fds_read;
	fd_set fds_write;
	fd_set fds_except;
	struct portinfo *socklookup[2048];	/* index socket descriptor -> scan[] 
						   index.  No OS better give us
						   an SD > 2047!@#$ */
	int maxsd;
};

struct firewallmodeinfo {
	int active;		/* is firewall mode currently active for the host? */
	int nonresponsive_ports;	/* # Of ports we haven't received any response from */
	int responsive_ports;	/* # of ports that told us whether they were open/closed/filtered/unfiltered */
};

/* The runtime statistics used to decide how fast to proced and how
   many ports we can try at once */
struct scanstats {
	int packet_incr;
	double fallback_percent;
	int numqueries_outstanding;	/* How many unexpired queries are on the 'net
					   right now? */
	double numqueries_ideal;	/* How many do we WANT to be on the 'net right now? */
	int max_width;		/* What is the MOST we will tolerate at once */
	int ports_left;
	int changed;		/* Has anything changed since last round? */
	int alreadydecreasedqueries;
};

struct ftpinfo {
	char user[64];
	char pass[256];		/* methinks you're paranoid if you need this much space */
	char server_name[MAXHOSTNAMELEN + 1];
	struct in_addr server;
	u16 port;
	int sd;			/* socket descriptor */
};

struct AVal {
	char *attribute;
	char value[128];
	struct AVal *next;
};

typedef struct FingerTest {
	char OS_name[256];
	int line;		/* For reference prints, the line # in nmap-os-fingerprints */
	const char *name;
	struct AVal *results;
	struct FingerTest *next;
} FingerPrint;

/* Maximum number of results allowed in one of these things ... */
#define MAX_FP_RESULTS 8
struct FingerPrintResults {
	double accuracy[MAX_FP_RESULTS];	/* Percentage of match (1.0 == perfect 
						   match) in same order as pritns[] below */
	FingerPrint *prints[MAX_FP_RESULTS];	/* ptrs to matching references -- 
						   highest accuracy matches first */
	int num_perfect_matches;	/* Number of 1.0 accuracy matches in prints[] */
	int num_matches;	/* Total number of matches in prints */
	int overall_results;	/* OSSCAN_TOOMANYMATCHES, OSSCAN_NOMATCHES, 
				   OSSCAN_SUCCESS, etc */
};

struct timeout_info {
	int srtt;		/* Smoothed rtt estimate (microseconds) */
	int rttvar;		/* Rout trip time variance */
	int timeout;		/* Current timeout threshold (microseconds) */
};

struct seq_info {
	int responses;
	int seqclass;		/* SEQ_* defines in nmap.h */
	int ts_seqclass;	/* TS_SEQ_* defines in nmap.h */
	time_t uptime;		/* time of latest system boot (or 0 if unknown ) */
	int ipid_seqclass;	/* IPID_SEQ_* defines in nmap.h */
	u32 seqs[NUM_SEQ_SAMPLES];
	u32 timestamps[NUM_SEQ_SAMPLES];
	int index;
	u16 ipids[NUM_SEQ_SAMPLES];
	time_t lastboot;	/* 0 means unknown */
};

struct targets {
	/* These 4 are used for the '/mask' style of specifying target net */
	u32 netmask;
	unsigned int maskformat;
	struct in_addr start;
	struct in_addr currentaddr;
	struct in_addr end;
	/* These two are for the '138.[1-7,16,91-95,200-].12.1 style */
	u8 addresses[4][256];
	unsigned int current[4];
	u8 last[4];
	int nleft;		/* Number of IPs left in this structure -- set to 0 if 
				   the fields are not valid */
};


struct hoststruct {
	struct in_addr host;
	struct in_addr source_ip;
	char *name;
	struct seq_info seq;
	struct FingerPrintResults FPR;
	FingerPrint *FPs[10];	/* Fingerprint data obtained from host */
	int osscan_performed;	/* nonzero if an osscan was performed */
	int osscan_openport;	/* Open port used for scannig (if one found -- 
				   otherwise -1) */
	int osscan_closedport;	/* Closed port used for scannig (if one found -- 
				   otherwise -1) */
	int numFPs;
	int goodFP;
	portlist ports;
	/*
	   unsigned int up;
	   unsigned int down; */
	int wierd_responses;	/* echo responses from other addresses, Ie a network broadcast address */
	unsigned int flags;	/* HOST_UP, HOST_DOWN, HOST_FIREWALLED, HOST_BROADCAST (instead of HOST_BROADCAST use wierd_responses */
	struct timeout_info to;
	struct timeval host_timeout;
	struct firewallmodeinfo firewallmode;	/* For supporting "firewall mode" speed optimisations */
	int timedout;		/* Nonzero if continued scanning should be aborted due to
				   timeout  */
	char device[64];	/* The device we transmit on */
};

struct hostgroup_state {
	struct hoststruct *hostbatch;
	int max_batch_sz;	/* The size of the hostbatch[] array */
	int current_batch_sz;	/* The number of VALID members of hostbatch[] */
	int next_batch_no;	/* The index of the next hostbatch[] member to be given 
				   back to the user */
	int randomize;		/* Whether each bach should be "shuffled" prior to the ping 
				   scan (they will also be out of order when given back one
				   at a time to the client program */
	char **target_expressions;	/* An array of target expression strings, passed
					   to us by the client (client is also in charge
					   of deleting it AFTER it is done with the 
					   hostgroup_state */
	int num_expressions;	/* The number of valid expressions in 
				   target_expressions member above */
	int next_expression;	/* The index of the next expression we have
				   to handle */
	struct targets current_expression;	/* For batch chunking */
};

struct ops {			/* someone took struct options, <grrr> */
	int debugging;
	int verbose;
	int randomize_hosts;
	int spoofsource;	/* -S used */
	struct in_addr *source;
	char device[64];
	int interactivemode;
	int host_group_sz;
	int generate_random_ips;	/* -iR option */
	u16 magic_port;
	unsigned short magic_port_set;	/* Was this set by user? */
	u16 tcp_probe_port;

	/* Scan timing/politeness issues */
	int max_parallelism;
	int max_rtt_timeout;
	int min_rtt_timeout;
	int extra_payload_length;	/* These two are for --data_length op */
	char *extra_payload;
	unsigned long host_timeout;
	int scan_delay;
	int scanflags;		/* if not -1, this value should dictate the TCP flags
				   for the core portscaning routine (eg to change a
				   FIN scan into a PSH scan.  Sort of a hack, but can
				   be very useful sometimes. */
	int initial_rtt_timeout;
	struct in_addr resume_ip;	/* The last IP in the log file if user 
					   requested --restore .  Otherwise 
					   restore_ip.s_addr == 0.  Also 
					   target_struct_get will eventually set it 
					   to 0. */
	int isr00t;
	struct in_addr decoys[MAX_DECOYS];
	int osscan_limit;	/* Skip OS Scan if no open or no closed TCP ports */
	int osscan_guess;	/* Be more aggressive in guessing OS type */
	int numdecoys;
	int decoyturn;
	int identscan;
	int osscan;
	int pingtype;
	int listscan;
	int pingscan;
	int allowall;
	int ackscan;
	int bouncescan;
	int connectscan;
	int rpcscan;
	int nullscan;
	int xmasscan;
	int fragscan;
	int synscan;
	int windowscan;
	int maimonscan;
	int idlescan;
	int finscan;
	int udpscan;
	int ipprotscan;
	int noresolve;
	int force;		/* force nmap to continue on even when the outcome seems somewhat certain */
	int append_output;	/* Append to any output files rather than overwrite */
	FILE *logfd[LOG_TYPES];
	FILE *nmap_stdout;	/* Nmap standard output */
};


/* The various kinds of port/protocol scans we can have
 * Each element is to point to an array of port/protocol numbers
 */
struct scan_lists {
	unsigned short *tcp_ports;
	int tcp_count;
	unsigned short *udp_ports;
	int udp_count;
	unsigned short *prots;
	int prot_count;
};


typedef enum { ACK_SCAN, SYN_SCAN, FIN_SCAN, XMAS_SCAN, UDP_SCAN, CONNECT_SCAN, NULL_SCAN, WINDOW_SCAN, RPC_SCAN, MAIMON_SCAN, IPPROT_SCAN } stype;

#endif				/*GLOBAL_STRUCTURES_H */
