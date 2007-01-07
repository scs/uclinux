
/***********************************************************************
 * targets.h -- Functions relating to "ping scanning" as well as       *
 * determining the exact IPs to hit based on CIDR and other input      *
 * formats.                                                            *
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

/* $Id: targets.h,v 1.1 2003/02/24 14:46:19 renaud Exp $ */

#ifndef TARGETS_H
#define TARGETS_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#ifdef WIN32
#include "nmap_winconfig.h"
#endif				/* WIN32 */
#endif				/* HAVE_CONFIG_H */

/* This contains pretty much everythign we need ... */
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif

#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>		/* Defines MAXHOSTNAMELEN on BSD */
#endif

#include "nmap.h"
#include "global_structures.h"

/**************************STRUCTURES******************************/
struct pingtune {
	int up_this_block;
	int down_this_block;
	int block_tries;
	int block_unaccounted;
	int max_tries;
	int num_responses;
	int dropthistry;
	int group_size;
	int group_start;
	int group_end;
	int discardtimesbefore;
};

struct tcpqueryinfo {
	int *sockets;
	int maxsd;
	fd_set fds_r;
	fd_set fds_w;
	fd_set fds_x;
	int sockets_out;
};

struct pingtech {
	unsigned int icmpscan:1, rawicmpscan:1, connecttcpscan:1, rawtcpscan:1;
};


/* Fills up the hostgroup_state structure passed in (which must point
   to valid memory).  Lookahead is the number of hosts that can be
   checked (such as ping scanned) in advance.  Randomize causes each
   group of up to lookahead hosts to be internally shuffled around.
   The target_expressions array must remail valid in memory as long as
   this hostgroup_state structure is used -- the array is NOT copied */
int hostgroup_state_init(struct hostgroup_state *hs, int lookahead, int randomize, char *target_expressions[], int num_expressions);
/* Free the *internal state* of a hostgroup_state structure -- it is
   important to note that this does not free the actual memory
   allocated for the "struct hostgroup_state" you pass in.  It only
   frees internal stuff -- after all, your hostgroup_state could be on
   the stack */
void hostgroup_state_destroy(struct hostgroup_state *hs);
/* If there is at least one IP address left in t, one is pulled out and placed
   in sin and then zero is returned and state information in t is updated
   to reflect that the IP was pulled out.  If t is empty, -1 is returned */
int target_struct_get(struct targets *t, struct in_addr *sin);
/* Undoes the previous target_struct_get operation */
void target_struct_return(struct targets *t);
void hoststructfry(struct hoststruct *hostbatch, int nelem);
/* Ports is the list of ports the user asked to be scanned (0 terminated),
   you can just pass NULL (it is only a stupid optimization that needs it) */
struct hoststruct *nexthost(struct hostgroup_state *hs, struct scan_lists *ports, int *pingtype);
/* Frees the *INTERNAL STRUCTURES* inside a hoststruct -- does not
   free the actual memory allocated to the hoststruct itself (for all
   this function knows, you could have declared it on the stack */
void hoststruct_free(struct hoststruct *currenths);
#endif				/* TARGETS_H */
