
/***********************************************************************
 * portlist.c -- Functions for manipulating various lists of ports     *
 * maintained internally by Nmap.                                      *
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

/* $Id: portlist.c,v 1.1 2003/02/24 14:46:19 renaud Exp $ */

#include "nmap.h"
#include "portlist.h"
#include "nmap_error.h"


#if HAVE_STRINGS_H
#include <strings.h>
#endif				/* HAVE_STRINGS_H */

extern struct ops o;		/* option structure */
static struct port *freeportlist = NULL;

/* gawd, my next project will be in c++ so I don't have to deal with
   this crap ... simple linked list implementation */
int addport(portlist * plist, u16 portno, u8 protocol, char *owner, int state)
{
	struct port *current = NULL;
	struct port **portarray = NULL;
	char msg[128];

	if ((state == PORT_OPEN && o.verbose) || (o.debugging > 1)) {
		if (owner && *owner) {
			snprintf(msg, sizeof(msg), " (owner: %s)", owner);
		} else
			msg[0] = '\0';

	}

/* Make sure state is OK */
	if (state != PORT_OPEN && state != PORT_CLOSED && state != PORT_FIREWALLED && state != PORT_UNFIREWALLED)
		fatal("addport: attempt to add port number %d with illegal state %d\n", portno, state);

	if (protocol == IPPROTO_TCP) {
		if (!plist->tcp_ports) {
			plist->tcp_ports = (struct port **) safe_zalloc(65536 * sizeof(struct port *));
		}
		portarray = plist->tcp_ports;
	} else if (protocol == IPPROTO_UDP) {
		if (!plist->udp_ports) {
			plist->udp_ports = (struct port **) safe_zalloc(65536 * sizeof(struct port *));
		}
		portarray = plist->udp_ports;
	} else if (protocol == IPPROTO_IP) {
		assert(portno < 256);
		if (!plist->ip_prots) {
			plist->ip_prots = (struct port **) safe_zalloc(256 * sizeof(struct port *));
		}
		portarray = plist->ip_prots;
	} else
		fatal("addport: attempted port insertion with invalid protocol");

	if (portarray[portno]) {
		/* We must discount our statistics from the old values.  Also warn
		   if a complete duplicate */
		current = portarray[portno];
		if (o.debugging && current->state == state && (!owner || !*owner)) {
			error("Duplicate port (%hu/%s)\n", portno, (protocol == IPPROTO_TCP) ? "tcp" : (protocol == IPPROTO_UDP) ? "udp" : "ip");
		}
		plist->state_counts[current->state]--;
		if (current->proto == IPPROTO_TCP) {
			plist->state_counts_tcp[current->state]--;
		} else if (current->proto == IPPROTO_UDP) {
			plist->state_counts_udp[current->state]--;
		} else
			plist->state_counts_ip[current->state]--;
	} else {
		portarray[portno] = make_empty_port();
		current = portarray[portno];
		plist->numports++;
		/*current->rpc_status = RPC_STATUS_UNTESTED; */
		current->confidence = CONF_HIGH;
		current->portno = portno;
	}

	plist->state_counts[state]++;
	current->state = state;
	if (protocol == IPPROTO_TCP) {
		plist->state_counts_tcp[state]++;
	} else if (protocol == IPPROTO_UDP) {
		plist->state_counts_udp[state]++;
	} else
		plist->state_counts_ip[state]++;
	current->proto = protocol;

	if (owner && *owner) {
		if (current->owner)
			free(current->owner);
		current->owner = strdup(owner);
	}

	return 0;		/*success */
}

int deleteport(portlist * plist, u16 portno, u8 protocol)
{
	struct port *answer = NULL;

	if (protocol == IPPROTO_TCP && plist->tcp_ports) {
		answer = plist->tcp_ports[portno];
		plist->tcp_ports[portno] = NULL;
	}

	if (protocol == IPPROTO_UDP && plist->udp_ports) {
		answer = plist->udp_ports[portno];
		plist->udp_ports[portno] = NULL;
	} else if (protocol == IPPROTO_IP && plist->ip_prots) {
		answer = plist->ip_prots[portno] = NULL;
	}

	if (!answer)
		return -1;

	free_port(answer);
	return 0;
}


struct port *lookupport(portlist * ports, u16 portno, u8 protocol)
{

	if (protocol == IPPROTO_TCP && ports->tcp_ports)
		return ports->tcp_ports[portno];

	if (protocol == IPPROTO_UDP && ports->udp_ports)
		return ports->udp_ports[portno];

	if (protocol == IPPROTO_IP && ports->ip_prots)
		return ports->ip_prots[portno];

	return NULL;
}


/* RECYCLES the port so that it can later be obtained again using 
   make_port_structure */
void free_port(struct port *pt)
{
	struct port *tmp;
	if (pt->owner)
		free(pt->owner);
	tmp = freeportlist;
	freeportlist = pt;
	pt->next = tmp;
}

struct port *make_empty_port()
{
	int i;
	struct port *newpt;

	if (!freeportlist) {
		freeportlist = (struct port *) safe_malloc(sizeof(struct port) * 1024);
		for (i = 0; i < 1023; i++)
			freeportlist[i].next = &freeportlist[i + 1];
		freeportlist[1023].next = NULL;
	}

	newpt = freeportlist;
	freeportlist = freeportlist->next;
	bzero(newpt, sizeof(struct port));
	return newpt;
}

/* Empties out a portlist so that it can be reused (or freed).  All the 
   internal structures that must be freed are done so here. */
void resetportlist(portlist * plist)
{
	int i;
	if (plist->tcp_ports) {
		for (i = 0; i < 65536; i++) {
			if (plist->tcp_ports[i])
				free_port(plist->tcp_ports[i]);
		}
		free(plist->tcp_ports);
	}

	if (plist->udp_ports) {
		for (i = 0; i < 65536; i++) {
			if (plist->udp_ports[i])
				free_port(plist->udp_ports[i]);
		}
		free(plist->udp_ports);
	}

	if (plist->ip_prots) {
		for (i = 0; i < 256; ++i) {
			if (plist->ip_prots[i])
				free_port(plist->ip_prots[i]);
		}
		free(plist->ip_prots);
	}

	bzero(plist, sizeof(*plist));
}


/* Decide which port we want to ignore in output (for example, we don't want
 to show closed ports if there are 40,000 of them.) */
void assignignoredportstate(portlist * plist)
{

	if (plist->state_counts[PORT_FIREWALLED] > 10 + MAX(plist->state_counts[PORT_UNFIREWALLED], plist->state_counts[PORT_CLOSED])) {
		plist->ignored_port_state = PORT_FIREWALLED;
	} else if (plist->state_counts[PORT_UNFIREWALLED] > plist->state_counts[PORT_CLOSED]) {
		plist->ignored_port_state = PORT_UNFIREWALLED;
	} else
		plist->ignored_port_state = PORT_CLOSED;
}



/* A function for iterating through the ports.  Give NULL for the
   first "afterthisport".  Then supply the most recent returned port
   for each subsequent call.  When no more matching ports remain, NULL
   will be returned.  To restrict returned ports to just one protocol,
   specify IPPROTO_TCP or IPPROTO_UDP for allowed_protocol.  A 0 for
   allowed_protocol matches either.  allowed_state works in the same
   fashion as allowed_protocol. This function returns ports in numeric
   order from lowest to highest, except that if you ask for both TCP &
   UDP, every TCP port will be returned before we start returning UDP
   ports */

struct port *nextport(portlist * plist, struct port *afterthisport, u8 allowed_protocol, int allowed_state)
{

	/* These two are chosen because they come right "before" port 1/tcp */
	unsigned int current_portno = 0;
	unsigned int current_proto = IPPROTO_TCP;

	if (afterthisport) {
		current_portno = afterthisport->portno;
		current_proto = afterthisport->proto;	/* (afterthisport->proto == IPPROTO_TCP)? IPPROTO_TCP : IPPROTO_UDP; */
	}

	current_portno++;	/* Start on the port after the one we were given */

/* First we look for TCP ports ... */
	if (current_proto == IPPROTO_TCP) {
		if ((allowed_protocol == 0 || allowed_protocol == IPPROTO_TCP) && current_proto == IPPROTO_TCP && plist->tcp_ports)
			for (; current_portno < 65536; current_portno++) {
				if (plist->tcp_ports[current_portno] && (!allowed_state || plist->tcp_ports[current_portno]->state == allowed_state))
					return plist->tcp_ports[current_portno];
			}

		/*  Uh-oh.  We have tried all tcp ports, lets move to udp */
		current_portno = 0;
		current_proto = IPPROTO_UDP;
	}

	if ((allowed_protocol == 0 || allowed_protocol == IPPROTO_UDP) && current_proto == IPPROTO_UDP && plist->udp_ports) {
		for (; current_portno < 65536; current_portno++) {
			if (plist->udp_ports[current_portno] && (!allowed_state || plist->udp_ports[current_portno]->state == allowed_state))
				return plist->udp_ports[current_portno];
		}
	}

/*  No more ports */
	return NULL;
}
