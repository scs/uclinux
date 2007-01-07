
/***********************************************************************
 * targets.c -- Functions relating to "ping scanning" as well as       *
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

/* $Id: targets.c,v 1.1 2003/02/24 14:46:19 renaud Exp $ */


#include "targets.h"
#include "timing.h"
#include "osscan.h"

extern struct ops o;

/*  predefined filters -- I need to kill these globals at some pont. */
extern unsigned long flt_dsthost, flt_srchost;
extern unsigned short flt_baseport;




/* Fills up the hostgroup_state structure passed in (which must point
   to valid memory).  Lookahead is the number of hosts that can be
   checked (such as ping scanned) in advance.  Randomize causes each
   group of up to lookahead hosts to be internally shuffled around.
   The target_expressions array must remail valid in memory as long as
   this hostgroup_state structure is used -- the array is NOT copied.
   Also, REMEMBER TO CALL hostgroup_state_destroy() when you are done
   with the hostgroup_state (the latter function only frees internal
   resources -- you still have to free the alocated memory (if any)
   for the struct hostgroup_state itself.  */
int hostgroup_state_init(struct hostgroup_state *hs, int lookahead, int randomize, char *target_expressions[], int num_expressions)
{
	bzero(hs, sizeof(*hs));
	assert(lookahead > 0);
	hs->hostbatch = (struct hoststruct *) safe_malloc(lookahead * sizeof(struct hoststruct));
	hs->max_batch_sz = lookahead;
	hs->current_batch_sz = 0;
	hs->next_batch_no = 0;
	hs->randomize = randomize;
	hs->target_expressions = target_expressions;
	hs->num_expressions = num_expressions;
	hs->next_expression = 0;
	hs->current_expression.nleft = 0;
	return 0;
}

/* Free the *internal state* of a hostgroup_state structure -- it is
   important to note that this does not free the actual memory
   allocated for the "struct hostgroup_state" you pass in.  It only
   frees internal stuff -- after all, your hostgroup_state could be on
   the stack */
void hostgroup_state_destroy(struct hostgroup_state *hs)
{
	if (!hs)
		fatal("NULL hostgroup_state passed to hostgroup_state_destroy()!");
	if (!hs->hostbatch)
		fatal("hostgroup_state passed to hostgroup_state_destroy() contains NULL hostbatch!");
	free(hs->hostbatch);
}


/* If there is at least one IP address left in t, one is pulled out and placed
   in sin and then zero is returned and state information in t is updated
   to reflect that the IP was pulled out.  If t is empty, -1 is returned */
int target_struct_get(struct targets *t, struct in_addr *sin)
{
	int octet;

      startover:		/* to hande nmap --resume where I have already
				   scanned many of the IPs */

	if (t->nleft <= 0)
		return -1;

	if (t->maskformat) {
		if (t->currentaddr.s_addr <= t->end.s_addr) {
			sin->s_addr = htonl(t->currentaddr.s_addr++);
		} else {
			error("Bogus target structure passed to target_struct_get");
			t->nleft = 0;
			sin->s_addr = 0;
			return -1;
		}
	} else {
		if (o.debugging > 2) {
			log_write(LOG_STDOUT,
				  "doing %d.%d.%d.%d = %d.%d.%d.%d\n",
				  t->current[0], t->current[1],
				  t->current[2], t->current[3], t->addresses[0][t->current[0]], t->addresses[1][t->current[1]], t->addresses[2][t->current[2]], t->addresses[3][t->current[3]]);
		}
		/* Set the IP to the current value of everything */
		sin->s_addr = htonl(t->addresses[0][t->current[0]] << 24 | t->addresses[1][t->current[1]] << 16 | t->addresses[2][t->current[2]] << 8 | t->addresses[3][t->current[3]]);

		/* Now we nudge up to the next IP */
		for (octet = 3; octet >= 0; octet--) {
			if (t->current[octet] < t->last[octet]) {
				/* OK, this is the column I have room to nudge upwards */
				t->current[octet]++;
				break;
			} else {
				/* This octet is finished so I reset it to the beginning */
				t->current[octet] = 0;
			}
		}
		if (octet == -1) {
			/* It didn't find anything to bump up, I muast have taken the last IP */
			assert(t->nleft == 1);
			/* So I set current to last with the very final octet up one ... */
			/* Note that this may make t->current[3] == 256 */
			t->current[0] = t->last[0];
			t->current[1] = t->last[1];
			t->current[2] = t->last[2];
			t->current[3] = t->last[3] + 1;
		} else {
			assert(t->nleft > 1);	/* There must be at least one more IP left */
		}
	}
	t->nleft--;
	assert(t->nleft >= 0);

	/* If we are resuming from a previous scan, we have already finished
	   scans up to o.resume_ip.  */
	if (o.resume_ip.s_addr) {
		if (o.resume_ip.s_addr == sin->s_addr)
			o.resume_ip.s_addr = 0;	/* So that we will KEEP the next one */
		goto startover;	/* Try again */
	}

	return 1;
}

/* Undoes the previous target_struct_get operation */
void target_struct_return(struct targets *t)
{
	int octet;
	t->nleft++;
	if (t->maskformat) {
		assert(t->currentaddr.s_addr > t->start.s_addr);
		t->currentaddr.s_addr--;
	} else {
		for (octet = 3; octet >= 0; octet--) {
			if (t->current[octet] > 0) {
				/* OK, this is the column I have room to nudge downwards */
				t->current[octet]--;
				break;
			} else {
				/* This octet is already at the beginning, so I set it to the end */
				t->current[octet] = t->last[octet];
			}
		}
		assert(octet != -1);
	}
}

void hoststructfry(struct hoststruct *hostbatch, int nelem)
{
	genfry((unsigned char *) hostbatch, sizeof(struct hoststruct), nelem);
	return;
}

/* REMEMBER TO CALL hoststruct_free() on the hoststruct when you are done
   with it!!! */
struct hoststruct *nexthost(struct hostgroup_state *hs, struct scan_lists *ports, int *pingtype)
{
	int hidx;
	char *device;

	if (hs->next_batch_no < hs->current_batch_sz) {
		/* Woop!  This is easy -- we just pass back the next host struct */
		return &hs->hostbatch[hs->next_batch_no++];
	}

	/* Doh, we need to refresh our array */
	bzero(hs->hostbatch, hs->max_batch_sz * sizeof(struct hoststruct));
	hs->current_batch_sz = hs->next_batch_no = 0;
	do {
		/* Grab anything we have in our current_expression */
		while (hs->current_batch_sz < hs->max_batch_sz && target_struct_get(&hs->current_expression, &(hs->hostbatch[hs->current_batch_sz].host)) != -1) {
			hidx = hs->current_batch_sz;

			/* Lets figure out what device this IP uses ... */
			if (o.source) {
				memcpy((char *) &hs->hostbatch[hidx].source_ip, (char *) o.source, sizeof(struct in_addr));
				strcpy(hs->hostbatch[hidx].device, o.device);
			} else {
				/* We figure out the source IP/device IFF
				   1) We are r00t AND
				   2) We are doing tcp pingscan OR
				   3) We are doing a raw-mode portscan or osscan */
				if (o.isr00t &&
				    ((*pingtype & PINGTYPE_TCP) ||
				     o.synscan || o.finscan || o.xmasscan || o.nullscan || o.ipprotscan || o.maimonscan || o.idlescan || o.ackscan || o.udpscan || o.osscan || o.windowscan)) {
					device = routethrough(&(hs->hostbatch[hidx].host), &(hs->hostbatch[hidx].source_ip));
					if (!device) {
						if (*pingtype == PINGTYPE_NONE) {
							fatal("Could not determine what interface to route packets through, run again with -e <device>");
						} else {
							error
							    ("WARNING:  Could not determine what interface to route packets through to %s, changing ping scantype to ICMP ping only",
							     inet_ntoa(hs->hostbatch[hidx].host));
							*pingtype = PINGTYPE_ICMP_PING;
						}
					} else {
						strcpy(hs->hostbatch[hidx].device, device);
					}
				}
			}

			/* In some cases, we can only allow hosts that use the same device
			   in a group. */
			if (o.isr00t && hidx > 0 && *hs->hostbatch[hidx].device && hs->hostbatch[hidx].source_ip.s_addr != hs->hostbatch[0].source_ip.s_addr) {
				/* Cancel everything!  This guy must go in the next group and we are
				   outtof here */
				target_struct_return(&(hs->current_expression));
				goto batchfull;
			}

			hs->current_batch_sz++;
		}

		if (hs->current_batch_sz < hs->max_batch_sz && hs->next_expression < hs->num_expressions) {
			/* We are going to have to plop in another expression. */
			while (!parse_targets(&(hs->current_expression), hs->target_expressions[hs->next_expression++])) {
				if (hs->next_expression >= hs->num_expressions)
					break;
			}
		} else
			break;
	} while (1);
      batchfull:

	if (hs->current_batch_sz == 0)
		return NULL;

/* OK, now we have our complete batch of entries.  The next step is to
   randomize them (if requested) */
	if (hs->randomize) {
		hoststructfry(hs->hostbatch, hs->current_batch_sz);
	}


	return &hs->hostbatch[hs->next_batch_no++];
}

/* Frees the *INTERNAL STRUCTURES* inside a hoststruct -- does not
   free the actual memory allocated to the hoststruct itself (for all
   this function knows, you could have declared it on the stack */
void hoststruct_free(struct hoststruct *currenths)
{
	int i;

	/* Free the DNS name if we resolved one */
	if (currenths->name && *currenths->name)
		free(currenths->name);

	/* Free OS fingerprints of OS scanning was done */
	for (i = 0; i < currenths->numFPs; i++) {
		freeFingerPrint(currenths->FPs[i]);
		currenths->FPs[i] = NULL;
	}
	currenths->numFPs = 0;
	
	for(i=0; i< MAX_FP_RESULTS; i++) {	
		if (currenths->FPR.prints[i]!=NULL) {
			freeFingerPrint(currenths->FPR.prints[i]);
			currenths->FPR.prints[i]=NULL;
		} else {
			break;
		}
	}
	
	/* Free the port lists */
	resetportlist(&currenths->ports);

}



int parse_targets(struct targets *targets, char *h)
{
	int i = 0, j = 0, k = 0;
	int start, end;
	char *r, *s, *target_net;
	char *addy[5];
	char *hostexp = strdup(h);
	struct hostent *target;
	unsigned long longtmp;
	int namedhost = 0;

	bzero(targets, sizeof(*targets));
	targets->nleft = 0;
/*struct in_addr current_in;*/
	addy[0] = addy[1] = addy[2] = addy[3] = addy[4] = NULL;
	addy[0] = r = hostexp;
/* First we break the expression up into the four parts of the IP address
   + the optional '/mask' */
	target_net = strtok(hostexp, "/");
	s = strtok(NULL, "");	/* find the end of the token from hostexp */
	targets->netmask = (s) ? atoi(s) : 32;
	if ((int) targets->netmask < 0 || targets->netmask > 32) {
		fprintf(stderr, "Illegal netmask value (%d), must be /0 - /32 .  Assuming /32 (one host)\n", targets->netmask);
		targets->netmask = 32;
	}
	for (i = 0; *(hostexp + i); i++)
		if (isupper((int) *(hostexp + i))
		    || islower((int) *(hostexp + i))) {
			namedhost = 1;
			break;
		}
	if (targets->netmask != 32 || namedhost) {
		targets->maskformat = 1;
		if (!inet_aton(target_net, &(targets->start))) {
			if ((target = gethostbyname(target_net)))
				memcpy(&(targets->start), target->h_addr_list[0], sizeof(struct in_addr));
			else {
				fprintf(stderr, "Failed to resolve given hostname/IP: %s.  Note that you can't use '/mask' AND '[1-4,7,100-]' style IP ranges\n", target_net);
				free(hostexp);
				return 0;
			}
		}
		longtmp = ntohl(targets->start.s_addr);
		targets->start.s_addr = longtmp & (unsigned long) (0 - (1 << (32 - targets->netmask)));
		targets->end.s_addr = longtmp | (unsigned long) ((1 << (32 - targets->netmask)) - 1);
		targets->currentaddr = targets->start;
		if (targets->start.s_addr <= targets->end.s_addr) {
			targets->nleft = targets->end.s_addr - targets->start.s_addr + 1;
			free(hostexp);
			return 1;
		}
		fprintf(stderr, "Host specification invalid");
		free(hostexp);
		return 0;
	} else {
		i = 0;
		targets->maskformat = 0;
		while (*++r) {
			if (*r == '.' && ++i < 4) {
				*r = '\0';
				addy[i] = r + 1;
			} else if (*r == '[') {
				*r = '\0';
				addy[i]++;
			} else if (*r == ']')
				*r = '\0';
			/*else if ((*r == '/' || *r == '\\') && i == 3) {
			 *r = '\0';
			 addy[4] = r + 1;
			 }*/
			else if (*r != '*' && *r != ',' && *r != '-' && !isdigit((int) *r))
				fatal("Invalid character in  host specification.");
		}
		if (i != 3)
			fatal("Target host specification is illegal.");

		for (i = 0; i < 4; i++) {
			j = 0;
			while ((s = strchr(addy[i], ','))) {
				*s = '\0';
				if (*addy[i] == '*') {
					start = 0;
					end = 255;
				} else if (*addy[i] == '-') {
					start = 0;
					if (!addy[i] + 1)
						end = 255;
					else
						end = atoi(addy[i] + 1);
				} else {
					start = end = atoi(addy[i]);
					if ((r = strchr(addy[i], '-'))
					    && *(r + 1))
						end = atoi(r + 1);
					else if (r && !*(r + 1))
						end = 255;
				}
				if (o.debugging)
					log_write(LOG_STDOUT, "The first host is %d, and the last one is %d\n", start, end);
				if (start < 0 || start > end)
					fatal("Your host specifications are illegal!");
				for (k = start; k <= end; k++)
					targets->addresses[i][j++] = k;
				addy[i] = s + 1;
			}
			if (*addy[i] == '*') {
				start = 0;
				end = 255;
			} else if (*addy[i] == '-') {
				start = 0;
				if (!addy[i] + 1)
					end = 255;
				else
					end = atoi(addy[i] + 1);
			} else {
				start = end = atoi(addy[i]);
				if ((r = strchr(addy[i], '-')) && *(r + 1))
					end = atoi(r + 1);
				else if (r && !*(r + 1))
					end = 255;
			}
			if (o.debugging)
				log_write(LOG_STDOUT, "The first host is %d, and the last one is %d\n", start, end);
			if (start < 0 || start > end)
				fatal("Your host specifications are illegal!");
			if (j + (end - start) > 255)
				fatal("Your host specifications are illegal!");
			for (k = start; k <= end; k++)
				targets->addresses[i][j++] = k;
			targets->last[i] = j - 1;

		}
	}
	bzero((char *) targets->current, 4);
	targets->nleft = (targets->last[0] + 1) * (targets->last[1] + 1) * (targets->last[2] + 1) * (targets->last[3] + 1);
	free(hostexp);
	return 1;
}
