/* Copyright 2004 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License as published by   
 * the Free Software Foundation; either version 2 of the License, or      
 * (at your option) any later version.                                    
 *                                                                         
 * This program is distributed in the hope that it will be useful,        
 * but WITHOUT ANY WARRANTY; without even the implied warranty of         
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the          
 * GNU General Public License for more details.                           
 *                                                                         
 * You should have received a copy of the GNU General Public License      
 * along with this program; if not, write to the Free Software            
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <asm/types.h>

#include <linux/netfilter_ipv4/ip_set_ipporthash.h>
#include <linux/netfilter_ipv4/ip_set_jhash.h>

#include "ipset.h"

#define OPT_CREATE_HASHSIZE	0x01U
#define OPT_CREATE_PROBES	0x02U
#define OPT_CREATE_RESIZE	0x04U
#define OPT_CREATE_NETWORK	0x08U
#define OPT_CREATE_FROM		0x10U
#define OPT_CREATE_TO		0x20U

/* Initialize the create. */
void create_init(void *data)
{
	struct ip_set_req_ipporthash_create *mydata =
	    (struct ip_set_req_ipporthash_create *) data;

	DP("create INIT");

	/* Default create parameters */	
	mydata->hashsize = 1024;
	mydata->probes = 8;
	mydata->resize = 50;
}

/* Function which parses command options; returns true if it ate an option */
int create_parse(int c, char *argv[], void *data, unsigned *flags)
{
	struct ip_set_req_ipporthash_create *mydata =
	    (struct ip_set_req_ipporthash_create *) data;
	ip_set_ip_t value;

	DP("create_parse");

	switch (c) {
	case '1':

		if (string_to_number(optarg, 1, UINT_MAX - 1, &mydata->hashsize))
			exit_error(PARAMETER_PROBLEM, "Invalid hashsize `%s' specified", optarg);

		*flags |= OPT_CREATE_HASHSIZE;

		DP("--hashsize %u", mydata->hashsize);
		
		break;

	case '2':

		if (string_to_number(optarg, 1, 65535, &value))
			exit_error(PARAMETER_PROBLEM, "Invalid probes `%s' specified", optarg);

		mydata->probes = value;
		*flags |= OPT_CREATE_PROBES;

		DP("--probes %u", mydata->probes);
		
		break;

	case '3':

		if (string_to_number(optarg, 0, 65535, &value))
			exit_error(PARAMETER_PROBLEM, "Invalid resize `%s' specified", optarg);

		mydata->resize = value;
		*flags |= OPT_CREATE_RESIZE;

		DP("--resize %u", mydata->resize);
		
		break;

	case '4':
		parse_ip(optarg, &mydata->from);

		*flags |= OPT_CREATE_FROM;

		DP("--from %x (%s)", mydata->from,
		   ip_tostring_numeric(mydata->from));

		break;

	case '5':
		parse_ip(optarg, &mydata->to);

		*flags |= OPT_CREATE_TO;

		DP("--to %x (%s)", mydata->to,
		   ip_tostring_numeric(mydata->to));

		break;

	case '6':
		parse_ipandmask(optarg, &mydata->from, &mydata->to);

		/* Make to the last of from + mask */
		if (mydata->to)
			mydata->to = mydata->from | ~(mydata->to);
		else {
			mydata->from = 0x00000000;
			mydata->to = 0xFFFFFFFF;
		}
		*flags |= OPT_CREATE_NETWORK;

		DP("--network from %x (%s)", 
		   mydata->from, ip_tostring_numeric(mydata->from));
		DP("--network to %x (%s)", 
		   mydata->to, ip_tostring_numeric(mydata->to));

		break;

	default:
		return 0;
	}

	return 1;
}

/* Final check; exit if not ok. */
void create_final(void *data, unsigned int flags)
{
	struct ip_set_req_ipporthash_create *mydata =
	    (struct ip_set_req_ipporthash_create *) data;

#ifdef IPSET_DEBUG
	DP("hashsize %u probes %u resize %u",
	   mydata->hashsize, mydata->probes, mydata->resize);
#endif

	if (flags & OPT_CREATE_NETWORK) {
		/* --network */
		if ((flags & OPT_CREATE_FROM) || (flags & OPT_CREATE_TO))
			exit_error(PARAMETER_PROBLEM,
				   "Can't specify --from or --to with --network\n");
	} else if (flags & (OPT_CREATE_FROM | OPT_CREATE_TO)) {
		/* --from --to */
		if (!(flags & OPT_CREATE_FROM) || !(flags & OPT_CREATE_TO))
			exit_error(PARAMETER_PROBLEM,
				   "Need to specify both --from and --to\n");
	} else {
		exit_error(PARAMETER_PROBLEM,
			   "Need to specify --from and --to, or --network\n");

	}

	DP("from : %x to: %x diff: %x", 
	   mydata->from, mydata->to,
	   mydata->to - mydata->from);

	if (mydata->from > mydata->to)
		exit_error(PARAMETER_PROBLEM,
			   "From can't be higher than to.\n");

	if (mydata->to - mydata->from > MAX_RANGE)
		exit_error(PARAMETER_PROBLEM,
			   "Range to large. Max is %d IPs in range\n",
			   MAX_RANGE+1);
}

/* Create commandline options */
static struct option create_opts[] = {
	{"hashsize", 1, 0, '1'},
	{"probes", 1, 0, '2'},
	{"resize", 1, 0, '3'},
	{"from", 1, 0, '4'},
	{"to", 1, 0, '5'},
	{"network", 1, 0, '6'},
	{0}
};

/* Add, del, test parser */
ip_set_ip_t adt_parser(unsigned cmd, const char *optarg, void *data)
{
	struct ip_set_req_ipporthash *mydata =
	    (struct ip_set_req_ipporthash *) data;
	char *saved = ipset_strdup(optarg);
	char *ptr, *tmp = saved;

	DP("ipporthash: %p %p", optarg, data);

	ptr = strsep(&tmp, "%");
	parse_ip(ptr, &mydata->ip);

	if (tmp)
		parse_port(tmp, &mydata->port);
	else
		exit_error(PARAMETER_PROBLEM,
			   "IP address and port must be specified: ip%%port");
	free(saved);
	return 1;	
};

/*
 * Print and save
 */

void initheader(struct set *set, const void *data)
{
	struct ip_set_req_ipporthash_create *header =
	    (struct ip_set_req_ipporthash_create *) data;
	struct ip_set_ipporthash *map =
		(struct ip_set_ipporthash *) set->settype->header;

	memset(map, 0, sizeof(struct ip_set_ipporthash));
	map->hashsize = header->hashsize;
	map->probes = header->probes;
	map->resize = header->resize;
	map->first_ip = header->from;
	map->last_ip = header->to;
}

void printheader(struct set *set, unsigned options)
{
	struct ip_set_ipporthash *mysetdata =
	    (struct ip_set_ipporthash *) set->settype->header;

	printf(" from: %s", ip_tostring(mysetdata->first_ip, options));
	printf(" to: %s", ip_tostring(mysetdata->last_ip, options));
	printf(" hashsize: %u", mysetdata->hashsize);
	printf(" probes: %u", mysetdata->probes);
	printf(" resize: %u\n", mysetdata->resize);
}

void printips(struct set *set, void *data, size_t len, unsigned options)
{
	struct ip_set_ipporthash *mysetdata =
	    (struct ip_set_ipporthash *) set->settype->header;
	size_t offset = 0;
	ip_set_ip_t *ipptr, ip;
	uint16_t port;

	while (offset < len) {
		ipptr = data + offset;
		if (*ipptr) {
			ip = (*ipptr>>16) + mysetdata->first_ip;
			port = (uint16_t) *ipptr;
			printf("%s%%%s\n", 
			       ip_tostring(ip, options),
			       port_tostring(port, options));
		}
		offset += sizeof(ip_set_ip_t);
	}
}

void saveheader(struct set *set, unsigned options)
{
	struct ip_set_ipporthash *mysetdata =
	    (struct ip_set_ipporthash *) set->settype->header;

	printf("-N %s %s --from %s",
	       set->name, set->settype->typename,
	       ip_tostring(mysetdata->first_ip, options));
	printf(" --to %s",
	       ip_tostring(mysetdata->last_ip, options));
	printf(" --hashsize %u --probes %u --resize %u\n",
	       mysetdata->hashsize, mysetdata->probes, mysetdata->resize);
}

/* Print save for an IP */
void saveips(struct set *set, void *data, size_t len, unsigned options)
{
	struct ip_set_ipporthash *mysetdata =
	    (struct ip_set_ipporthash *) set->settype->header;
	size_t offset = 0;
	ip_set_ip_t *ipptr, ip;
	uint16_t port;

	while (offset < len) {
		ipptr = data + offset;
		if (*ipptr) {
			ip = (*ipptr>>16) + mysetdata->first_ip;
			port = (uint16_t) *ipptr;
			printf("-A %s %s%%%s\n", set->name, 
			       ip_tostring(ip, options),
			       port_tostring(port, options));
		}
		offset += sizeof(ip_set_ip_t);
	}
}

static char buffer[22];

static char * unpack_ipport_tostring(struct set *set, ip_set_ip_t bip, unsigned options)
{
	struct ip_set_ipporthash *mysetdata =
	    (struct ip_set_ipporthash *) set->settype->header;
	ip_set_ip_t ip, port;
	
	ip = (bip>>16) + mysetdata->first_ip;
	port = (uint16_t) bip;
	sprintf(buffer, "%s%%%s", 
		ip_tostring(ip, options), port_tostring(port, options));
		
	return buffer;
}

void usage(void)
{
	printf
	    ("-N set ipporthash --from IP --to IP\n"
	     "   [--hashsize hashsize] [--probes probes ] [--resize resize]\n"
	     "-N set ipporthash --network IP/mask\n"
	     "   [--hashsize hashsize] [--probes probes ] [--resize resize]\n"
	     "-A set IP%%port\n"
	     "-D set IP%%port\n"
	     "-T set IP%%port\n");
}

static struct settype settype_ipporthash = {
	.typename = SETTYPE_NAME,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	/* Create */
	.create_size = sizeof(struct ip_set_req_ipporthash_create),
	.create_init = &create_init,
	.create_parse = &create_parse,
	.create_final = &create_final,
	.create_opts = create_opts,

	/* Add/del/test */
	.adt_size = sizeof(struct ip_set_req_ipporthash),
	.adt_parser = &adt_parser,

	/* Printing */
	.header_size = sizeof(struct ip_set_ipporthash),
	.initheader = &initheader,
	.printheader = &printheader,
	.printips = &printips,		/* We only have the unsorted version */
	.printips_sorted = &printips,
	.saveheader = &saveheader,
	.saveips = &saveips,
	
	/* Bindings */
	.bindip_tostring = &unpack_ipport_tostring,
	.bindip_parse = &parse_ip,
	
	.usage = &usage,
};

void _init(void)
{
	settype_register(&settype_ipporthash);

}
