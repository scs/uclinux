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

#include <linux/netfilter_ipv4/ip_set_iphash.h>
#include <linux/netfilter_ipv4/ip_set_jhash.h>

#include "ipset.h"

#define BUFLEN 30;

#define OPT_CREATE_HASHSIZE	0x01U
#define OPT_CREATE_PROBES	0x02U
#define OPT_CREATE_RESIZE	0x04U
#define OPT_CREATE_NETMASK	0x08U

/* Initialize the create. */
void create_init(void *data)
{
	struct ip_set_req_iphash_create *mydata =
	    (struct ip_set_req_iphash_create *) data;

	DP("create INIT");

	/* Default create parameters */	
	mydata->hashsize = 1024;
	mydata->probes = 8;
	mydata->resize = 50;
	
	mydata->netmask = 0xFFFFFFFF;
}

/* Function which parses command options; returns true if it ate an option */
int create_parse(int c, char *argv[], void *data, unsigned *flags)
{
	struct ip_set_req_iphash_create *mydata =
	    (struct ip_set_req_iphash_create *) data;
	unsigned int bits;
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

		if (string_to_number(optarg, 0, 32, &bits))
			exit_error(PARAMETER_PROBLEM, 
				  "Invalid netmask `%s' specified", optarg);
		
		if (bits != 0)
			mydata->netmask = 0xFFFFFFFF << (32 - bits);

		*flags |= OPT_CREATE_NETMASK;

		DP("--netmask %x", mydata->netmask);
		
		break;

	default:
		return 0;
	}

	return 1;
}

/* Final check; exit if not ok. */
void create_final(void *data, unsigned int flags)
{
#ifdef IPSET_DEBUG
	struct ip_set_req_iphash_create *mydata =
	    (struct ip_set_req_iphash_create *) data;

	DP("hashsize %u probes %u resize %u",
	   mydata->hashsize, mydata->probes, mydata->resize);
#endif
}

/* Create commandline options */
static struct option create_opts[] = {
	{"hashsize", 1, 0, '1'},
	{"probes", 1, 0, '2'},
	{"resize", 1, 0, '3'},
	{"netmask", 1, 0, '4'},
	{0}
};

/* Add, del, test parser */
ip_set_ip_t adt_parser(unsigned cmd, const char *optarg, void *data)
{
	struct ip_set_req_iphash *mydata =
	    (struct ip_set_req_iphash *) data;

	parse_ip(optarg, &mydata->ip);
	if (!mydata->ip)
		exit_error(PARAMETER_PROBLEM,
			   "Zero valued IP address `%s' specified", optarg);

	return mydata->ip;	
};

/*
 * Print and save
 */

void initheader(struct set *set, const void *data)
{
	struct ip_set_req_iphash_create *header =
	    (struct ip_set_req_iphash_create *) data;
	struct ip_set_iphash *map =
		(struct ip_set_iphash *) set->settype->header;

	memset(map, 0, sizeof(struct ip_set_iphash));
	map->hashsize = header->hashsize;
	map->probes = header->probes;
	map->resize = header->resize;
	map->netmask = header->netmask;
}

unsigned int
mask_to_bits(ip_set_ip_t mask)
{
	unsigned int bits = 32;
	ip_set_ip_t maskaddr;
	
	if (mask == 0xFFFFFFFF)
		return bits;
	
	maskaddr = 0xFFFFFFFE;
	while (--bits >= 0 && maskaddr != mask)
		maskaddr <<= 1;
	
	return bits;
}
	
void printheader(struct set *set, unsigned options)
{
	struct ip_set_iphash *mysetdata =
	    (struct ip_set_iphash *) set->settype->header;

	printf(" hashsize: %u", mysetdata->hashsize);
	printf(" probes: %u", mysetdata->probes);
	printf(" resize: %u", mysetdata->resize);
	if (mysetdata->netmask == 0xFFFFFFFF)
		printf("\n");
	else
		printf(" netmask: %d\n", mask_to_bits(mysetdata->netmask));
}

void printips(struct set *set, void *data, size_t len, unsigned options)
{
	size_t offset = 0;
	ip_set_ip_t *ip;

	while (offset < len) {
		ip = data + offset;
		if (*ip)
			printf("%s\n", ip_tostring(*ip, options));
		offset += sizeof(ip_set_ip_t);
	}
}

void saveheader(struct set *set, unsigned options)
{
	struct ip_set_iphash *mysetdata =
	    (struct ip_set_iphash *) set->settype->header;

	printf("-N %s %s --hashsize %u --probes %u --resize %u",
	       set->name, set->settype->typename,
	       mysetdata->hashsize, mysetdata->probes, mysetdata->resize);
	if (mysetdata->netmask == 0xFFFFFFFF)
		printf("\n");
	else
		printf(" --netmask %d\n", mask_to_bits(mysetdata->netmask));
}

/* Print save for an IP */
void saveips(struct set *set, void *data, size_t len, unsigned options)
{
	size_t offset = 0;
	ip_set_ip_t *ip;

	while (offset < len) {
		ip = data + offset;
		if (*ip)
			printf("-A %s %s\n", set->name, 
			       ip_tostring(*ip, options));
		offset += sizeof(ip_set_ip_t);
	}
}

void usage(void)
{
	printf
	    ("-N set iphash [--hashsize hashsize] [--probes probes ]\n"
	     "              [--resize resize] [--netmask CIDR-netmask]\n"
	     "-A set IP\n"
	     "-D set IP\n"
	     "-T set IP\n");
}

static struct settype settype_iphash = {
	.typename = SETTYPE_NAME,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	/* Create */
	.create_size = sizeof(struct ip_set_req_iphash_create),
	.create_init = &create_init,
	.create_parse = &create_parse,
	.create_final = &create_final,
	.create_opts = create_opts,

	/* Add/del/test */
	.adt_size = sizeof(struct ip_set_req_iphash),
	.adt_parser = &adt_parser,

	/* Printing */
	.header_size = sizeof(struct ip_set_iphash),
	.initheader = &initheader,
	.printheader = &printheader,
	.printips = &printips,		/* We only have the unsorted version */
	.printips_sorted = &printips,
	.saveheader = &saveheader,
	.saveips = &saveips,
	
	/* Bindings */
	.bindip_tostring = &binding_ip_tostring,
	.bindip_parse = &parse_ip,
	
	.usage = &usage,
};

void _init(void)
{
	settype_register(&settype_iphash);

}
