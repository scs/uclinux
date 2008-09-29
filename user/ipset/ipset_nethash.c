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

#include <linux/netfilter_ipv4/ip_set_nethash.h>
#include <linux/netfilter_ipv4/ip_set_jhash.h>

#include "ipset.h"

#define BUFLEN 30;

#define OPT_CREATE_HASHSIZE	0x01U
#define OPT_CREATE_PROBES	0x02U
#define OPT_CREATE_RESIZE	0x04U

/* Initialize the create. */
void create_init(void *data)
{
	struct ip_set_req_nethash_create *mydata =
	    (struct ip_set_req_nethash_create *) data;

	DP("create INIT");

	/* Default create parameters */	
	mydata->hashsize = 1024;
	mydata->probes = 4;
	mydata->resize = 50;
}

/* Function which parses command options; returns true if it ate an option */
int create_parse(int c, char *argv[], void *data, unsigned *flags)
{
	struct ip_set_req_nethash_create *mydata =
	    (struct ip_set_req_nethash_create *) data;
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

	default:
		return 0;
	}

	return 1;
}

/* Final check; exit if not ok. */
void create_final(void *data, unsigned int flags)
{
#ifdef IPSET_DEBUG
	struct ip_set_req_nethash_create *mydata =
	    (struct ip_set_req_nethash_create *) data;

	DP("hashsize %u probes %u resize %u",
	   mydata->hashsize, mydata->probes, mydata->resize);
#endif
}

/* Create commandline options */
static struct option create_opts[] = {
	{"hashsize", 1, 0, '1'},
	{"probes", 1, 0, '2'},
	{"resize", 1, 0, '3'},
	{0}
};

/* Add, del, test parser */
ip_set_ip_t adt_parser(unsigned cmd, const char *optarg, void *data)
{
	struct ip_set_req_nethash *mydata =
	    (struct ip_set_req_nethash *) data;
	char *saved = ipset_strdup(optarg);
	char *ptr, *tmp = saved;
	ip_set_ip_t cidr;

	ptr = strsep(&tmp, "/");
	
	if (tmp == NULL) {
		if (cmd == CMD_TEST)
			cidr = 32;
		else
			exit_error(PARAMETER_PROBLEM,
				   "Missing cidr from `%s'", optarg);
	} else
		if (string_to_number(tmp, 1, 31, &cidr))
			exit_error(PARAMETER_PROBLEM,
				   "Out of range cidr `%s' specified", optarg);
	
	mydata->cidr = cidr;
	parse_ip(ptr, &mydata->ip);
	if (!mydata->ip)
		exit_error(PARAMETER_PROBLEM,
			  "Zero valued IP address `%s' specified", ptr);
	free(saved);

	return mydata->ip;	
};

/*
 * Print and save
 */

void initheader(struct set *set, const void *data)
{
	struct ip_set_req_nethash_create *header =
	    (struct ip_set_req_nethash_create *) data;
	struct ip_set_nethash *map =
		(struct ip_set_nethash *) set->settype->header;

	memset(map, 0, sizeof(struct ip_set_nethash));
	map->hashsize = header->hashsize;
	map->probes = header->probes;
	map->resize = header->resize;
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
	struct ip_set_nethash *mysetdata =
	    (struct ip_set_nethash *) set->settype->header;

	printf(" hashsize: %u", mysetdata->hashsize);
	printf(" probes: %u", mysetdata->probes);
	printf(" resize: %u\n", mysetdata->resize);
}

static char buf[20];

static char * unpack_ip_tostring(ip_set_ip_t ip, unsigned options)
{
	int i, j = 3;
	unsigned char a, b;

	ip = htonl(ip);	
	for (i = 3; i >= 0; i--)
		if (((unsigned char *)&ip)[i] != 0) {
			j = i;
			break;
		}
			
	a = ((unsigned char *)&ip)[j];
	if (a <= 128) {
		a = (a - 1) * 2;
		b = 7;
	} else if (a <= 192) {
		a = (a - 129) * 4;
		b = 6;
	} else if (a <= 224) {
		a = (a - 193) * 8;
		b = 5;
	} else if (a <= 240) {
		a = (a - 225) * 16;
		b = 4;
	} else if (a <= 248) {
		a = (a - 241) * 32;
		b = 3;
	} else if (a <= 252) {
		a = (a - 249) * 64;
		b = 2;
	} else if (a <= 254) {
		a = (a - 253) * 128;
		b = 1;
	} else {
		a = b = 0;
	}
	((unsigned char *)&ip)[j] = a;
	b += j * 8;
	
	sprintf(buf, "%u.%u.%u.%u/%u",
		((unsigned char *)&ip)[0],
		((unsigned char *)&ip)[1],
		((unsigned char *)&ip)[2],
		((unsigned char *)&ip)[3],
		b);

	DP("%s %s", ip_tostring(ntohl(ip), options), buf);
	return buf;
}

void printips(struct set *set, void *data, size_t len, unsigned options)
{
	size_t offset = 0;
	ip_set_ip_t *ip;

	while (offset < len) {
		ip = data + offset;
		if (*ip)
			printf("%s\n", unpack_ip_tostring(*ip, options));
		offset += sizeof(ip_set_ip_t);
	}
}

void saveheader(struct set *set, unsigned options)
{
	struct ip_set_nethash *mysetdata =
	    (struct ip_set_nethash *) set->settype->header;

	printf("-N %s %s --hashsize %u --probes %u --resize %u\n",
	       set->name, set->settype->typename,
	       mysetdata->hashsize, mysetdata->probes, mysetdata->resize);
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
			       unpack_ip_tostring(*ip, options));
		offset += sizeof(ip_set_ip_t);
	}
}

static char * net_tostring(struct set *set, ip_set_ip_t ip, unsigned options)
{
	return unpack_ip_tostring(ip, options);
}

static void parse_net(const char *str, ip_set_ip_t *ip)
{
	char *saved = strdup(str);
	char *ptr, *tmp = saved;
	ip_set_ip_t cidr;

	ptr = strsep(&tmp, "/");
	
	if (tmp == NULL)
		exit_error(PARAMETER_PROBLEM,
			   "Missing cidr from `%s'", str);

	if (string_to_number(tmp, 1, 31, &cidr))
		exit_error(PARAMETER_PROBLEM,
			   "Out of range cidr `%s' specified", str);
	
	parse_ip(ptr, ip);
	free(saved);
	
	*ip = pack(*ip, cidr);
}

void usage(void)
{
	printf
	    ("-N set nethash [--hashsize hashsize] [--probes probes ]\n"
	     "               [--resize resize]\n"
	     "-A set IP/cidr\n"
	     "-D set IP/cidr\n"
	     "-T set IP/cidr\n");
}

static struct settype settype_nethash = {
	.typename = SETTYPE_NAME,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	/* Create */
	.create_size = sizeof(struct ip_set_req_nethash_create),
	.create_init = &create_init,
	.create_parse = &create_parse,
	.create_final = &create_final,
	.create_opts = create_opts,

	/* Add/del/test */
	.adt_size = sizeof(struct ip_set_req_nethash),
	.adt_parser = &adt_parser,

	/* Printing */
	.header_size = sizeof(struct ip_set_nethash),
	.initheader = &initheader,
	.printheader = &printheader,
	.printips = &printips,		/* We only have the unsorted version */
	.printips_sorted = &printips,
	.saveheader = &saveheader,
	.saveips = &saveips,
	
	/* Bindings */
	.bindip_tostring = &net_tostring,
	.bindip_parse = &parse_net,

	.usage = &usage,
};

void _init(void)
{
	settype_register(&settype_nethash);

}
