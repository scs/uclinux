/* Copyright 2005 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/netfilter_ipv4/ip_set_iptree.h>
#include "ipset.h"

#define BUFLEN 30;

#define OPT_CREATE_TIMEOUT    0x01U

/* Initialize the create. */
void create_init(void *data)
{
	struct ip_set_req_iptree_create *mydata =
	    (struct ip_set_req_iptree_create *) data;

	DP("create INIT");
	mydata->timeout = 0;
}

/* Function which parses command options; returns true if it ate an option */
int create_parse(int c, char *argv[], void *data, unsigned *flags)
{
	struct ip_set_req_iptree_create *mydata =
	    (struct ip_set_req_iptree_create *) data;

	DP("create_parse");

	switch (c) {
	case '1':
		string_to_number(optarg, 0, UINT_MAX, &mydata->timeout);

		*flags |= OPT_CREATE_TIMEOUT;

		DP("--timeout %u", mydata->timeout);

		break;
	default:
		return 0;
	}

	return 1;
}

/* Final check; exit if not ok. */
void create_final(void *data, unsigned int flags)
{
}

/* Create commandline options */
static struct option create_opts[] = {
	{"timeout", 1, 0, '1'},
	{0}
};

/* Add, del, test parser */
ip_set_ip_t adt_parser(unsigned cmd, const char *optarg, void *data)
{
	struct ip_set_req_iptree *mydata =
	    (struct ip_set_req_iptree *) data;
	char *saved = ipset_strdup(optarg);
	char *ptr, *tmp = saved;

	DP("iptree: %p %p", optarg, data);

	ptr = strsep(&tmp, "%");
	parse_ip(ptr, &mydata->ip);

	if (tmp)
		string_to_number(tmp, 0, UINT_MAX, &mydata->timeout);
	else
		mydata->timeout = 0;	

	free(saved);
	return 1;	
}

/*
 * Print and save
 */

void initheader(struct set *set, const void *data)
{
	struct ip_set_req_iptree_create *header =
	    (struct ip_set_req_iptree_create *) data;
	struct ip_set_iptree *map =
		(struct ip_set_iptree *) set->settype->header;
		
	map->timeout = header->timeout;
}

void printheader(struct set *set, unsigned options)
{
	struct ip_set_iptree *mysetdata =
	    (struct ip_set_iptree *) set->settype->header;

	if (mysetdata->timeout)
		printf(" timeout: %u", mysetdata->timeout);
	printf("\n");
}

void printips_sorted(struct set *set, void *data, size_t len, unsigned options)
{
	struct ip_set_iptree *mysetdata =
	    (struct ip_set_iptree *) set->settype->header;
	struct ip_set_req_iptree *req;
	size_t offset = 0;

	while (len >= offset + sizeof(struct ip_set_req_iptree)) {
		req = (struct ip_set_req_iptree *)(data + offset);
		if (mysetdata->timeout)
			printf("%s%%%u\n", ip_tostring(req->ip, options),
					   req->timeout);
		else
			printf("%s\n", ip_tostring(req->ip, options));
		offset += sizeof(struct ip_set_req_iptree);
	}
}

void saveheader(struct set *set, unsigned options)
{
	struct ip_set_iptree *mysetdata =
	    (struct ip_set_iptree *) set->settype->header;

	if (mysetdata->timeout)
		printf("-N %s %s --timeout %u\n",
		       set->name, set->settype->typename,
		       mysetdata->timeout);
	else
		printf("-N %s %s\n",
		       set->name, set->settype->typename);
}

void saveips(struct set *set, void *data, size_t len, unsigned options)
{
	struct ip_set_iptree *mysetdata =
	    (struct ip_set_iptree *) set->settype->header;
	struct ip_set_req_iptree *req;
	size_t offset = 0;

	DP("%s", set->name);

	while (len >= offset + sizeof(struct ip_set_req_iptree)) {
		req = (struct ip_set_req_iptree *)(data + offset);
		if (mysetdata->timeout)
			printf("-A %s %s%%%u\n",
				set->name, 
				ip_tostring(req->ip, options),
				req->timeout);
		else
			printf("-A %s %s\n", 
				set->name,
				ip_tostring(req->ip, options));
		offset += sizeof(struct ip_set_req_iptree);
	}
}

void usage(void)
{
	printf
	    ("-N set iptree [--timeout value]\n"
	     "-A set IP[%%timeout]\n"
	     "-D set IP\n"
	     "-T set IP\n");
}

static struct settype settype_iptree = {
	.typename = SETTYPE_NAME,
	.protocol_version = IP_SET_PROTOCOL_VERSION,

	/* Create */
	.create_size = sizeof(struct ip_set_req_iptree_create),
	.create_init = &create_init,
	.create_parse = &create_parse,
	.create_final = &create_final,
	.create_opts = create_opts,

	/* Add/del/test */
	.adt_size = sizeof(struct ip_set_req_iptree),
	.adt_parser = &adt_parser,

	/* Printing */
	.header_size = sizeof(struct ip_set_iptree),
	.initheader = &initheader,
	.printheader = &printheader,
	.printips = &printips_sorted,	/* We only have sorted version */
	.printips_sorted = &printips_sorted,
	.saveheader = &saveheader,
	.saveips = &saveips,
	
	/* Bindings */
	.bindip_tostring = &binding_ip_tostring,
	.bindip_parse	= &parse_ip,

	.usage = &usage,
};

void _init(void)
{
	settype_register(&settype_iptree);

}
