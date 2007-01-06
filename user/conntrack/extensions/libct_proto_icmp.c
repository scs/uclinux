/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *	       Harald Welte <laforge@netfilter.org>
 *
 *      This program is free software; you can redistribute it and/or modify
 *      it under the terms of the GNU General Public License as published by
 *      the Free Software Foundation; either version 2 of the License, or
 *      (at your option) any later version.
 *
 */
#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <netinet/in.h> /* For htons */
#include <netinet/ip_icmp.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_icmp.h>
#include "conntrack.h"

static struct option opts[] = {
	{"icmp-type", 1, 0, '1'},
	{"icmp-code", 1, 0, '2'},
	{"icmp-id", 1, 0, '3'},
	{0, 0, 0, 0}
};

static void help()
{
	fprintf(stdout, "--icmp-type            icmp type\n");
	fprintf(stdout, "--icmp-code            icmp code\n");
	fprintf(stdout, "--icmp-id              icmp id\n");
}

/* Add 1; spaces filled with 0. */
static u_int8_t invmap[]
	= { [ICMP_ECHO] = ICMP_ECHOREPLY + 1,
	    [ICMP_ECHOREPLY] = ICMP_ECHO + 1,
	    [ICMP_TIMESTAMP] = ICMP_TIMESTAMPREPLY + 1,
	    [ICMP_TIMESTAMPREPLY] = ICMP_TIMESTAMP + 1,
	    [ICMP_INFO_REQUEST] = ICMP_INFO_REPLY + 1,
	    [ICMP_INFO_REPLY] = ICMP_INFO_REQUEST + 1,
	    [ICMP_ADDRESS] = ICMP_ADDRESSREPLY + 1,
	    [ICMP_ADDRESSREPLY] = ICMP_ADDRESS + 1};

static int parse(char c, char *argv[], 
		 struct nfct_tuple *orig,
		 struct nfct_tuple *reply,
		 struct nfct_tuple *mask,
		 union nfct_protoinfo *proto,
		 unsigned int *flags)
{
	switch(c) {
		case '1':
			if (optarg) {
				orig->l4dst.icmp.type = atoi(optarg);
				reply->l4dst.icmp.type =
					invmap[orig->l4dst.icmp.type] - 1;
				*flags |= ICMP_TYPE;
			}
			break;
		case '2':
			if (optarg) {
				orig->l4dst.icmp.code = atoi(optarg);
				reply->l4dst.icmp.code = 0;
				*flags |= ICMP_CODE;
			}
			break;
		case '3':
			if (optarg) {
				orig->l4src.icmp.id = htons(atoi(optarg));
				reply->l4dst.icmp.id = 0;
				*flags |= ICMP_ID;
			}
			break;
	}
	return 1;
}

static int final_check(unsigned int flags,
		       unsigned int command,
		       struct nfct_tuple *orig,
		       struct nfct_tuple *reply)
{
	if (!(flags & ICMP_TYPE))
		return 0;
	else if (!(flags & ICMP_CODE))
		return 0;

	return 1;
}

static struct ctproto_handler icmp = {
	.name 		= "icmp",
	.protonum	= IPPROTO_ICMP,
	.parse_opts	= parse,
	.final_check	= final_check,
	.help		= help,
	.opts		= opts,
	.version	= VERSION,
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
	register_proto(&icmp);
}
