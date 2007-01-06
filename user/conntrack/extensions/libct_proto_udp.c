/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
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
#include "conntrack.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_udp.h>

static struct option opts[] = {
	{"orig-port-src", 1, 0, '1'},
	{"orig-port-dst", 1, 0, '2'},
	{"reply-port-src", 1, 0, '3'},
	{"reply-port-dst", 1, 0, '4'},
	{"mask-port-src", 1, 0, '5'},
	{"mask-port-dst", 1, 0, '6'},
	{0, 0, 0, 0}
};

static void help()
{
	fprintf(stdout, "--orig-port-src        original source port\n");
	fprintf(stdout, "--orig-port-dst        original destination port\n");
	fprintf(stdout, "--reply-port-src       reply source port\n");
	fprintf(stdout, "--reply-port-dst       reply destination port\n");
	fprintf(stdout, "--mask-port-src	mask source port\n");
	fprintf(stdout, "--mask-port-dst	mask destination port\n");
}

static int parse_options(char c, char *argv[], 
			 struct nfct_tuple *orig,
			 struct nfct_tuple *reply,
			 struct nfct_tuple *mask,
			 union nfct_protoinfo *proto,
			 unsigned int *flags)
{
	switch(c) {
		case '1':
			if (optarg) {
				orig->l4src.udp.port = htons(atoi(optarg));
				*flags |= UDP_ORIG_SPORT;
			}
			break;
		case '2':
			if (optarg) {
				orig->l4dst.udp.port = htons(atoi(optarg));
				*flags |= UDP_ORIG_DPORT;
			}
			break;
		case '3':
			if (optarg) {
				reply->l4src.udp.port = htons(atoi(optarg));
				*flags |= UDP_REPL_SPORT;
			}
			break;
		case '4':
			if (optarg) {
				reply->l4dst.udp.port = htons(atoi(optarg));
				*flags |= UDP_REPL_DPORT;
			}
			break;
		case '5':
			if (optarg) {
				mask->l4src.udp.port = htons(atoi(optarg));
				*flags |= UDP_MASK_SPORT;
			}
			break;
		case '6':
			if (optarg) {
				mask->l4dst.udp.port = htons(atoi(optarg));
				*flags |= UDP_MASK_DPORT;
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
	if ((flags & (UDP_ORIG_SPORT|UDP_ORIG_DPORT)) 
	    && !(flags & (UDP_REPL_SPORT|UDP_REPL_DPORT))) {
		reply->l4src.udp.port = orig->l4dst.udp.port;
		reply->l4dst.udp.port = orig->l4src.udp.port;
		return 1;
	} else if (!(flags & (UDP_ORIG_SPORT|UDP_ORIG_DPORT))
	            && (flags & (UDP_REPL_SPORT|UDP_REPL_DPORT))) {
		orig->l4src.udp.port = reply->l4dst.udp.port;
		orig->l4dst.udp.port = reply->l4src.udp.port;
		return 1;
	}
	if ((flags & (UDP_ORIG_SPORT|UDP_ORIG_DPORT)) 
	    && ((flags & (UDP_REPL_SPORT|UDP_REPL_DPORT))))
		return 1;

	return 0;
}

static struct ctproto_handler udp = {
	.name 			= "udp",
	.protonum		= IPPROTO_UDP,
	.parse_opts		= parse_options,
	.final_check		= final_check,
	.help			= help,
	.opts			= opts,
	.version		= VERSION,
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
	register_proto(&udp);
}
