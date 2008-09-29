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
#include <string.h>
#include <netinet/in.h> /* For htons */
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_tcp.h>

#include "conntrack.h"

static struct option opts[] = {
	{"orig-port-src", 1, 0, '1'},
	{"orig-port-dst", 1, 0, '2'},
	{"reply-port-src", 1, 0, '3'},
	{"reply-port-dst", 1, 0, '4'},
	{"mask-port-src", 1, 0, '5'},
	{"mask-port-dst", 1, 0, '6'},
	{"state", 1, 0, '7'},
	{0, 0, 0, 0}
};

static const char *states[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"LISTEN"
};

static void help()
{
	fprintf(stdout, "--orig-port-src        original source port\n");
	fprintf(stdout, "--orig-port-dst        original destination port\n");
	fprintf(stdout, "--reply-port-src       reply source port\n");
	fprintf(stdout, "--reply-port-dst       reply destination port\n");
	fprintf(stdout, "--mask-port-src	mask source port\n");
	fprintf(stdout, "--mask-port-dst	mask destination port\n");
	fprintf(stdout, "--state                TCP state, fe. ESTABLISHED\n");
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
				orig->l4src.tcp.port = htons(atoi(optarg));
				*flags |= TCP_ORIG_SPORT;
			}
			break;
		case '2':
			if (optarg) {
				orig->l4dst.tcp.port = htons(atoi(optarg));
				*flags |= TCP_ORIG_DPORT;
			}
			break;
		case '3':
			if (optarg) {
				reply->l4src.tcp.port = htons(atoi(optarg));
				*flags |= TCP_REPL_SPORT;
			}
			break;
		case '4':
			if (optarg) {
				reply->l4dst.tcp.port = htons(atoi(optarg));
				*flags |= TCP_REPL_DPORT;
			}
			break;
		case '5':
			if (optarg) {
				mask->l4src.tcp.port = htons(atoi(optarg));
				*flags |= TCP_MASK_SPORT;
			}
			break;
		case '6':
			if (optarg) {
				mask->l4dst.tcp.port = htons(atoi(optarg));
				*flags |= TCP_MASK_DPORT;
			}
			break;
		case '7':
			if (optarg) {
				int i;
				for (i=0; i<10; i++) {
					if (strcmp(optarg, states[i]) == 0) {
						proto->tcp.state = i;
						break;
					}
				}
				if (i == 10) {
					printf("doh?\n");
					return 0;
				}
				*flags |= TCP_STATE;
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
	int ret = 0;
	
	if ((flags & (TCP_ORIG_SPORT|TCP_ORIG_DPORT)) 
	    && !(flags & (TCP_REPL_SPORT|TCP_REPL_DPORT))) {
		reply->l4src.tcp.port = orig->l4dst.tcp.port;
		reply->l4dst.tcp.port = orig->l4src.tcp.port;
		ret = 1;
	} else if (!(flags & (TCP_ORIG_SPORT|TCP_ORIG_DPORT))
	            && (flags & (TCP_REPL_SPORT|TCP_REPL_DPORT))) {
		orig->l4src.tcp.port = reply->l4dst.tcp.port;
		orig->l4dst.tcp.port = reply->l4src.tcp.port;
		ret = 1;
	}
	if ((flags & (TCP_ORIG_SPORT|TCP_ORIG_DPORT)) 
	    && ((flags & (TCP_REPL_SPORT|TCP_REPL_DPORT))))
		ret = 1;

	/* --state is missing and we are trying to create a conntrack */
	if (ret && (command & CT_CREATE) && (!(flags & TCP_STATE)))
		ret = 0;

	return ret;
}

static struct ctproto_handler tcp = {
	.name 			= "tcp",
	.protonum		= IPPROTO_TCP,
	.parse_opts		= parse_options,
	.final_check		= final_check,
	.help			= help,
	.opts			= opts,
	.version		= VERSION,
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
	register_proto(&tcp);
}
