/*
 * (C) 2005 by Harald Welte <laforge@netfilter.org>
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
#include "conntrack.h"
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack_sctp.h>

static struct option opts[] = {
	{"orig-port-src", 1, 0, '1'},
	{"orig-port-dst", 1, 0, '2'},
	{"reply-port-src", 1, 0, '3'},
	{"reply-port-dst", 1, 0, '4'},
	{"state", 1, 0, '7'},
	{0, 0, 0, 0}
};

static const char *states[] = {
	"NONE",
	"CLOSED",
	"COOKIE_WAIT",
	"COOKIE_ECHOED",
	"ESTABLISHED",
	"SHUTDOWN_SENT",
	"SHUTDOWN_RECV",
	"SHUTDOWN_ACK_SENT",
};

static void help()
{
	fprintf(stdout, "--orig-port-src        original source port\n");
	fprintf(stdout, "--orig-port-dst        original destination port\n");
	fprintf(stdout, "--reply-port-src       reply source port\n");
	fprintf(stdout, "--reply-port-dst       reply destination port\n");
	fprintf(stdout, "--state                SCTP state, fe. ESTABLISHED\n");
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
				orig->l4src.sctp.port = htons(atoi(optarg));
				*flags |= SCTP_ORIG_SPORT;
			}
			break;
		case '2':
			if (optarg) {
				orig->l4dst.sctp.port = htons(atoi(optarg));
				*flags |= SCTP_ORIG_DPORT;
			}
			break;
		case '3':
			if (optarg) {
				reply->l4src.sctp.port = htons(atoi(optarg));
				*flags |= SCTP_REPL_SPORT;
			}
			break;
		case '4':
			if (optarg) {
				reply->l4dst.sctp.port = htons(atoi(optarg));
				*flags |= SCTP_REPL_DPORT;
			}
			break;
		case '5':
			if (optarg) {
				int i;
				for (i=0; i<10; i++) {
					if (strcmp(optarg, states[i]) == 0) {
						/* FIXME: Add state to
						 * nfct_protoinfo
						proto->sctp.state = i; */
						break;
					}
				}
				if (i == 10) {
					printf("doh?\n");
					return 0;
				}
				*flags |= SCTP_STATE;
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
	
	if ((flags & (SCTP_ORIG_SPORT|SCTP_ORIG_DPORT)) 
	    && !(flags & (SCTP_REPL_SPORT|SCTP_REPL_DPORT))) {
		reply->l4src.sctp.port = orig->l4dst.sctp.port;
		reply->l4dst.sctp.port = orig->l4src.sctp.port;
		ret = 1;
	} else if (!(flags & (SCTP_ORIG_SPORT|SCTP_ORIG_DPORT))
	            && (flags & (SCTP_REPL_SPORT|SCTP_REPL_DPORT))) {
		orig->l4src.sctp.port = reply->l4dst.sctp.port;
		orig->l4dst.sctp.port = reply->l4src.sctp.port;
		ret = 1;
	}
	if ((flags & (SCTP_ORIG_SPORT|SCTP_ORIG_DPORT)) 
	    && ((flags & (SCTP_REPL_SPORT|SCTP_REPL_DPORT))))
		ret = 1;

	/* --state is missing and we are trying to create a conntrack */
	if (ret && (command & CT_CREATE) && (!(flags & SCTP_STATE)))
		ret = 0;

	return ret;
}

static struct ctproto_handler sctp = {
	.name 			= "sctp",
	.protonum		= IPPROTO_SCTP,
	.parse_opts		= parse_options,
	.final_check		= final_check,
	.help			= help,
	.opts			= opts,
	.version		= VERSION,
};

static void __attribute__ ((constructor)) init(void);

static void init(void)
{
	register_proto(&sctp);
}
