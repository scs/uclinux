/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_TCP_H_
#define _LIBNETFILTER_CONNTRACK_TCP_H_

enum tcp_flags {
	TCP_ORIG_SPORT_BIT = 0,
	TCP_ORIG_SPORT = (1 << TCP_ORIG_SPORT_BIT),

	TCP_ORIG_DPORT_BIT = 1,
	TCP_ORIG_DPORT = (1 << TCP_ORIG_DPORT_BIT),

	TCP_REPL_SPORT_BIT = 2,
	TCP_REPL_SPORT = (1 << TCP_REPL_SPORT_BIT),

	TCP_REPL_DPORT_BIT = 3,
	TCP_REPL_DPORT = (1 << TCP_REPL_DPORT_BIT),

	TCP_MASK_SPORT_BIT = 4,
	TCP_MASK_SPORT = (1 << TCP_MASK_SPORT_BIT),

	TCP_MASK_DPORT_BIT = 5,
	TCP_MASK_DPORT = (1 << TCP_MASK_DPORT_BIT),

	TCP_STATE_BIT = 6,
	TCP_STATE = (1 << TCP_STATE_BIT)
};

#endif
