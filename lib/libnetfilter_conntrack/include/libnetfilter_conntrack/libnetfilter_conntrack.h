/*
 * (C) 2005 by Pablo Neira Ayuso <pablo@eurodev.net>
 *
 * This software may be used and distributed according to the terms
 * of the GNU General Public License, incorporated herein by reference.
 */

#ifndef _LIBNETFILTER_CONNTRACK_H_
#define _LIBNETFILTER_CONNTRACK_H_

#include <netinet/in.h>
#include <libnfnetlink/linux_nfnetlink.h>
#include <libnfnetlink/libnfnetlink.h>
#include <libnetfilter_conntrack/linux_nfnetlink_conntrack.h> 

enum {
	CONNTRACK = NFNL_SUBSYS_CTNETLINK,
	EXPECT = NFNL_SUBSYS_CTNETLINK_EXP
};

/*
 * In case that the user doesn't want to do some kind
 * of action against a conntrack based on its ID 
 */
#define NFCT_ANY_ID 0

/*
 * Subscribe to all possible conntrack event groups. Use this 
 * flag in case that you want to catch up all the possible 
 * events. Do not use this flag for dumping or any other
 * similar operation.
 */
#define NFCT_ALL_CT_GROUPS (NF_NETLINK_CONNTRACK_NEW|NF_NETLINK_CONNTRACK_UPDATE|NF_NETLINK_CONNTRACK_DESTROY)

union nfct_l4 {
	/* Add other protocols here. */
	u_int16_t all;
	struct {
		u_int16_t port;
	} tcp;
	struct {
		u_int16_t port;
	} udp;
	struct {
		u_int8_t type, code;
		u_int16_t id;
	} icmp;
	struct {
		u_int16_t port;
	} sctp;
};

union nfct_address {
	u_int32_t v4;
	u_int32_t v6[4];
};

struct nfct_tuple {
	union nfct_address src;
	union nfct_address dst;

	u_int8_t l3protonum;
	u_int8_t protonum;
	union nfct_l4 l4src;
	union nfct_l4 l4dst;
};

union nfct_protoinfo {
	struct {
		u_int8_t state;
	} tcp;
};

struct nfct_counters {
	u_int64_t packets;
	u_int64_t bytes;
};

struct nfct_nat {
	u_int32_t min_ip, max_ip;
	union nfct_l4 l4min, l4max;
};

#define NFCT_DIR_ORIGINAL 0
#define NFCT_DIR_REPLY 1
#define NFCT_DIR_MAX NFCT_DIR_REPLY+1

struct nfct_conntrack {
	struct nfct_tuple tuple[NFCT_DIR_MAX];
	
	u_int32_t 	timeout;
	u_int32_t	mark;
	u_int32_t 	status;
	u_int32_t	use;
	u_int32_t	id;

	union nfct_protoinfo protoinfo;
	struct nfct_counters counters[NFCT_DIR_MAX];
	struct nfct_nat nat;
};

struct nfct_expect {
	struct nfct_tuple master;
	struct nfct_tuple tuple;
	struct nfct_tuple mask;
	u_int32_t timeout;
	u_int32_t id;
};

struct nfct_conntrack_compare {
	struct nfct_conntrack *ct;
	unsigned int flags;
	unsigned int l3flags;
	unsigned int l4flags;
};

enum {
	NFCT_STATUS_BIT = 0,
	NFCT_STATUS = (1 << NFCT_STATUS_BIT),
	
	NFCT_PROTOINFO_BIT = 1,
	NFCT_PROTOINFO = (1 << NFCT_PROTOINFO_BIT),

	NFCT_TIMEOUT_BIT = 2,
	NFCT_TIMEOUT = (1 << NFCT_TIMEOUT_BIT),

	NFCT_MARK_BIT = 3,
	NFCT_MARK = (1 << NFCT_MARK_BIT),

	NFCT_COUNTERS_ORIG_BIT = 4,
	NFCT_COUNTERS_ORIG = (1 << NFCT_COUNTERS_ORIG_BIT),

	NFCT_COUNTERS_RPLY_BIT = 5,
	NFCT_COUNTERS_RPLY = (1 << NFCT_COUNTERS_RPLY_BIT),

	NFCT_USE_BIT = 6,
	NFCT_USE = (1 << NFCT_USE_BIT),

	NFCT_ID_BIT = 7,
	NFCT_ID = (1 << NFCT_ID_BIT)
};

/* Bitset representing status of connection. Taken from ip_conntrack.h
 * 
 * Note: For backward compatibility this shouldn't ever change
 * 	 in kernel space.
 */
enum ip_conntrack_status {
	/* It's an expected connection: bit 0 set.  This bit never changed */
	IPS_EXPECTED_BIT = 0,
	IPS_EXPECTED = (1 << IPS_EXPECTED_BIT),

	/* We've seen packets both ways: bit 1 set.  Can be set, not unset. */
	IPS_SEEN_REPLY_BIT = 1,
	IPS_SEEN_REPLY = (1 << IPS_SEEN_REPLY_BIT),

	/* Conntrack should never be early-expired. */
	IPS_ASSURED_BIT = 2,
	IPS_ASSURED = (1 << IPS_ASSURED_BIT),

	/* Connection is confirmed: originating packet has left box */
	IPS_CONFIRMED_BIT = 3,
	IPS_CONFIRMED = (1 << IPS_CONFIRMED_BIT),

	/* Connection needs src nat in orig dir.  This bit never changed. */
	IPS_SRC_NAT_BIT = 4,
	IPS_SRC_NAT = (1 << IPS_SRC_NAT_BIT),

	/* Connection needs dst nat in orig dir.  This bit never changed. */
	IPS_DST_NAT_BIT = 5,
	IPS_DST_NAT = (1 << IPS_DST_NAT_BIT),

	/* Both together. */
	IPS_NAT_MASK = (IPS_DST_NAT | IPS_SRC_NAT),

	/* Connection needs TCP sequence adjusted. */
	IPS_SEQ_ADJUST_BIT = 6,
	IPS_SEQ_ADJUST = (1 << IPS_SEQ_ADJUST_BIT),

	/* NAT initialization bits. */
	IPS_SRC_NAT_DONE_BIT = 7,
	IPS_SRC_NAT_DONE = (1 << IPS_SRC_NAT_DONE_BIT),

	IPS_DST_NAT_DONE_BIT = 8,
	IPS_DST_NAT_DONE = (1 << IPS_DST_NAT_DONE_BIT),

	/* Both together */
	IPS_NAT_DONE_MASK = (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE),

	/* Connection is dying (removed from lists), can not be unset. */
	IPS_DYING_BIT = 9,
	IPS_DYING = (1 << IPS_DYING_BIT),
};

enum {
	NFCT_MSG_UNKNOWN,
	NFCT_MSG_NEW,
	NFCT_MSG_UPDATE,
	NFCT_MSG_DESTROY
};

struct nfct_handle;
typedef int (*nfct_callback)(void *arg, unsigned int flags, int, void *data);

/*
 * [Allocate|free] a conntrack
 */
extern struct nfct_conntrack *
nfct_conntrack_alloc(struct nfct_tuple *orig, struct nfct_tuple *reply,
		     u_int32_t timeout, union nfct_protoinfo *proto,
		     u_int32_t status, u_int32_t mark,
		     u_int32_t id, struct nfct_nat *range);
extern void nfct_conntrack_free(struct nfct_conntrack *ct);

/*
 * [Allocate|free] an expectation
 */
extern struct nfct_expect *
nfct_expect_alloc(struct nfct_tuple *master, struct nfct_tuple *tuple,
		  struct nfct_tuple *mask, u_int32_t timeout, 
		  u_int32_t id);
extern void nfct_expect_free(struct nfct_expect *exp);

/*
 * [Open|close] a conntrack handler
 */
extern struct nfct_handle *nfct_open(u_int8_t, unsigned);
extern int nfct_close(struct nfct_handle *cth);

extern int nfct_fd(struct nfct_handle *cth);

/*
 * [Register|unregister] callbacks
 */
extern void nfct_register_callback(struct nfct_handle *cth,
				   nfct_callback callback, void *data);
extern void nfct_unregister_callback(struct nfct_handle *cth);

/*
 * callback displayers
 */
extern int nfct_default_conntrack_display(void *, unsigned int, int, void *); 
extern int nfct_default_conntrack_display_id(void *, unsigned int, int, void *);
extern int nfct_default_expect_display(void *, unsigned int, int, void *);
extern int nfct_default_expect_display_id(void *, unsigned int, int, void *);
extern int nfct_default_conntrack_event_display(void *, unsigned int, int, 
						void *);

/*
 * [Create|update|get|destroy] conntracks
 */
extern int nfct_create_conntrack(struct nfct_handle *cth, 
				 struct nfct_conntrack *ct);
extern int nfct_update_conntrack(struct nfct_handle *cth,
				 struct nfct_conntrack *ct);
extern int nfct_delete_conntrack(struct nfct_handle *cth, 
				 struct nfct_tuple *tuple, int dir, 
				 u_int32_t id);
extern int nfct_get_conntrack(struct nfct_handle *cth, 
			      struct nfct_tuple *tuple, int dir,
			      u_int32_t id); 
/*
 * Conntrack table dumping & zeroing
 */
extern int nfct_dump_conntrack_table(struct nfct_handle *cth, int family);
extern int nfct_dump_conntrack_table_reset_counters(struct nfct_handle *cth, 
						    int family);

/*
 * Conntrack event notification
 */
extern int nfct_event_conntrack(struct nfct_handle *cth); 

/*
 * Conntrack printing functions
 */
extern int nfct_sprintf_conntrack(char *buf, struct nfct_conntrack *ct, 
				  unsigned int flags);
extern int nfct_sprintf_conntrack_id(char *buf, struct nfct_conntrack *ct,
				     unsigned int flags);
extern int nfct_sprintf_address(char *buf, struct nfct_tuple *t);
extern int nfct_sprintf_proto(char *buf, struct nfct_tuple *t);
extern int nfct_sprintf_protoinfo(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_timeout(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_protocol(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_status_assured(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_status_seen_reply(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_counters(char *buf, struct nfct_conntrack *ct, int dir);
extern int nfct_sprintf_mark(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_use(char *buf, struct nfct_conntrack *ct);
extern int nfct_sprintf_id(char *buf, u_int32_t id);

/*
 * Conntrack comparison
 */
extern int nfct_conntrack_compare(struct nfct_conntrack *ct1, 
				  struct nfct_conntrack *ct2,
				  struct nfct_conntrack_compare *cmp);

/* 
 * Expectations
 */
extern int nfct_dump_expect_list(struct nfct_handle *cth, int family);
extern int nfct_flush_conntrack_table(struct nfct_handle *cth, int family);
extern int nfct_get_expectation(struct nfct_handle *cth, 
				struct nfct_tuple *tuple,
				u_int32_t id);
extern int nfct_create_expectation(struct nfct_handle *cth, struct nfct_expect *);
extern int nfct_delete_expectation(struct nfct_handle *cth,
				   struct nfct_tuple *tuple, u_int32_t id);
extern int nfct_event_expectation(struct nfct_handle *cth);
extern int nfct_flush_expectation_table(struct nfct_handle *cth, int family);

/*
 * expectation printing functions
 */
extern int nfct_sprintf_expect(char *buf, struct nfct_expect *exp);
extern int nfct_sprintf_expect_id(char *buf, struct nfct_expect *exp);

#endif	/* _LIBNETFILTER_CONNTRACK_H_ */
