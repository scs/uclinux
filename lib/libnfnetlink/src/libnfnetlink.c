/* libnfnetlink.c: generic library for communication with netfilter
 *
 * (C) 2001 by Jay Schulist <jschlst@samba.org>
 * (C) 2002-2005 by Harald Welte <laforge@gnumonks.org>
 *
 * Development of this code funded by Astaro AG (http://www.astaro.com)
 *
 * this software may be used and distributed according to the terms
 * of the gnu general public license, incorporated herein by reference.
 *
 * 2005-09-14 Pablo Neira Ayuso <pablo@netfilter.org>: 
 * 	Define structure nfnlhdr
 * 	Added __be64_to_cpu function
 *	Use NFA_TYPE macro to get the attribute type
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <libnfnetlink/libnfnetlink.h>

#define nfnl_error(format, args...) \
	fprintf(stderr, "%s: " format "\n", __FUNCTION__, ## args)

#ifdef _NFNL_DEBUG
#define nfnl_debug_dump_packet nfnl_dump_packet
#else
#define nfnl_debug_dump_packet(a, b, ...)
#endif

void nfnl_dump_packet(struct nlmsghdr *nlh, int received_len, char *desc)
{
	void *nlmsg_data = NLMSG_DATA(nlh);
	struct nfattr *nfa = NFM_NFA(NLMSG_DATA(nlh));
	int len = NFM_PAYLOAD(nlh);

	printf("%s called from %s\n", __FUNCTION__, desc);
	printf("  nlmsghdr = %p, received_len = %u\n", nlh, received_len);
	printf("  NLMSG_DATA(nlh) = %p (+%td bytes)\n", nlmsg_data,
	       (nlmsg_data - (void *)nlh));
	printf("  NFM_NFA(NLMSG_DATA(nlh)) = %p (+%td bytes)\n",
		nfa, ((void *)nfa - (void *)nlh));
	printf("  NFM_PAYLOAD(nlh) = %u\n", len);
	printf("  nlmsg_type = %u, nlmsg_len = %u, nlmsg_seq = %u "
		"nlmsg_flags = 0x%x\n", nlh->nlmsg_type, nlh->nlmsg_len,
		nlh->nlmsg_seq, nlh->nlmsg_flags);

	while (NFA_OK(nfa, len)) {
		printf("    nfa@%p: nfa_type=%u, nfa_len=%u\n",
			nfa, NFA_TYPE(nfa), nfa->nfa_len);
		nfa = NFA_NEXT(nfa,len);
	}
}

int nfnl_fd(struct nfnl_handle *h)
{
	return h->fd;
}

/**
 * nfnl_open - open a netlink socket
 *
 * nfnlh: libnfnetlink handle to be allocated by user
 * subsys_id: which nfnetlink subsystem we are interested in
 * cb_count: number of callbacks that are used maximum.
 * subscriptions: netlink groups we want to be subscribed to
 *
 */
int nfnl_open(struct nfnl_handle *nfnlh, u_int8_t subsys_id, 
	      u_int8_t cb_count, u_int32_t subscriptions)
{
	int err;
	unsigned int addr_len;
	struct nfnl_callback *cb;

	cb = malloc(sizeof(*cb) * cb_count);
	if (!cb)
		return -ENOMEM;
	
	memset(nfnlh, 0, sizeof(*nfnlh));
	nfnlh->fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
	if (nfnlh->fd < 0) {
		nfnl_error("socket(netlink): %s", strerror(errno));
		return nfnlh->fd;
	}

	nfnlh->local.nl_family = AF_NETLINK;
	nfnlh->local.nl_groups = subscriptions;

	nfnlh->peer.nl_family = AF_NETLINK;

	err = bind(nfnlh->fd, (struct sockaddr *)&nfnlh->local,
		   sizeof(nfnlh->local));
	if (err < 0) {
		nfnl_error("bind(netlink): %s", strerror(errno));
		return err;
	}

	addr_len = sizeof(nfnlh->local);
	err = getsockname(nfnlh->fd, (struct sockaddr *)&nfnlh->local, 
			  &addr_len);
	if (addr_len != sizeof(nfnlh->local)) {
		nfnl_error("Bad address length (%u != %zd)", addr_len,
			   sizeof(nfnlh->local));
		return -1;
	}
	if (nfnlh->local.nl_family != AF_NETLINK) {
		nfnl_error("Bad address family %d", nfnlh->local.nl_family);
		return -1;
	}
	nfnlh->seq = time(NULL);
	nfnlh->subsys_id = subsys_id;
	nfnlh->cb_count = cb_count;
	nfnlh->cb = cb;

	return 0;
}

/**
 * nfnl_close - close netlink socket
 *
 * nfnlh: libnfnetlink handle
 *
 */
int nfnl_close(struct nfnl_handle *nfnlh)
{
	free(nfnlh->cb);
	return close(nfnlh->fd);
}

/**
 * nfnl_send - send a nfnetlink message through netlink socket
 *
 * nfnlh: libnfnetlink handle
 * n: netlink message
 */
int nfnl_send(struct nfnl_handle *nfnlh, struct nlmsghdr *n)
{
	nfnl_debug_dump_packet(n, n->nlmsg_len+sizeof(*n), "nfnl_send");

	return sendto(nfnlh->fd, n, n->nlmsg_len, 0, 
		      (struct sockaddr *)&nfnlh->peer, sizeof(nfnlh->peer));
}

int nfnl_sendmsg(const struct nfnl_handle *nfnlh, const struct msghdr *msg,
		 unsigned int flags)
{
	return sendmsg(nfnlh->fd, msg, flags);
}

int nfnl_sendiov(const struct nfnl_handle *nfnlh, const struct iovec *iov,
		 unsigned int num, unsigned int flags)
{
	struct msghdr msg;

	msg.msg_name = (struct sockaddr *) &nfnlh->peer;
	msg.msg_namelen = sizeof(nfnlh->peer);
	msg.msg_iov = (struct iovec *) iov;
	msg.msg_iovlen = num;
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_flags = 0;

	return nfnl_sendmsg(nfnlh, &msg, flags);
}

/**
 * nfnl_fill_hdr - fill in netlink and nfnetlink header
 *
 * nfnlh: libnfnetlink handle
 * nlh: netlink header to be filled in
 * len: length of _payload_ bytes (not including nfgenmsg)
 * family: AF_INET / ...
 * res_id: resource id
 * msg_type: nfnetlink message type (without subsystem)
 * msg_flags: netlink message flags
 *
 * NOTE: the nlmsghdr must point to a memory region of at least
 * the size of struct nlmsghdr + struct nfgenmsg
 *
 */
void nfnl_fill_hdr(struct nfnl_handle *nfnlh,
		    struct nlmsghdr *nlh, unsigned int len, 
		    u_int8_t family,
		    u_int16_t res_id,
		    u_int16_t msg_type,
		    u_int16_t msg_flags)
{
	struct nfgenmsg *nfg = (struct nfgenmsg *) 
					((void *)nlh + sizeof(*nlh));

	nlh->nlmsg_len = NLMSG_LENGTH(len+sizeof(*nfg));
	nlh->nlmsg_type = (nfnlh->subsys_id<<8)|msg_type;
	nlh->nlmsg_flags = msg_flags;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_seq = ++nfnlh->seq;

	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(res_id);
}

struct nfattr *
nfnl_parse_hdr(const struct nfnl_handle *nfnlh,
		const struct nlmsghdr *nlh,
		struct nfgenmsg **genmsg)
{
	if (nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct nfgenmsg)))
		return NULL;

	if (nlh->nlmsg_len == NLMSG_LENGTH(sizeof(struct nfgenmsg))) {
		if (genmsg)
			*genmsg = (struct nfgenmsg *)((void *)nlh+sizeof(nlh));
		return NULL;
	}

	if (genmsg)
		*genmsg = (struct nfgenmsg *)((void *)nlh + sizeof(nlh));

	return ((void *)nlh + NLMSG_LENGTH(sizeof(struct nfgenmsg)));
}

ssize_t 
nfnl_recv(const struct nfnl_handle *h, unsigned char *buf, size_t len)
{
	socklen_t addrlen;
	int status;
	struct nlmsghdr *nlh;
	struct sockaddr_nl peer;
	
	if (len < sizeof(struct nlmsgerr)
	    || len < sizeof(struct nlmsghdr))
		return -1; 

	addrlen = sizeof(h->peer);
	status = recvfrom(h->fd, buf, len, 0, (struct sockaddr *)&peer,	
			&addrlen);
	if (status <= 0)
		return status;

	if (addrlen != sizeof(peer))
		return -1;

	if (peer.nl_pid != 0)
		return -1;

	nlh = (struct nlmsghdr *)buf;
	if (nlh->nlmsg_flags & MSG_TRUNC || status > len)
		return -1;

	return status;
}
/**
 * nfnl_listen: listen for one or more netlink messages
 *
 * nfnhl: libnfnetlink handle
 * handler: callback function to be called for every netlink message
 *          - the callback handler should normally return 0
 *          - but may return a negative error code which will cause
 *            nfnl_listen to return immediately with the same error code
 *          - or return a postivie error code which will cause 
 *            nfnl_listen to return after it has finished processing all
 *            the netlink messages in the current packet
 *          Thus a positive error code will terminate nfnl_listen "soon"
 *          without any loss of data, a negative error code will terminate
 *          nfnl_listen "very soon" and throw away data already read from
 *          the netlink socket.
 * jarg: opaque argument passed on to callback
 *
 */
int nfnl_listen(struct nfnl_handle *nfnlh,
		int (*handler)(struct sockaddr_nl *, struct nlmsghdr *n,
			       void *), void *jarg)
{
	struct sockaddr_nl nladdr;
	char buf[NFNL_BUFFSIZE];
	struct iovec iov;
	int remain;
	struct nlmsghdr *h;
	struct nlmsgerr *msgerr;
	int quit=0;

	struct msghdr msg = {
		(void *)&nladdr, sizeof(nladdr),
		&iov, 1,
		NULL, 0,
		0
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	while (! quit) {
		remain = recvmsg(nfnlh->fd, &msg, 0);
		if (remain < 0) {
			if (errno == EINTR)
				continue;
			/* Bad file descriptor */
			else if (errno == EBADF)
				break;
			else if (errno == EAGAIN)
				break;
			nfnl_error("recvmsg overrun: %s", strerror(errno));
			continue;
		}
		if (remain == 0) {
			nfnl_error("EOF on netlink");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			nfnl_error("Bad sender address len (%d)",
				   msg.msg_namelen);
			return -1;
		}

		for (h = (struct nlmsghdr *)buf; remain >= sizeof(*h);) {
			int err;
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len > remain) {
				if (msg.msg_flags & MSG_TRUNC) {
					nfnl_error("MSG_TRUNC");
					return -1;
				}
				nfnl_error("Malformed msg (len=%d)", len);
				return -1;
			}

			/* end of messages reached, let's return */
			if (h->nlmsg_type == NLMSG_DONE)
				return 0;

			/* Break the loop if success is explicitely
			 * reported via NLM_F_ACK flag set */
			if (h->nlmsg_type == NLMSG_ERROR) {
				msgerr = NLMSG_DATA(h);
				return msgerr->error;
			}

			err = handler(&nladdr, h, jarg);
			if (err < 0)
				return err;
			quit |= err;
		
			/* FIXME: why not _NEXT macros, etc.? */
			//h = NLMSG_NEXT(h, remain);
			remain -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			nfnl_error("MSG_TRUNC");
			continue;
		}
		if (remain) {
			nfnl_error("remnant size %d", remain);
			return -1;
		}
	}

	return quit;
}

int nfnl_talk(struct nfnl_handle *nfnlh, struct nlmsghdr *n, pid_t peer,
	      unsigned groups, struct nlmsghdr *answer,
	      int (*junk)(struct sockaddr_nl *, struct nlmsghdr *n, void *),
	      void *jarg)
{
	char buf[NFNL_BUFFSIZE];
	struct sockaddr_nl nladdr;
	struct nlmsghdr *h;
	unsigned int seq;
	int status;
	struct iovec iov = {
		(void *)n, n->nlmsg_len
	};
	struct msghdr msg = {
		(void *)&nladdr, sizeof(nladdr),
		&iov, 1,
		NULL, 0,
		0
	};

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = peer;
	nladdr.nl_groups = groups;

	n->nlmsg_seq = seq = ++nfnlh->seq;
	/* FIXME: why ? */
	if (!answer)
		n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(nfnlh->fd, &msg, 0);
	if (status < 0) {
		nfnl_error("sendmsg(netlink) %s", strerror(errno));
		return -1;
	}
	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);

	while (1) {
		status = recvmsg(nfnlh->fd, &msg, 0);
		if (status < 0) {
			if (errno == EINTR)
				continue;
			nfnl_error("recvmsg over-run");
			continue;
		}
		if (status == 0) {
			nfnl_error("EOF on netlink");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			nfnl_error("Bad sender address len %d",
				   msg.msg_namelen);
			return -1;
		}

		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);
			int err;

			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					nfnl_error("Truncated message\n");
					return -1;
				}
				nfnl_error("Malformed message: len=%d\n", len);
				return -1; /* FIXME: libnetlink exits here */
			}

			if (h->nlmsg_pid != nfnlh->local.nl_pid ||
			    h->nlmsg_seq != seq) {
				if (junk) {
					err = junk(&nladdr, h, jarg);
					if (err < 0)
						return err;
				}
				goto cont;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = NLMSG_DATA(h);
				if (l < sizeof(struct nlmsgerr))
					nfnl_error("ERROR truncated\n");
				else {
					errno = -err->error;
					if (errno == 0) {
						if (answer)
							memcpy(answer, h, h->nlmsg_len);
						return 0;
					}
					perror("NFNETLINK answers");
				}
				return err->error;
			}
			if (answer) {
				memcpy(answer, h, h->nlmsg_len);
				return 0;
			}

			nfnl_error("Unexpected reply!\n");
cont:
			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		if (msg.msg_flags & MSG_TRUNC) {
			nfnl_error("Messages truncated\n");
			continue;
		}
		if (status) {
			nfnl_error("Remnant of size %d\n", status);
			exit(1);
		}
	}
}

/**
 * nfnl_addattr_l - Add variable length attribute to nlmsghdr
 *
 * n: netlink message header to which attribute is to be added
 * maxlen: maximum length of netlink message header
 * type: type of new attribute
 * data: content of new attribute
 * alen: attribute length
 *
 */
int nfnl_addattr_l(struct nlmsghdr *n, int maxlen, int type, void *data,
		   int alen)
{
	int len = NFA_LENGTH(alen);
	struct nfattr *nfa;

	if ((NLMSG_ALIGN(n->nlmsg_len) + len) > maxlen) {
		nfnl_error("%d greater than maxlen (%d)\n",
			   NLMSG_ALIGN(n->nlmsg_len) + len, maxlen);
		return -1;
	}

	nfa = NLMSG_TAIL(n);
	nfa->nfa_type = type;
	nfa->nfa_len = len;
	memcpy(NFA_DATA(nfa), data, alen);
	n->nlmsg_len = (NLMSG_ALIGN(n->nlmsg_len) + NFA_ALIGN(len));
	return 0;
}

/**
 * nfnl_nfa_addattr_l - Add variable length attribute to struct nfattr 
 *
 * nfa: struct nfattr
 * maxlen: maximal length of nfattr buffer
 * type: type for new attribute
 * data: content of new attribute
 * alen: length of new attribute
 *
 */
int nfnl_nfa_addattr_l(struct nfattr *nfa, int maxlen, int type, void *data,
		       int alen)
{
	struct nfattr *subnfa;
	int len = NFA_LENGTH(alen);

	if ((NFA_OK(nfa, nfa->nfa_len) + len) > maxlen)
		return -1;

	subnfa = (struct nfattr *)(((char *)nfa) + NFA_OK(nfa, nfa->nfa_len));
	subnfa->nfa_type = type;
	subnfa->nfa_len = len;
	memcpy(NFA_DATA(subnfa), data, alen);
	nfa->nfa_len = (NLMSG_ALIGN(nfa->nfa_len) + len);

	return 0;
}


/**
 * nfnl_nfa_addattr32 - Add u_int32_t attribute to struct nfattr 
 *
 * nfa: struct nfattr
 * maxlen: maximal length of nfattr buffer
 * type: type for new attribute
 * data: content of new attribute
 *
 */
int nfnl_nfa_addattr32(struct nfattr *nfa, int maxlen, int type, 
		       u_int32_t data)
{

	return nfnl_nfa_addattr_l(nfa, maxlen, type, &data, sizeof(data));
}

/**
 * nfnl_addattr32 - Add u_int32_t attribute to nlmsghdr
 *
 * n: netlink message header to which attribute is to be added
 * maxlen: maximum length of netlink message header
 * type: type of new attribute
 * data: content of new attribute
 *
 */
int nfnl_addattr32(struct nlmsghdr *n, int maxlen, int type,
		   u_int32_t data)
{
	return nfnl_addattr_l(n, maxlen, type, &data, sizeof(data));
}

/**
 * nfnl_parse_attr - Parse a list of nfattrs into a pointer array
 *
 * tb: pointer array, will be filled in (output)
 * max: size of pointer array
 * nfa: pointer to list of nfattrs
 * len: length of 'nfa'
 *
 */
int nfnl_parse_attr(struct nfattr *tb[], int max, struct nfattr *nfa, int len)
{
	memset(tb, 0, sizeof(struct nfattr *) * max);

	while (NFA_OK(nfa, len)) {
		if (NFA_TYPE(nfa) <= max)
			tb[NFA_TYPE(nfa)-1] = nfa;
                nfa = NFA_NEXT(nfa,len);
	}
	if (len)
		nfnl_error("deficit (%d) len (%d).\n", len, nfa->nfa_len);

	return 0;
}

/**
 * nfnl_build_nfa_iovec - Build two iovec's from tag, length and value
 *
 * iov: pointer to array of two 'struct iovec' (caller-allocated)
 * nfa: pointer to 'struct nfattr' (caller-allocated)
 * type: type (tag) of attribute
 * len: length of value
 * val: pointer to buffer containing 'value'
 *
 */ 
void nfnl_build_nfa_iovec(struct iovec *iov, struct nfattr *nfa, 
			  u_int16_t type, u_int32_t len, unsigned char *val)
{
	iov[0].iov_base = nfa;
	iov[0].iov_len = sizeof(*nfa);
	iov[1].iov_base = val;
	iov[1].iov_len = NFA_ALIGN(len);
}

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE	(33)
#endif

unsigned int nfnl_rcvbufsiz(struct nfnl_handle *h, unsigned int size)
{
	int status;
	socklen_t socklen = sizeof(size);
	unsigned int read_size = 0;

	/* first we try the FORCE option, which is introduced in kernel
	 * 2.6.14 to give "root" the ability to override the system wide
	 * maximum */
	status = setsockopt(h->fd, SOL_SOCKET, SO_RCVBUFFORCE, &size, socklen);
	if (status < 0) {
		/* if this didn't work, we try at least to get the system
		 * wide maximum (or whatever the user requested) */
		setsockopt(h->fd, SOL_SOCKET, SO_RCVBUF, &size, socklen);
	}
	getsockopt(h->fd, SOL_SOCKET, SO_RCVBUF, &read_size, &socklen);

	return read_size;
}


struct nlmsghdr *nfnl_get_msg_first(struct nfnl_handle *h,
				    const unsigned char *buf,
				    size_t len)
{
	struct nlmsghdr *nlh;

	/* first message in buffer */
	nlh = (struct nlmsghdr *)buf;
	if (!NLMSG_OK(nlh, len))
		return NULL;
	h->last_nlhdr = nlh;

	return nlh;
}

struct nlmsghdr *nfnl_get_msg_next(struct nfnl_handle *h,
				   const unsigned char *buf,
				   size_t len)
{
	struct nlmsghdr *nlh;
	size_t remain_len;

	/* if last header in handle not inside this buffer, 
	 * drop reference to last header */
	if (!h->last_nlhdr ||
	    (unsigned char *)h->last_nlhdr >= (buf + len)  ||
	    (unsigned char *)h->last_nlhdr < buf) {
		h->last_nlhdr = NULL;
		return NULL;
	}

	/* n-th part of multipart message */
	if (h->last_nlhdr->nlmsg_type == NLMSG_DONE ||
	    h->last_nlhdr->nlmsg_flags & NLM_F_MULTI) {
		/* if last part in multipart message or no
		 * multipart message at all, return */
		h->last_nlhdr = NULL;
		return NULL;
	}

	remain_len = (len - ((unsigned char *)h->last_nlhdr - buf));
	nlh = NLMSG_NEXT(h->last_nlhdr, remain_len);

	h->last_nlhdr = nlh;

	return nlh;
}

int nfnl_callback_register(struct nfnl_handle *h,
			   u_int8_t type, struct nfnl_callback *cb)
{
	if (type >= h->cb_count)
		return -EINVAL;

	memcpy(&h->cb[type], cb, sizeof(*cb));

	return 0;
}

int nfnl_callback_unregister(struct nfnl_handle *h, u_int8_t type)
{
	if (type >= h->cb_count)
		return -EINVAL;

	h->cb[type].call = NULL;

	return 0;
}

int nfnl_check_attributes(const struct nfnl_handle *h,
			 const struct nlmsghdr *nlh,
			 struct nfattr *nfa[])
{
	int min_len;
	u_int8_t type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	struct nfnl_callback *cb = &h->cb[type];

#if 1
	/* checks need to be enabled as soon as this is called from
	 * somebody else than __nfnl_handle_msg */
	if (type >= h->cb_count)
		return -EINVAL;

	min_len = NLMSG_ALIGN(sizeof(struct nfgenmsg));
	if (nlh->nlmsg_len < min_len)
		return -EINVAL;
#endif
	memset(nfa, 0, sizeof(struct nfattr *) * cb->attr_count);

	if (nlh->nlmsg_len > min_len) {
		struct nfattr *attr = NFM_NFA(NLMSG_DATA(nlh));
		int attrlen = nlh->nlmsg_len - NLMSG_ALIGN(min_len);

		while (NFA_OK(attr, attrlen)) {
			unsigned int flavor = NFA_TYPE(attr);
			if (flavor) {
				if (flavor > cb->attr_count)
					return -EINVAL;
				nfa[flavor - 1] = attr;
			}
			attr = NFA_NEXT(attr, attrlen);
		}
	}

	return 0;
}

static int __nfnl_handle_msg(struct nfnl_handle *h, struct nlmsghdr *nlh,
			     int len)
{
	u_int8_t type = NFNL_MSG_TYPE(nlh->nlmsg_type);
	int err = 0;

	if (NFNL_SUBSYS_ID(nlh->nlmsg_type) != h->subsys_id)
		return -1;

	if (nlh->nlmsg_len < NLMSG_LENGTH(NLMSG_ALIGN(sizeof(struct nfgenmsg))))
		return -1;

	if (type >= h->cb_count)
		return -1;

	if (h->cb[type].attr_count) {
		struct nfattr *nfa[h->cb[type].attr_count];

		err = nfnl_check_attributes(h, nlh, nfa);
		if (err < 0)
			return err;
		if (h->cb[type].call)
			return h->cb[type].call(nlh, nfa, h->cb[type].data);
	}
	return 0;
}

int nfnl_handle_packet(struct nfnl_handle *h, char *buf, int len)
{

	while (len >= NLMSG_SPACE(0)) {
		u_int32_t rlen;
		struct nlmsghdr *nlh = (struct nlmsghdr *)buf;

		if (nlh->nlmsg_len < sizeof(struct nlmsghdr)
		    || len < nlh->nlmsg_len)
			return -1;

		rlen = NLMSG_ALIGN(nlh->nlmsg_len);
		if (rlen > len)
			rlen = len;

		if (__nfnl_handle_msg(h, nlh, rlen) < 0)
			return -1;

		len -= rlen;
	}
	return 0;
}
