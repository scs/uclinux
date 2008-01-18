/* libnfnetlink.h: Header file for generic netfilter netlink interface
 *
 * (C) 2002 Harald Welte <laforge@gnumonks.org>
 *
 * 2005-10-29 Pablo Neira Ayuso <pablo@netfilter.org>:
 * 	Fix NFNL_HEADER_LEN
 * 2005-11-13 Pablo Neira Ayuso <pablo@netfilter.org>:
 * 	Define NETLINK_NETFILTER if it's undefined
 */

#ifndef __LIBNFNETLINK_H
#define __LIBNFNETLINK_H

#ifndef aligned_u64
#define aligned_u64 unsigned long long __attribute__((aligned(8)))
#endif

#include <linux/types.h>
#include <sys/socket.h>	/* for sa_family_t */
#include <linux/netlink.h>
#include <libnfnetlink/linux_nfnetlink.h>

#ifndef NETLINK_NETFILTER
#define NETLINK_NETFILTER 12
#endif

#define NLMSG_TAIL(nlh) \
	(((void *) (nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len))

#define NFNL_HEADER_LEN	(NLMSG_ALIGN(sizeof(struct nlmsghdr))	\
			 +NLMSG_ALIGN(sizeof(struct nfgenmsg)))

#define NFNL_BUFFSIZE		8192

struct nfnlhdr {
	struct nlmsghdr nlh;
	struct nfgenmsg nfmsg;
};

struct nfnl_callback {
	int (*call)(struct nlmsghdr *nlh, struct nfattr *nfa[], void *data);
	void *data;
	u_int16_t attr_count;
};

struct nfnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	u_int8_t		subsys_id;
	u_int32_t		seq;
	u_int32_t		dump;
	struct nlmsghdr 	*last_nlhdr;

	u_int8_t		cb_count;
	struct nfnl_callback 	*cb;	/* array of callbacks */
};

extern int nfnl_fd(struct nfnl_handle *h);

/* get a new library handle */
extern int nfnl_open(struct nfnl_handle *, u_int8_t, u_int8_t, unsigned int);
extern int nfnl_close(struct nfnl_handle *);

/* sending of data */
extern int nfnl_send(struct nfnl_handle *, struct nlmsghdr *);
extern int nfnl_sendmsg(const struct nfnl_handle *, const struct msghdr *msg,
			unsigned int flags);
extern int nfnl_sendiov(const struct nfnl_handle *nfnlh,
			const struct iovec *iov, unsigned int num,
			unsigned int flags);
extern void nfnl_fill_hdr(struct nfnl_handle *, struct nlmsghdr *,
			  unsigned int, u_int8_t, u_int16_t, u_int16_t,
			  u_int16_t);
extern int nfnl_talk(struct nfnl_handle *, struct nlmsghdr *, pid_t,
                     unsigned, struct nlmsghdr *,
                     int (*)(struct sockaddr_nl *, struct nlmsghdr *, void *),
                     void *);

/* simple challenge/response */
extern int nfnl_listen(struct nfnl_handle *,
                      int (*)(struct sockaddr_nl *, struct nlmsghdr *, void *),
                      void *);

/* receiving */
extern ssize_t nfnl_recv(const struct nfnl_handle *h, unsigned char *buf, size_t len);
extern int nfnl_callback_register(struct nfnl_handle *,
				  u_int8_t type, struct nfnl_callback *cb);
extern int nfnl_callback_unregister(struct nfnl_handle *, u_int8_t type);
extern int nfnl_handle_packet(struct nfnl_handle *, char *buf, int len);

/* parsing */
extern struct nfattr *nfnl_parse_hdr(const struct nfnl_handle *nfnlh, 
				     const struct nlmsghdr *nlh,
				     struct nfgenmsg **genmsg);
extern int nfnl_check_attributes(const struct nfnl_handle *nfnlh,
				 const struct nlmsghdr *nlh,
				 struct nfattr *tb[]);
extern struct nlmsghdr *nfnl_get_msg_first(struct nfnl_handle *h,
					   const unsigned char *buf,
					   size_t len);
extern struct nlmsghdr *nfnl_get_msg_next(struct nfnl_handle *h,
					  const unsigned char *buf,
					  size_t len);

#define nfnl_attr_present(tb, attr)			\
	(tb[attr-1])

#define nfnl_get_data(tb, attr, type)			\
	({	type __ret = 0;				\
	 if (tb[attr-1])				\
	 __ret = *(type *)NFA_DATA(tb[attr-1]);		\
	 __ret;						\
	 })

#define nfnl_get_pointer_to_data(tb, attr, type)	\
	({	type *__ret = NULL;			\
	 if (tb[attr-1])				\
	 __ret = NFA_DATA(tb[attr-1]);			\
	 __ret;						\
	 })

/* nfnl attribute handling functions */
extern int nfnl_addattr_l(struct nlmsghdr *, int, int, void *, int);
extern int nfnl_addattr32(struct nlmsghdr *, int, int, u_int32_t);
extern int nfnl_nfa_addattr_l(struct nfattr *, int, int, void *, int);
extern int nfnl_nfa_addattr32(struct nfattr *, int, int, u_int32_t);
extern int nfnl_parse_attr(struct nfattr **, int, struct nfattr *, int);
#define nfnl_parse_nested(tb, max, nfa) \
	nfnl_parse_attr((tb), (max), NFA_DATA((nfa)), NFA_PAYLOAD((nfa)))
#define nfnl_nest(nlh, bufsize, type) 				\
({	struct nfattr *__start = NLMSG_TAIL(nlh);		\
	nfnl_addattr_l(nlh, bufsize, (NFNL_NFA_NEST | type), NULL, 0); 	\
	__start; })
#define nfnl_nest_end(nlh, tail) 				\
({	(tail)->nfa_len = (void *) NLMSG_TAIL(nlh) - (void *) tail; })

extern void nfnl_build_nfa_iovec(struct iovec *iov, struct nfattr *nfa, 
				 u_int16_t type, u_int32_t len,
				 unsigned char *val);
extern unsigned int nfnl_rcvbufsiz(struct nfnl_handle *h, unsigned int size);


extern void nfnl_dump_packet(struct nlmsghdr *, int, char *);

/* Pablo: What is the equivalence of be64_to_cpu in userspace?
 * 
 * Harald: Good question.  I don't think there's a standard way [yet?], 
 * so I'd suggest manually implementing it by "#if little endian" bitshift
 * operations in C (at least for now).
 *
 * All the payload of any nfattr will always be in network byte order.
 * This would allow easy transport over a real network in the future 
 * (e.g. jamal's netlink2).
 *
 * Pablo: I've called it __be64_to_cpu instead of be64_to_cpu, since maybe 
 * there will one in the userspace headers someday. We don't want to
 * pollute POSIX space naming,
 */

#include <byteswap.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#  define __be64_to_cpu(x)	(x)
# else
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define __be64_to_cpu(x)	__bswap_64(x)
# endif
#endif

#endif /* __LIBNFNETLINK_H */
