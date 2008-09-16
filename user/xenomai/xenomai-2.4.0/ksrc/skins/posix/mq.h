#ifndef POSIX_MQ_H
#define POSIX_MQ_H

#include <nucleus/queue.h>
#include <posix/registry.h>     /* For associative lists. */

typedef struct pse51_direct_msg {
	char *buf;
	size_t *lenp;
	unsigned *priop;
	int flags;
} pse51_direct_msg_t;

#define PSE51_MSG_DIRECT  1
#define PSE51_MSG_RESCHED 2

int pse51_mq_timedsend_inner(pse51_direct_msg_t *msgp, mqd_t fd,
			     size_t len, const struct timespec *abs_timeoutp);

void pse51_mq_finish_send(mqd_t fd, pse51_direct_msg_t *msgp);

int pse51_mq_timedrcv_inner(pse51_direct_msg_t *msgp, mqd_t fd,
			    size_t len, const struct timespec *abs_timeoutp);

void pse51_mq_finish_rcv(mqd_t fd, pse51_direct_msg_t *msgp);

#ifdef CONFIG_XENO_OPT_PERVASIVE

void pse51_mq_uqds_cleanup(pse51_queues_t *q);

#endif /* CONFIG_XENO_OPT_PERVASIVE */

int pse51_mq_pkg_init(void);

void pse51_mq_pkg_cleanup(void);

#endif /* POSIX_MQ_H */
