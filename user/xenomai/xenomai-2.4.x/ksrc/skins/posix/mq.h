#ifndef POSIX_MQ_H
#define POSIX_MQ_H

#include <nucleus/queue.h>
#include <posix/registry.h>     /* For associative lists. */

struct pse51_mq;
typedef struct pse51_mq pse51_mq_t;

typedef struct pse51_msg {
	xnpholder_t link;
	size_t len;
	char data[0];
} pse51_msg_t;

#define pse51_msg_get_prio(msg) (msg)->link.prio
#define pse51_msg_set_prio(msg, prio) (msg)->link.prio = (prio)

pse51_msg_t *pse51_mq_timedsend_inner(pse51_mq_t **mqp, mqd_t fd, size_t len,
				      const struct timespec *abs_timeoutp);

int pse51_mq_finish_send(mqd_t fd, pse51_mq_t *mq, pse51_msg_t *msg);

pse51_msg_t *pse51_mq_timedrcv_inner(pse51_mq_t **mqp, mqd_t fd, size_t len,
				     const struct timespec *abs_timeoutp);

int pse51_mq_finish_rcv(mqd_t fd, pse51_mq_t *mq, pse51_msg_t *msg);

#ifdef CONFIG_XENO_OPT_PERVASIVE

void pse51_mq_uqds_cleanup(pse51_queues_t *q);

#endif /* CONFIG_XENO_OPT_PERVASIVE */

int pse51_mq_pkg_init(void);

void pse51_mq_pkg_cleanup(void);

#endif /* POSIX_MQ_H */
