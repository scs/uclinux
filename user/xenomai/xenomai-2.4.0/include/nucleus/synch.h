/*
 * @note Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * \ingroup synch
 */

#ifndef _XENO_NUCLEUS_SYNCH_H
#define _XENO_NUCLEUS_SYNCH_H

#include <nucleus/queue.h>

/* Creation flags */
#define XNSYNCH_FIFO    0x0
#define XNSYNCH_PRIO    0x1
#define XNSYNCH_NOPIP   0x0
#define XNSYNCH_PIP     0x2
#define XNSYNCH_DREORD  0x4

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#define XNSYNCH_CLAIMED 0x8	/* Claimed by other thread(s) w/ PIP */

/* Spare flags usable by upper interfaces */
#define XNSYNCH_SPARE0  0x01000000
#define XNSYNCH_SPARE1  0x02000000
#define XNSYNCH_SPARE2  0x04000000
#define XNSYNCH_SPARE3  0x08000000
#define XNSYNCH_SPARE4  0x10000000
#define XNSYNCH_SPARE5  0x20000000
#define XNSYNCH_SPARE6  0x40000000
#define XNSYNCH_SPARE7  0x80000000

/* Statuses */
#define XNSYNCH_DONE    0	/* Resource available / operation complete */
#define XNSYNCH_WAIT    1	/* Calling thread blocked -- start rescheduling */
#define XNSYNCH_RESCHED 2	/* Force rescheduling */

struct xnthread;
struct xnsynch;
struct xnmutex;

typedef struct xnsynch {

    xnpholder_t link;	/* Link in claim queues */

#define link2synch(ln)		container_of(ln, xnsynch_t, link)

    xnflags_t status;	/* Status word */

    xnpqueue_t pendq;	/* Pending threads */

    struct xnthread *owner; /* Thread which owns the resource */

    void (*cleanup)(struct xnsynch *synch); /* Cleanup handler */

    XNARCH_DECL_DISPLAY_CONTEXT();

} xnsynch_t;

#define xnsynch_test_flags(synch,flags)	testbits((synch)->status,flags)
#define xnsynch_set_flags(synch,flags)	setbits((synch)->status,flags)
#define xnsynch_clear_flags(synch,flags)	clrbits((synch)->status,flags)
#define xnsynch_wait_queue(synch)		(&((synch)->pendq))
#define xnsynch_nsleepers(synch)		countpq(&((synch)->pendq))
#define xnsynch_pended_p(synch)		(!emptypq_p(&((synch)->pendq)))
#define xnsynch_owner(synch)		((synch)->owner)

#ifdef __cplusplus
extern "C" {
#endif

void xnsynch_init(xnsynch_t *synch,
		  xnflags_t flags);

#define xnsynch_destroy(synch) xnsynch_flush(synch,XNRMID)

static inline void xnsynch_set_owner (xnsynch_t *synch, struct xnthread *thread)
{
    synch->owner = thread;
}

static inline void xnsynch_register_cleanup (xnsynch_t *synch, void (*handler)(xnsynch_t *))
{
    synch->cleanup = handler;
}

void xnsynch_sleep_on(xnsynch_t *synch,
		      xnticks_t timeout,
		      xntmode_t timeout_mode);

struct xnthread *xnsynch_wakeup_one_sleeper(xnsynch_t *synch);

struct xnthread *xnsynch_peek_pendq(xnsynch_t *synch);

xnpholder_t *xnsynch_wakeup_this_sleeper(xnsynch_t *synch,
					 xnpholder_t *holder);

int xnsynch_flush(xnsynch_t *synch,
		  xnflags_t reason);

void xnsynch_release_all_ownerships(struct xnthread *thread);

void xnsynch_renice_sleeper(struct xnthread *thread);

void xnsynch_forget_sleeper(struct xnthread *thread);

struct xnthread *xnsynch_forget_one_sleeper(xnsynch_t *synch);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#endif /* !_XENO_NUCLEUS_SYNCH_H_ */
