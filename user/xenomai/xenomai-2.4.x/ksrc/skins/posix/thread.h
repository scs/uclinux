/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#ifndef _POSIX_THREAD_H
#define _POSIX_THREAD_H

#include <posix/internal.h>
#include <nucleus/select.h>

typedef unsigned long long pse51_sigset_t;

struct mm_struct;

struct pse51_hkey {

    unsigned long u_tid;
    struct mm_struct *mm;
};

typedef struct {
    pse51_sigset_t mask;
    xnpqueue_t list;
} pse51_sigqueue_t;

struct pse51_thread {
    unsigned magic;
    xnthread_t threadbase;

#define thread2pthread(taddr) ({                                        \
    xnthread_t *_taddr = (taddr);                                       \
    (_taddr                                                             \
    ? ((xnthread_get_magic(_taddr) == PSE51_SKIN_MAGIC)                 \
       ? ((pthread_t)(((char *)_taddr)- offsetof(struct pse51_thread,   \
                                                 threadbase)))          \
       : NULL)                                                          \
    : NULL);                                                            \
})


   xnholder_t link;	/* Link in pse51_threadq */
   xnqueue_t *container;
    
#define link2pthread(laddr) \
    ((pthread_t)(((char *)laddr) - offsetof(struct pse51_thread, link)))
    

    pthread_attr_t attr;        /* creation attributes */

    void *(*entry)(void *arg);  /* start routine */
    void *arg;                  /* start routine argument */

    /* For pthread_join */
    void *exit_status;
    xnsynch_t join_synch;       /* synchronization object, used by other threads
                                   waiting for this one to finish. */
    int nrt_joiners;

    /* For pthread_cancel */
    unsigned cancelstate : 2;
    unsigned canceltype : 2;
    unsigned cancel_request : 1;
    xnqueue_t cleanup_handlers_q;

    /* errno value for this thread. */
    int err;

    /* For signals handling. */
    pse51_sigset_t sigmask;     /* signals mask. */
    pse51_sigqueue_t pending;   /* Pending signals */
    pse51_sigqueue_t blocked_received; /* Blocked signals received. */

    /* For thread specific data. */
    const void *tsd [PTHREAD_KEYS_MAX];

    /* For timers. */
    xnqueue_t timersq;
    
    /* For select. */
    struct xnselector *selector;

#ifdef CONFIG_XENO_OPT_PERVASIVE
    struct pse51_hkey hkey;
#endif /* CONFIG_XENO_OPT_PERVASIVE */
};

#define PSE51_JOINED_DETACHED XNTHREAD_INFO_SPARE0

#define pse51_current_thread() thread2pthread(xnpod_current_thread())

static inline void thread_set_errno (int err)
{
	*xnthread_get_errno_location(xnpod_current_thread()) = err;
}

static inline int thread_get_errno (void)
{
	return *xnthread_get_errno_location(xnpod_current_thread());
}

#define thread_name(thread) ((thread)->attr.name)

#define thread_exit_status(thread) ((thread)->exit_status)

#define thread_getdetachstate(thread) ((thread)->attr.detachstate)

#define thread_setdetachstate(thread, state) ((thread)->attr.detachstate=state)

#define thread_getcancelstate(thread) ((thread)->cancelstate)

#define thread_setcancelstate(thread, state) ((thread)->cancelstate=state)

#define thread_setcanceltype(thread, type) ((thread)->canceltype=type)

#define thread_getcanceltype(thread) ((thread)->canceltype)

#define thread_clrcancel(thread) ((thread)->cancel_request = 0)

#define thread_setcancel(thread) ((thread)->cancel_request = 1)

#define thread_cleanups(thread) (&(thread)->cleanup_handlers_q)

#define thread_gettsd(thread, key) ((thread)->tsd[key])

#define thread_settsd(thread, key, value) ((thread)->tsd[key]=(value))

void pse51_thread_abort(pthread_t thread, void *status);

static inline void thread_cancellation_point (xnthread_t *thread)
{
    pthread_t cur = thread2pthread(thread);
    
    if(cur && cur->cancel_request
        && thread_getcancelstate(cur) == PTHREAD_CANCEL_ENABLE )
        pse51_thread_abort(cur, PTHREAD_CANCELED);
}

void pse51_threadq_cleanup(pse51_kqueues_t *q);

void pse51_thread_pkg_init(u_long rrperiod);

void pse51_thread_pkg_cleanup(void);

/* round-robin period. */
extern xnticks_t pse51_time_slice;

#endif /* !_POSIX_THREAD_H */
