/*
 * @note Copyright (C) 2001,2002,2003 Philippe Gerum.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA
 * 02139, USA; either version 2 of the License, or (at your option)
 * any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _XENO_NUCLEUS_PIPE_H
#define _XENO_NUCLEUS_PIPE_H

#define XNPIPE_NDEVS      CONFIG_XENO_OPT_PIPE_NRDEV
#define XNPIPE_DEV_MAJOR  150

#define	XNPIPE_IOCTL_BASE	'p'
#define XNPIPEIOC_GET_NRDEV	_IOW(XNPIPE_IOCTL_BASE, 0, int)
#define XNPIPEIOC_IFLUSH	_IO(XNPIPE_IOCTL_BASE,1)
#define XNPIPEIOC_OFLUSH	_IO(XNPIPE_IOCTL_BASE,2)
#define XNPIPEIOC_FLUSH		XNPIPEIOC_OFLUSH
#define XNPIPEIOC_SETSIG	_IO(XNPIPE_IOCTL_BASE,3)

#define XNPIPE_NORMAL  0x0
#define XNPIPE_URGENT  0x1

#define XNPIPE_IFLUSH  0x1
#define XNPIPE_OFLUSH  0x2

#define XNPIPE_MINOR_AUTO  -1

#ifdef __KERNEL__

#include <nucleus/queue.h>
#include <nucleus/synch.h>
#include <nucleus/thread.h>
#include <linux/types.h>
#include <linux/poll.h>

#define XNPIPE_KERN_CONN         0x1
#define XNPIPE_KERN_LCLOSE       0x2
#define XNPIPE_USER_CONN         0x4
#define XNPIPE_USER_SIGIO        0x8
#define XNPIPE_USER_WREAD        0x10
#define XNPIPE_USER_WREAD_READY  0x20
#define XNPIPE_USER_WSYNC        0x40
#define XNPIPE_USER_WSYNC_READY  0x80

#define XNPIPE_USER_ALL_WAIT \
(XNPIPE_USER_WREAD|XNPIPE_USER_WSYNC)

#define XNPIPE_USER_ALL_READY \
(XNPIPE_USER_WREAD_READY|XNPIPE_USER_WSYNC_READY)

typedef struct xnpipe_mh {

	struct xnholder link;
	unsigned size;
	unsigned rdoff;

} xnpipe_mh_t;

static inline xnpipe_mh_t *link2mh(struct xnholder *ln)
{
	return ln ? container_of(ln, xnpipe_mh_t, link) : NULL;
}

struct xnpipe_state;

struct xnpipe_operations {
	void (*output)(struct xnpipe_mh *mh, void *xstate);
	int (*input)(struct xnpipe_mh *mh, int retval, void *xstate);
	void *(*alloc_ibuf)(size_t size, void *xstate);
	void (*free_ibuf)(void *buf, void *xstate);
	void (*free_obuf)(void *buf, void *xstate);
	void (*release)(void *xstate);
};

struct xnpipe_state {

	struct xnholder slink;	/* Link on sleep queue */
	struct xnholder alink;	/* Link on async queue */
#define link2xnpipe(ln, fld)	container_of(ln, struct xnpipe_state, fld)

	struct xnqueue inq;		/* From user-space to kernel */
	struct xnqueue outq;		/* From kernel to user-space */
	struct xnsynch synchbase;
	struct xnpipe_operations ops;
	void *xstate;		/* Extra state managed by caller */

	/* Linux kernel part */
	xnflags_t status;
	struct fasync_struct *asyncq;
	wait_queue_head_t readq;	/* open/read/poll waiters */
	wait_queue_head_t syncq;	/* sync waiters */
	int wcount;			/* number of waiters on this minor */
	size_t ionrd;

};

extern struct xnpipe_state xnpipe_states[];

#define xnminor_from_state(s) (s - xnpipe_states)

#ifdef __cplusplus
extern "C" {
#endif				/* __cplusplus */

int xnpipe_mount(void);

void xnpipe_umount(void);

/* Entry points of the kernel interface. */

int xnpipe_connect(int minor,
		   struct xnpipe_operations *ops, void *xstate);

int xnpipe_disconnect(int minor);

ssize_t xnpipe_send(int minor,
		    struct xnpipe_mh *mh, size_t size, int flags);

ssize_t xnpipe_mfixup(int minor, struct xnpipe_mh *mh, ssize_t size);

ssize_t xnpipe_recv(int minor,
		    struct xnpipe_mh **pmh, xnticks_t timeout);

int xnpipe_flush(int minor, int mode);

#ifdef __cplusplus
}
#endif /* __cplusplus */

static inline struct xnholder *xnpipe_m_link(xnpipe_mh_t *mh)
{
	return &mh->link;
}

static inline char *xnpipe_m_data(xnpipe_mh_t *mh)
{
	return (char *)(mh + 1);
}

#define xnpipe_m_size(mh) ((mh)->size)

#define xnpipe_m_rdoff(mh) ((mh)->rdoff)

#endif /* __KERNEL__ */

#endif /* !_XENO_NUCLEUS_PIPE_H */
