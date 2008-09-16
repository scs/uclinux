/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
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

#ifndef _XENO_PIPE_H
#define _XENO_PIPE_H

#include <nucleus/pipe.h>
#include <nucleus/heap.h>
#include <native/types.h>

/* Operation flags. */
#define P_NORMAL  XNPIPE_NORMAL
#define P_URGENT  XNPIPE_URGENT

#define P_MINOR_AUTO	XNPIPE_MINOR_AUTO

typedef struct rt_pipe_placeholder {
    xnhandle_t opaque;
} RT_PIPE_PLACEHOLDER;

#ifdef __KERNEL__

#include <native/ppd.h>

#define XENO_PIPE_MAGIC  0x55550202

#define P_SYNCWAIT  0
#define P_ATOMIC    1

typedef xnpipe_mh_t RT_PIPE_MSG;

#define P_MSGPTR(msg)  xnpipe_m_data(msg)
#define P_MSGSIZE(msg) xnpipe_m_size(msg)

typedef struct rt_pipe {

    unsigned magic;		/* !< Magic code -- must be first. */

    xnholder_t link;		/* !< Link in flush queue. */

#define link2rtpipe(ln)	container_of(ln, RT_PIPE, link)

    int minor;			/* !< Device minor number.  */

    RT_PIPE_MSG *buffer;	/* !< Buffer used in byte stream mode. */

    xnheap_t *bufpool;         /* !< Current buffer pool. */

    xnheap_t privpool;         /* !< Private buffer pool. */

    size_t fillsz;		/* !< Bytes written to the buffer.  */

    u_long status;		/* !< Status information. */

    xnhandle_t handle;		/* !< Handle in registry -- zero if unregistered. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    pid_t cpid;			/* !< Creator's pid. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2pipe(ln)		container_of(ln, RT_PIPE, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} RT_PIPE;

#else /* !__KERNEL__ */

typedef RT_PIPE_PLACEHOLDER RT_PIPE;

#endif /* __KERNEL__ */

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface. */

int rt_pipe_create(RT_PIPE *pipe,
		   const char *name,
		   int minor,
		   size_t poolsize);

int rt_pipe_delete(RT_PIPE *pipe);

ssize_t rt_pipe_read(RT_PIPE *pipe,
		     void *buf,
		     size_t size,
		     RTIME timeout);

ssize_t rt_pipe_write(RT_PIPE *pipe,
		      const void *buf,
		      size_t size,
		      int mode);

ssize_t rt_pipe_stream(RT_PIPE *pipe,
		       const void *buf,
		       size_t size);

#ifdef __KERNEL__

ssize_t rt_pipe_receive(RT_PIPE *pipe,
			RT_PIPE_MSG **msg,
			RTIME timeout);

ssize_t rt_pipe_send(RT_PIPE *pipe,
		     RT_PIPE_MSG *msg,
		     size_t size,
		     int mode);

RT_PIPE_MSG *rt_pipe_alloc(RT_PIPE *pipe,
                           size_t size);

int rt_pipe_free(RT_PIPE *pipe,
                 RT_PIPE_MSG *msg);

int rt_pipe_flush(RT_PIPE *pipe,
		  int mode);

#ifdef CONFIG_XENO_OPT_NATIVE_PIPE

int __native_pipe_pkg_init(void);

void __native_pipe_pkg_cleanup(void);

static inline void __native_pipe_flush_rq(xnqueue_t *rq)
{
	xeno_flush_rq(RT_PIPE, rq, pipe);
}

#else /* !CONFIG_XENO_OPT_NATIVE_PIPE */

#define __native_pipe_pkg_init()		({ 0; })
#define __native_pipe_pkg_cleanup()		do { } while(0)
#define __native_pipe_flush_rq(rq)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_NATIVE_PIPE */

#else /* !__KERNEL__ */

int rt_pipe_bind(RT_PIPE *pipe,
		 const char *name,
		 RTIME timeout);

static inline int rt_pipe_unbind(RT_PIPE *pipe)
{
    pipe->opaque = XN_NO_HANDLE;
    return 0;
}

#endif /* __KERNEL__ */

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_PIPE_H */
