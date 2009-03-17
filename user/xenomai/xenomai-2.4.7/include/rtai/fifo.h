/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
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

#ifndef _RTAI_FIFO_H
#define _RTAI_FIFO_H

#include <nucleus/pipe.h>
#include <rtai/types.h>

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#define RTFIFO_SYNCWAIT  0

typedef struct rt_fifo {

    xnholder_t link;		/* !< Link in flush queue. */

#define link2rtfifo(laddr) \
((RT_FIFO *)(((char *)laddr) - (int)(&((RT_FIFO *)0)->link)))

    int minor;			/* !< Device minor number.  */

    int refcnt;			/* !< Reference count.  */

    xnpipe_mh_t *buffer;	/* !< Output buffer. */

    size_t bufsz;		/* !< Size of the output buffer.  */

    size_t fillsz;		/* !< Bytes written to the buffer.  */

    u_long status;		/* !< Status information. */

    int (*handler)(unsigned minor); /* !< Input handler. */

#ifdef CONFIG_XENO_OPT_REGISTRY
    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

    xnhandle_t handle;		/* !< Handle in registry. */
#endif /* CONFIG_XENO_OPT_REGISTRY */

} RT_FIFO;

#ifdef __cplusplus
extern "C" {
#endif

int __rtai_fifo_pkg_init(void);

void __rtai_fifo_pkg_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

int rtf_create(unsigned minor,
	       int size);

int rtf_destroy(unsigned minor);

int rtf_put(unsigned minor,
	    const void *buf,
	    int count);

int rtf_get(unsigned minor,
	    void *buf,
	    int count);

int rtf_create_handler(unsigned minor,
		       int (*handler)(unsigned minor));

#define X_FIFO_HANDLER(handler) ((int (*)(unsigned int))(handler))

int rtf_reset(unsigned minor);

#ifdef __cplusplus
}
#endif

#endif /* !_RTAI_FIFO_H */
