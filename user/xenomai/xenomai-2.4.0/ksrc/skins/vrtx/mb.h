/*
 * Copyright (C) 2001,2002 IDEALX (http://www.idealx.com/).
 * Written by Julien Pinon <jpinon@idealx.com>.
 * Copyright (C) 2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _XENO_VRTX_MB_H
#define _XENO_VRTX_MB_H

#include <vrtx/defs.h>

typedef struct vrtxmb {

    xnholder_t link;

#define link2vrtxmb(ln) container_of(ln, vrtxmb_t, link)

    xnsynch_t  synchbase;

    char **mboxp;

    /* We don't store the pending message into *mboxp directly, but
       rather into a separate field which is always accessible from
       kernel space, so that posting a new value could be done for
       user-space originated mailboxes too regardless of the current
       context. This means that peeking at the mailbox value without
       using the VRTX services won't work, but nothing says it should
       anyway, except perhaps for post-mortem analysis. In the latter
       case, the debugging code should fetch the last posted value
       from ->msg instead of dereferencing the mailbox pointer
       directly. */

    char *msg;

    struct vrtxmb *hnext;

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN];
#endif /* CONFIG_XENO_OPT_REGISTRY */

} vrtxmb_t;

#ifdef __cplusplus
extern "C" {
#endif

void vrtxmb_init(void);

void vrtxmb_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_VRTX_MB_H */
