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

#ifndef _XENO_VRTX_QUEUE_H
#define _XENO_VRTX_QUEUE_H

#include <vrtx/defs.h>

#define VRTX_QUEUE_MAGIC 0x82820303

typedef struct vrtxqueue {

    unsigned magic;   /* Magic code - must be first */

    xnholder_t link;

#define link2vrtxqueue(ln) container_of(ln, vrtxqueue_t, link)

    int qid;

    xnsynch_t synchbase;

    char **messages;
    
    int rdptr;

    int wrptr;

    int qused;

    int qsize;	/* Does not account for the jamming slot. */

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN];
#endif /* CONFIG_XENO_OPT_REGISTRY */

} vrtxqueue_t;

#ifdef __cplusplus
extern "C" {
#endif

int vrtxqueue_init(void);

void vrtxqueue_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_VRTX_QUEUE_H */
