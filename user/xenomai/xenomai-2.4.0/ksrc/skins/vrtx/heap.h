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

#ifndef _XENO_VRTX_HEAP_H
#define _XENO_VRTX_HEAP_H

#include "vrtx/defs.h"

#define VRTX_HEAP_MAGIC 0x82820505

typedef struct vrtxuslt { /* Region unit slot */

    unsigned prev : 15;
    unsigned next : 15;
    unsigned busy : 1;
    unsigned heading : 1;
    unsigned units;

} vrtxuslt_t;

#define heap_align_mask   (sizeof(vrtxuslt_t)-1)

struct mm_struct;

typedef struct vrtxheap {

    unsigned magic;   /* Magic code - must be first */

    xnholder_t link;  /* Link in vrtxheapq */

#define link2vrtxheap(ln) container_of(ln, vrtxheap_t, link)

    int hid;		/* VRTX identifier */

    xnsynch_t synchbase;

    u_long log2psize;	/* Aligned allocation unit size */

    u_long allocated;	/* count of allocated blocks */

    u_long released;	/* count of allocated then released blocks */

    xnheap_t sysheap;	/* memory heap */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    struct mm_struct *mm;	/* !< Creator's mm. */
    caddr_t mapbase;		/* !< Heap mapping in creator's address space. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN];
#endif /* CONFIG_XENO_OPT_REGISTRY */

} vrtxheap_t;

#ifdef __cplusplus
extern "C" {
#endif

int vrtxheap_init(u_long heap0size);

void vrtxheap_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_VRTX_HEAP_H */
