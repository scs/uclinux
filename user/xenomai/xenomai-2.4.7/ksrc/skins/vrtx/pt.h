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

#ifndef _XENO_VRTX_PT_H
#define _XENO_VRTX_PT_H

#include "vrtx/defs.h"

#define VRTX_PT_MAGIC 0x82820404

#define ptext_align_mask   (sizeof(void *)-1)

#define ptext_bitmap_pos(ptext,n) \
ptext->bitmap[((n) / (sizeof(u_long) * 8))]

#define ptext_block_pos(n) \
(1 << ((n) % (sizeof(u_long) * 8)))

#define ptext_bitmap_setbit(ptext,n) \
(ptext_bitmap_pos(ptext,n) |= ptext_block_pos(n))

#define ptext_bitmap_clrbit(ptext,n) \
(ptext_bitmap_pos(ptext,n) &= ~ptext_block_pos(n))

#define ptext_bitmap_tstbit(ptext,n) \
(ptext_bitmap_pos(ptext,n) & ptext_block_pos(n))

typedef struct vrtxptext {

    xnholder_t link;	/* Link in vrtxpt->extq */

#define link2vrtxptext(ln) container_of(ln, vrtxptext_t, link)

    void *freelist;	/* Free block list head */

    char *data;		/* Pointer to the user space behind the bitmap */

    u_long nblks;	/* Number of data blocks */

    u_long extsize;	/* Size of storage space */

    u_long bitmap[1];	/* Start of bitmap -- keeps alignment */

} vrtxptext_t;

struct mm_struct;
struct xnheap;

typedef struct vrtxpt {

    unsigned magic;   /* Magic code - must be first */

    xnholder_t link;  /* Link in vrtxptq */

    xnqueue_t extq;   /* Linked list of active extents */

#define link2vrtxpt(ln) container_of(ln, vrtxpt_t, link)

    int pid;		/* Partition identifier */

    u_long bsize;	/* (Aligned) Block size */

    u_long ublks;	/* Overall number of used blocks */

    u_long fblks;	/* Overall number of free blocks */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    struct mm_struct *mm;	/* !< Creator's mm. */
    caddr_t mapbase;		/* !< Partition mapping in creator's address space. */
    struct xnheap *sysheap;	/* !< Underlying heap */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
    char name[XNOBJECT_NAME_LEN];
#endif /* CONFIG_XENO_OPT_REGISTRY */

} vrtxpt_t;

#ifdef __cplusplus
extern "C" {
#endif

int vrtxpt_init(void);

void vrtxpt_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_VRTX_PT_H */
