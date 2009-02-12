/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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
 */

#ifndef _PSOS_PT_H
#define _PSOS_PT_H

#include <psos+/defs.h>
#include <psos+/psos.h>
#include <psos+/ppd.h>

#define PSOS_PT_MAGIC 0x81810404

#define pt_align_mask   (sizeof(void *)-1)

#define pt_bitmap_pos(pt,n) \
pt->bitmap[((n) / (sizeof(u_long) * 8))]

#define pt_block_pos(n) \
(1L << ((n) % (sizeof(u_long) * 8)))

#define pt_bitmap_setbit(pt,n) \
(pt_bitmap_pos(pt,n) |= pt_block_pos(n))

#define pt_bitmap_clrbit(pt,n) \
(pt_bitmap_pos(pt,n) &= ~pt_block_pos(n))

#define pt_bitmap_tstbit(pt,n) \
(pt_bitmap_pos(pt,n) & pt_block_pos(n))

typedef struct psospt {

    unsigned magic;   /* Magic code - must be first */

    xnholder_t link;  /* Link in psosptq */

#define link2psospt(ln) container_of(ln, psospt_t, link)

    char name[XNOBJECT_NAME_LEN]; /* Symbolic name of partition */

    u_long flags;

    u_long bsize;		/* (Aligned) Block size */

    u_long psize;		/* Size of storage space */

    u_long nblks;		/* Number of data blocks */

    u_long ublks;		/* Number of used blocks */

    void *freelist;		/* Free block list head */

    char *data;			/* Pointer to the user space behind the bitmap */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2pt(ln)		container_of(ln, psospt_t, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

    u_long bitmap[1];		/* Start of bitmap -- keeps alignment */

} psospt_t;

#ifdef __cplusplus
extern "C" {
#endif

void psospt_init(void);

void psospt_cleanup(void);

static inline void psos_pt_flush_rq(xnqueue_t *rq)
{
	psos_flush_rq(psospt_t, rq, pt);
}

#ifdef __cplusplus
}
#endif

#endif /* !_PSOS_PT_H */
