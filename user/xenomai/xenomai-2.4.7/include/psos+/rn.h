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

#ifndef _PSOS_RN_H
#define _PSOS_RN_H

#include <psos+/defs.h>
#include <psos+/psos.h>
#include <psos+/ppd.h>

#define PSOS_RN_MAGIC 0x81810505

/* This flag is cumulative with standard region creation flags */
#define RN_FORCEDEL   XNSYNCH_SPARE0 /* Forcible deletion allowed */

#define rn_align_mask   (sizeof(u_long)-1)

typedef struct psosrn {

    unsigned magic;		/* Magic code - must be first */

    xnholder_t link;		/* Link in psosrnq */

#define link2psosrn(ln) container_of(ln, psosrn_t, link)

    char name[XNOBJECT_NAME_LEN]; /* Name of region */

#ifdef CONFIG_XENO_OPT_REGISTRY
    xnhandle_t handle;
#endif /* CONFIG_XENO_OPT_REGISTRY */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    struct mm_struct *mm;	/* !< Creator's mm. */
    caddr_t mapbase;		/* !< Region mapping in creator's address space. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    u_long rnsize;		/* Adjusted region size */

    u_long usize;		/* Aligned allocation unit size */

    xnsynch_t synchbase;	/* Synchronization object to pend on */

    xnheap_t heapbase;		/* Nucleus heap */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2rn(ln)		container_of(ln, psosrn_t, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} psosrn_t;

#ifdef __cplusplus
extern "C" {
#endif

int psosrn_init(u_long rn0size);

void psosrn_cleanup(void);

static inline void psos_rn_flush_rq(xnqueue_t *rq)
{
	psos_flush_rq(psosrn_t, rq, rn);
}

#ifdef __cplusplus
}
#endif

#endif /* !_PSOS_RN_H */
