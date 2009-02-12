/*
 * Copyright (C) 2001-2007 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _UITRON_SEM_H
#define _UITRON_SEM_H

#include <nucleus/synch.h>
#include <uitron/uitron.h>
#include <uitron/defs.h>
#include <uitron/ppd.h>

#define uITRON_SEM_MAGIC 0x85850202

typedef struct uisem {

    unsigned magic;		/* Magic code - must be first */

    ID id;

    VP exinf;

    ATR sematr;

    INT semcnt;

    INT maxsem;

    xnsynch_t synchbase;

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2sem(ln)		container_of(ln, struct uisem, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

#ifdef CONFIG_XENO_OPT_REGISTRY
    char name[XNOBJECT_NAME_LEN];

    xnhandle_t handle;
#endif

} uisem_t;

#ifdef __cplusplus
extern "C" {
#endif

int uisem_init(void);

void uisem_cleanup(void);

static inline void ui_sem_flush_rq(xnqueue_t *rq)
{
	ui_flush_rq(uisem_t, rq, sem);
}

#ifdef __cplusplus
}
#endif

#endif /* !_UITRON_SEM_H */
