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

#ifndef _UITRON_FLAG_H
#define _UITRON_FLAG_H

#include <nucleus/synch.h>
#include <uitron/uitron.h>
#include <uitron/defs.h>
#include <uitron/ppd.h>

#define uITRON_FLAG_MAGIC 0x85850303

typedef struct uiflag {

    unsigned magic;		/* !< Magic code - must be first. */

    VP exinf;

    ATR flgatr;

    UINT flgvalue;

    ID id;

    xnsynch_t synchbase;

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2flg(ln)		container_of(ln, struct uiflag, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

#ifdef CONFIG_XENO_OPT_REGISTRY
    char name[XNOBJECT_NAME_LEN];

    xnhandle_t handle;
#endif

} uiflag_t;

#ifdef __cplusplus
extern "C" {
#endif

int uiflag_init(void);

void uiflag_cleanup(void);

static inline void ui_flag_flush_rq(xnqueue_t *rq)
{
	ui_flush_rq(uiflag_t, rq, flg);
}

#ifdef __cplusplus
}
#endif

#endif /* !_UITRON_FLAG_H */
