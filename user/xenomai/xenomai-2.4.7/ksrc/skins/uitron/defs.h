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

#ifndef _UITRON_DEFS_H
#define _UITRON_DEFS_H

#include <nucleus/map.h>

#define uITRON_MAX_TASKID 64	/* [1..64] */
#define uITRON_MAX_SEMID  32	/* [1..32] */
#define uITRON_MAX_FLAGID 32	/* [1..32] */
#define uITRON_MAX_MBXID  32	/* [1..32] */
#define uITRON_MAX_MBFID  32	/* [1..32] */
#define uITRON_MAX_IDS    64

#if XNMAP_MAX_KEYS < uITRON_MAX_IDS
#error "Internal map cannot hold so many identifiers"
#endif

#define ui_h2obj(h,m,t) \
((h) && ((t *)(h))->magic == (m) ? ((t *)(h)) : NULL)

#define ui_mark_deleted(t) ((t)->magic = 0)

#define ui_isobj(h) ((h) && \
((*((unsigned *)(h)) & 0xffff0000) == 0x85850000)

extern xntbase_t *ui_tbase;

#endif /* !_UITRON_DEFS_H */
