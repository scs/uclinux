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

#ifndef _PSOS_DEFS_H
#define _PSOS_DEFS_H

#include <nucleus/xenomai.h>

#define psos_h2obj_active(h,m,t) \
((h) && ((t *)(h))->magic == (m) ? ((t *)(h)) : NULL)

#define psos_h2obj_deleted(h,m,t) \
((h) && ((t *)(h))->magic == ~(m))

#define psos_mark_deleted(t) ((t)->magic = ~(t)->magic)

#define psos_h2obj_any(h) ((h) && \
(((*((unsigned *)(h)) & 0xffff0000) == 0x81810000) || \
(((~(*((unsigned *)(h)) & 0xffff0000)) == 0x81810000))))

#define psos_handle_error(h,m,t) \
(psos_h2obj_deleted(h,m,t) ? ERR_OBJDEL : \
(psos_h2obj_any(h) ? ERR_OBJTYPE : ERR_OBJID))

#endif /* !_PSOS_DEFS_H */
