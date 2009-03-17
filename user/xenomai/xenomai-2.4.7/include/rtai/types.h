/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _RTAI_TYPES_H
#define _RTAI_TYPES_H

#define RTAI_SKIN_MAGIC  0x56544442

#include <nucleus/types.h>

#if defined(__KERNEL__) || defined(__XENO_SIM__)

typedef xnsticks_t RTIME;

#define rtai_h2obj_validate(h,m,t) \
((h) && ((t *)(h))->magic == (m) ? ((t *)(h)) : NULL)

#define rtai_h2obj_deleted(h,m,t) \
((h) && ((t *)(h))->magic == ~(m))

#define rtai_mark_deleted(t) ((t)->magic = ~(t)->magic)

#define rtai_test_magic(h,m) \
((h) && *((unsigned *)(h)) == (m))

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef long long RTIME;

#endif /* __KERNEL__ || __XENO_SIM__ */

#endif /* !_RTAI_TYPES_H */
