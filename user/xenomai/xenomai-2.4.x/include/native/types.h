/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
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

#ifndef _XENO_TYPES_H
#define _XENO_TYPES_H

#define XENO_SKIN_MAGIC  0x52544149

#include <nucleus/types.h>

#define TM_INFINITE XN_INFINITE
#define TM_NONBLOCK XN_NONBLOCK
#define TM_NOW      XN_INFINITE

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#ifndef CONFIG_XENO_OPT_DEBUG_NATIVE
#define CONFIG_XENO_OPT_DEBUG_NATIVE  0
#endif

typedef xnticks_t RTIME;

typedef xnsticks_t SRTIME;

#define xeno_h2obj_validate(h,m,t) \
((h) && ((t *)(h))->magic == (m) ? ((t *)(h)) : NULL)

#define xeno_h2obj_deleted(h,m,t) \
((h) && ((t *)(h))->magic == ~(m))

#define xeno_mark_deleted(t) ((t)->magic = ~(t)->magic)

#define xeno_handle_error(h,m,t) \
(xeno_h2obj_deleted(h,m,t) ? -EIDRM : -EINVAL)

#define xeno_test_magic(h,m) \
((h) && *((unsigned *)(h)) == (m))

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef unsigned long long RTIME;

typedef long long SRTIME;

#endif /* __KERNEL__ || __XENO_SIM__ */

typedef xnsigmask_t rt_sigset_t;

#define RT_HANDLER_NONE XNTHREAD_INVALID_ASR

struct rt_alarm;

typedef void (*rt_alarm_t)(struct rt_alarm *alarm,
			   void *cookie);

typedef xnisr_t rt_isr_t;

typedef xniack_t rt_iack_t;

#endif /* !_XENO_TYPES_H */
