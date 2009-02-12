/*
 * Copyright (C) 2006 Jan Kiszka <jan.kiszka@web.de>.
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
 *
 * User-space interface to the arch-specific tracing support.
 */

#ifndef _XENO_NUCLEUS_TRACE_H
#define _XENO_NUCLEUS_TRACE_H

#define __xntrace_op_max_begin		0
#define __xntrace_op_max_end		1
#define __xntrace_op_max_reset		2
#define __xntrace_op_user_start		3
#define __xntrace_op_user_stop		4
#define __xntrace_op_user_freeze	5
#define __xntrace_op_special		6
#define __xntrace_op_special_u64	7

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <asm/xenomai/system.h>

#define xntrace_max_begin(v)		xnarch_trace_max_begin(v)
#define xntrace_max_end(v)		xnarch_trace_max_end(v)
#define xntrace_max_reset()		xnarch_trace_max_reset()
#define xntrace_user_start()		xnarch_trace_user_start()
#define xntrace_user_stop(v)		xnarch_trace_user_stop(v)
#define xntrace_user_freeze(v, once)	xnarch_trace_user_freeze(v, once)
#define xntrace_special(id, v)	xnarch_trace_special(id, v)
#define xntrace_special_u64(id, v)	xnarch_trace_special_u64(id, v)
#define xntrace_pid(pid, prio)	xnarch_trace_pid(pid, prio)
#define xntrace_panic_freeze()	xnarch_trace_panic_freeze()
#define xntrace_panic_dump()		xnarch_trace_panic_dump()

#else /* !(defined(__KERNEL__) || defined(__XENO_SIM__)) */

#include <asm/xenomai/syscall.h>

static inline int xntrace_max_begin(unsigned long v)
{
	return XENOMAI_SYSCALL2(__xn_sys_trace, __xntrace_op_max_begin, v);
}

static inline int xntrace_max_end(unsigned long v)
{
	return XENOMAI_SYSCALL2(__xn_sys_trace, __xntrace_op_max_end, v);
}

static inline int xntrace_max_reset(void)
{
	return XENOMAI_SYSCALL1(__xn_sys_trace, __xntrace_op_max_reset);
}

static inline int xntrace_user_start(void)
{
	return XENOMAI_SYSCALL1(__xn_sys_trace, __xntrace_op_user_start);
}

static inline int xntrace_user_stop(unsigned long v)
{
	return XENOMAI_SYSCALL2(__xn_sys_trace, __xntrace_op_user_stop, v);
}

static inline int xntrace_user_freeze(unsigned long v, int once)
{
	return XENOMAI_SYSCALL3(__xn_sys_trace, __xntrace_op_user_freeze,
				v, once);
}

static inline int xntrace_special(unsigned char id, unsigned long v)
{
	return XENOMAI_SYSCALL3(__xn_sys_trace, __xntrace_op_special, id, v);
}

static inline int xntrace_special_u64(unsigned char id, unsigned long long v)
{
	return XENOMAI_SYSCALL4(__xn_sys_trace, __xntrace_op_special_u64, id,
				(unsigned long)(v >> 32),
				(unsigned long)(v & 0xFFFFFFFF));
}

#endif /* defined(__KERNEL__) || defined(__XENO_SIM__) */

#endif /* !_XENO_NUCLEUS_TRACE_H */
