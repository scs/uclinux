/*
 * Copyright (C) 2001-2006 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_NUCLEUS_COMPILER_H
#define _XENO_NUCLEUS_COMPILER_H

#if !defined(__IN_XENOMAI__) && (__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0))
#define __deprecated_call__		__attribute__((deprecated))
#if defined(__KERNEL__) || defined(__XENO_SIM__)
#define __deprecated_call_in_user__
#define __deprecated_call_in_kernel__	__deprecated_call__
#else /* !(__KERNEL__ || __XENO_SIM__) */
#define __deprecated_call_in_user__	__deprecated_call__
#define __deprecated_call_in_kernel__
#endif /* __KERNEL__ || __XENO_SIM__ */
#else /* __IN_XENOMAI__ || !(__GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0)) */
#define __deprecated_call__
#define __deprecated_call_in_user__
#define __deprecated_call_in_kernel__
#endif /* __GNUC__ > 3 || (__GNUC__ == 3 && __GNUC_MINOR__ > 0) */

#ifndef likely
#if !defined(__GNUC__) || __GNUC__ == 2 && __GNUC_MINOR__ < 96
#define __builtin_expect(x, v)         (x)
#endif /* !gcc or gcc version < 2.96 */

#define likely(x)   __builtin_expect((x) != 0, 1)
#define unlikely(x) __builtin_expect((x) != 0, 0)
#endif /* !defined(likely) */

#endif /* !_XENO_NUCLEUS_COMPILER_H */
