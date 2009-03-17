/*
 * Copyright (C) 2006 Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>.
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

#ifndef _XENO_ERRNO_H
#define _XENO_ERRNO_H

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/xenomai.h>

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/unistd.h>         /* conflicting declaration of errno. */
#else /* __XENO_SIM__ */
#include <posix_overrides.h>
#endif /* __KERNEL__ */

/* errno values pasted from Linux asm/errno.h and bits/errno.h (ENOTSUP). */
#define ENOTSUP         EOPNOTSUPP
#define	ETIMEDOUT	110	/* Connection timed out */

#define errno (*xnthread_get_errno_location(xnpod_current_thread()))

#ifdef __cplusplus
extern "C" {
#endif

int *xnthread_get_errno_location(xnthread_t *thread);

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

#include_next <errno.h>

#endif /* !(__KERNEL__ || __XENO_SIM__) */

#endif /* _XENO_ERRNO_H */
