/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_POSIX_UNISTD_H
#define _XENO_POSIX_UNISTD_H

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/xenomai.h>

#ifdef __KERNEL__
#include <linux/types.h>
#endif /* __KERNEL__ */

#ifdef __XENO_SIM__
#include <posix_overrides.h>
#endif /* __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

#undef close
#define close pse51_shm_close

int pse51_shm_close(int fildes);

int ftruncate(int fildes, off_t length);

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

#include_next <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS != 64
int __real_ftruncate(int fildes, long length);
#else
#define __real_ftruncate __real_ftruncate64
#endif
#ifdef _LARGEFILE64_SOURCE
int __real_ftruncate64(int fildes, long long length);
#endif

ssize_t __real_read(int fd, void *buf, size_t nbyte);

ssize_t __real_write(int fd, const void *buf, size_t nbyte);

int __real_close(int fildes);

#ifdef __cplusplus
}
#endif

#endif /* !(__KERNEL__ || __XENO_SIM__) */

#endif /* _XENO_POSIX_UNISTD_H */
