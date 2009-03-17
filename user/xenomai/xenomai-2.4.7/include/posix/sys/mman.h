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

#ifndef _XENO_POSIX_SYS_MMAN_H
#define _XENO_POSIX_SYS_MMAN_H

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/xenomai.h>

#ifdef __KERNEL__
#include <asm/mman.h>
#endif /* __KERNEL__ */

#ifdef __XENO_SIM__
#include_next <sys/mman.h>
#include <posix_overrides.h>
#endif /* __XENO_SIM__ */

#define MAP_FAILED ((void *) -1)

#ifdef __cplusplus
extern "C" {
#endif

int shm_open(const char *name, int oflag, mode_t mode); 

int shm_unlink(const char *name);

void *mmap(void *addr, size_t len, int prot, int flags,
	   int fildes, off_t off);

int munmap(void *addr, size_t len);

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

#include_next <sys/mman.h>

#ifdef __cplusplus
extern "C" {
#endif

int __real_shm_open(const char *name, int oflag, mode_t mode); 

int __real_shm_unlink(const char *name);

#if !defined(_FILE_OFFSET_BITS) || _FILE_OFFSET_BITS != 64
void *__real_mmap(void *addr,
                  size_t len,
                  int prot,
                  int flags,
                  int fildes,
                  long off);
#else
#define __real_mmap __real_mmap64
#endif
#ifdef _LARGEFILE64_SOURCE
void *__real_mmap64(void *addr,
		    size_t len,
		    int prot,
		    int flags,
		    int fildes,
		    long long off);
#endif

int __real_munmap(void *addr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* !(__KERNEL__ || __XENO_SIM__) */

#endif /* _XENO_POSIX_SYS_MMAN_H */
