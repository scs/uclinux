/*
 * Copyright (C) 2005 Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.

 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.
 */

#include <errno.h>
#include <unistd.h>		/* ftruncate, close. */
#include <fcntl.h>		/* open */
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <posix/syscall.h>

#undef __real_mmap
#undef __real_ftruncate

extern int __pse51_muxid;

int __wrap_shm_open(const char *name, int oflag, mode_t mode)
{
	int err, fd;

	fd = __real_open("/dev/rtheap", O_RDWR, mode);

	if (fd == -1)
		return -1;

	err = -XENOMAI_SKINCALL4(__pse51_muxid,
				 __pse51_shm_open, name, oflag, mode, fd);
	if (!err)
		return fd;

#ifdef HAVE_SHM_OPEN
	if (err == ENOSYS)
		return __real_shm_open(name, oflag, mode);
#endif

	close(fd);
	errno = err;
	return -1;
}

int __wrap_shm_unlink(const char *name)
{
	int err;

	err = -XENOMAI_SKINCALL1(__pse51_muxid, __pse51_shm_unlink, name);
	if (!err)
		return 0;

#ifdef HAVE_SHM_UNLINK
	if (err == ENOSYS)
		return __real_shm_unlink(name);
#endif
	
	errno = err;
	return -1;
}

int __wrap_ftruncate(int fildes, long length)
{
	int err;

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_ftruncate, fildes, length);
	if (!err)
		return 0;

	if (err == EBADF || err == ENOSYS)
		return __real_ftruncate(fildes, length);

	errno = err;
	return -1;
}

void *__wrap_mmap(void *addr,
		  size_t len, int prot, int flags, int fildes, long off)
{
	struct {
		unsigned long kaddr;
		unsigned long len;
		unsigned long ioctl_cookie;
		unsigned long mapsize;
		unsigned long offset;
	} map;
	void *uaddr;
	int err;

	err = -XENOMAI_SKINCALL4(__pse51_muxid,
				 __pse51_mmap_prologue, len, fildes, off, &map);

	if (err == EBADF || err == ENOSYS)
		return __real_mmap(addr, len, prot, flags, fildes, off);

	if (err)
		goto error;

	err = __real_ioctl(fildes, 0, map.ioctl_cookie);

	if (err)
		goto err_mmap_epilogue;

	/* map the whole heap. */
	uaddr = __real_mmap(NULL, map.mapsize, prot, flags, fildes, 0);

	if (uaddr == MAP_FAILED) {
	      err_mmap_epilogue:
		XENOMAI_SKINCALL2(__pse51_muxid,
				  __pse51_mmap_epilogue, MAP_FAILED, &map);
		return MAP_FAILED;
	}

	/* Forbid access to map.offset first bytes. */
	mprotect(uaddr, map.offset, PROT_NONE);

	uaddr = (char *)uaddr + map.offset;

	/* Forbid access to the last mapsize - offset - len bytes. */
	if (len < map.mapsize - map.offset)
		mprotect((char *)uaddr + len, map.mapsize - map.offset - len,
			 PROT_NONE);

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_mmap_epilogue,
				 (unsigned long)uaddr, &map);

	if (!err)
		return uaddr;

	__real_munmap(uaddr, map.mapsize);

      error:
	errno = err;
	return MAP_FAILED;
}

/* 32 bits platform */
#if __WORDSIZE == 32
int __wrap_ftruncate64(int fildes, long long length)
{
	int err;

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_ftruncate, fildes,
				 ((unsigned long long) length < LONG_MAX
				  ? (long) length : -1L));
	if (!err)
		return 0;

	if (err == EBADF || err == ENOSYS)
		return __real_ftruncate64(fildes, length);

	errno = err;
	return -1;
}

void *__wrap_mmap64(void *addr,
		    size_t len, int prot, int flags, int fildes, long long off)
{
	struct {
		unsigned long kaddr;
		unsigned long len;
		unsigned long ioctl_cookie;
		unsigned long mapsize;
		unsigned long offset;
	} map;
	void *uaddr;
	int err;

	err = -XENOMAI_SKINCALL4(__pse51_muxid,
				 __pse51_mmap_prologue, len, fildes,
				 ((unsigned long long) off < LONG_MAX
				  ? (long) off : -1L), &map);

	if (err == EBADF || err == ENOSYS)
		return __real_mmap64(addr, len, prot, flags, fildes, off);

	if (err)
		goto error;

	err = __real_ioctl(fildes, 0, map.ioctl_cookie);

	if (err)
		goto err_mmap_epilogue;

	/* map the whole heap. */
	uaddr = __real_mmap64(NULL, map.mapsize, prot, flags, fildes, 0);

	if (uaddr == MAP_FAILED) {
	      err_mmap_epilogue:
		XENOMAI_SKINCALL2(__pse51_muxid,
				  __pse51_mmap_epilogue, MAP_FAILED, &map);
		return MAP_FAILED;
	}

	/* Forbid access to map.offset first bytes. */
	mprotect(uaddr, map.offset, PROT_NONE);

	uaddr = (char *)uaddr + map.offset;

	/* Forbid access to the last mapsize - offset - len bytes. */
	if (len < map.mapsize - map.offset)
		mprotect((char *)uaddr + len, map.mapsize - map.offset - len,
			 PROT_NONE);

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_mmap_epilogue,
				 (unsigned long)uaddr, &map);

	if (!err)
		return uaddr;

	__real_munmap(uaddr, map.mapsize);

      error:
	errno = err;
	return MAP_FAILED;
}
#endif

int __shm_close(int fd)
{
	int err;

	err = XENOMAI_SKINCALL1(__pse51_muxid, __pse51_shm_close, fd);

	if (!err)
		return __real_close(fd);

	errno = -err;
	return -1;
}

int __wrap_munmap(void *addr, size_t len)
{
	struct {
		unsigned long mapsize;
		unsigned long offset;
	} map;
	int err;

	err = -XENOMAI_SKINCALL3(__pse51_muxid,
				 __pse51_munmap_prologue, addr, len, &map);

	if (err == ENXIO || err == ENOSYS)
		return __real_munmap(addr, len);

	if (err)
		goto error;

	if (__real_munmap((char *)addr - map.offset, map.mapsize))
		return -1;

	err = -XENOMAI_SKINCALL2(__pse51_muxid,
				 __pse51_munmap_epilogue, addr, len);

	if (!err)
		return 0;

      error:
	errno = err;
	return -1;
}
