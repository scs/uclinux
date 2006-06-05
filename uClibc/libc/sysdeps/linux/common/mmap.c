/* vi: set sw=4 ts=4: */
/*
 * _mmap() for uClibc
 *
 * Copyright (C) 2000-2004 by Erik Andersen <andersen@codepoet.org>
 *
 * GNU Library General Public License (LGPL) version 2 or later.
 */

#include "syscalls.h"
#include <unistd.h>
#include <sys/mman.h>

#ifdef __NR_mmap
#define __NR__mmap __NR_mmap
_syscall1(__ptr_t, _mmap, unsigned long *, buffer);

struct mmap_arg_struct {
	unsigned long addr;
	unsigned long len;
	unsigned long prot;
	unsigned long flags;
	unsigned long fd;
	unsigned long offset;
};

__ptr_t mmap(__ptr_t addr, size_t len, int prot,
			 int flags, int fd, __off_t offset)
{
	struct mmap_arg_struct a;

	a.addr = (unsigned long) addr;
	a.len = (unsigned long) len;
	a.prot = (unsigned long) prot;
	a.flags = (unsigned long) flags;
	a.fd = (unsigned long) fd;
	a.offset = (unsigned long) offset;

	/* Make sure assign to a not be optimized away.  */
	asm ("":: "m"(a));
	return (__ptr_t) _mmap(&a);
}
#endif
