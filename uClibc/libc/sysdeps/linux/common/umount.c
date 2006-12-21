/* vi: set sw=4 ts=4: */
/*
 * umount() for uClibc
 *
 * Copyright (C) 2000-2004 by Erik Andersen <andersen@codepoet.org>
 *
 * GNU Library General Public License (LGPL) version 2 or later.
 */

#include "syscalls.h"
#include <sys/mount.h>

#ifdef __NR_umount2
int umount(const char *special_file)
{
	return umount2(special_file, 0);
}
#else
_syscall1(int, umount, const char *, specialfile);
#endif
