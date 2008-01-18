/*
 * Copyright (C) 2000 Lennert Buytenhek
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include "libbridge.h"
#include "libbridge_private.h"

static int br_ioctl32(unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	unsigned long arg[3];

	arg[0] = arg0;
	arg[1] = arg1;
	arg[2] = arg2;

	return ioctl(br_socket_fd, SIOCGIFBR, arg);
}

#ifdef __sparc__
static int br_ioctl64(unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
	unsigned long long arg[3];

	arg[0] = arg0;
	arg[1] = arg1;
	arg[2] = arg2;

	return ioctl(br_socket_fd, SIOCGIFBR, arg);
}

int __kernel_is_64_bit()
{
	static int kernel_is_64_bit = -1;

	if (kernel_is_64_bit == -1) {
		struct utsname buf;

		uname(&buf);
		kernel_is_64_bit = !strcmp(buf.machine, "sparc64");
	}

	return kernel_is_64_bit;
}
#endif

int br_ioctl(unsigned long arg0, unsigned long arg1, unsigned long arg2)
{
#ifdef __sparc__
	if (__kernel_is_64_bit())
		return br_ioctl64(arg0, arg1, arg2);
#endif

	return br_ioctl32(arg0, arg1, arg2);
}

int br_get_version()
{
	return br_ioctl(BRCTL_GET_VERSION, 0, 0);
}

int br_add_bridge(char *brname)
{
	char _br[IFNAMSIZ];

	memcpy(_br, brname, IFNAMSIZ);
	if (br_ioctl(BRCTL_ADD_BRIDGE, (unsigned long)_br, 0) < 0)
		return errno;

	return 0;
}

int br_del_bridge(char *brname)
{
	char _br[IFNAMSIZ];

	memcpy(_br, brname, IFNAMSIZ);
	if (br_ioctl(BRCTL_DEL_BRIDGE, (unsigned long)_br, 0) < 0)
		return errno;

	return 0;
}
