/*
 * Copyright (C) 2005 Jan Kiszka <jan.kiszka@web.de>.
 * Copyright (C) 2005 Joerg Langenberg <joerg.langenberg@gmx.net>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Xenomai is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Xenomai; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _RTDM_SYSCALL_H
#define _RTDM_SYSCALL_H

#ifndef __XENO_SIM__
#include <asm/xenomai/syscall.h>
#endif /* __XENO_SIM__ */

#define RTDM_SKIN_MAGIC		0x5254444D

#define __rtdm_fdcount		0
#define __rtdm_open		1
#define __rtdm_socket		2
#define __rtdm_close		3
#define __rtdm_ioctl		4
#define __rtdm_read		5
#define __rtdm_write		6
#define __rtdm_recvmsg		7
#define __rtdm_sendmsg		8

#ifdef __KERNEL__

#ifdef __cplusplus
extern "C" {
#endif

extern int __rtdm_muxid;

int __init rtdm_syscall_init(void);

static inline void rtdm_syscall_cleanup(void) {
	xnshadow_unregister_interface(__rtdm_muxid);
}

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ */

#endif /* _RTDM_SYSCALL_H */
