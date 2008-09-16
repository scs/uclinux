/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_IA64_WRAPPERS_H
#define _XENO_ASM_IA64_WRAPPERS_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

#include <asm-generic/xenomai/wrappers.h> /* Read the generic portion. */
#include <linux/interrupt.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

#define wrap_access_ok(task,addr,size) __access_ok((addr),(size),(task)->addr_limit)

#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)  */

#define wrap_access_ok(task,addr,size) __access_ok((addr),(size),task_thread_info(task)->addr_limit)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#define task_pt_regs(t)  ia64_task_regs(t)
#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)  */

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0) */

typedef irqreturn_t (*rthal_irq_host_handler_t)(int irq,
						void *dev_id,
						struct pt_regs *regs);

#endif /* _XENO_ASM_IA64_WRAPPERS_H */
