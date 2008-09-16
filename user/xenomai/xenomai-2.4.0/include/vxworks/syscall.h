/*
 * Copyright (C) 2006 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_VXWORKS_SYSCALL_H
#define _XENO_VXWORKS_SYSCALL_H

#ifndef __XENO_SIM__
#include <asm/xenomai/syscall.h>
#endif /* __XENO_SIM__ */

#define __vxworks_task_init        0
#define __vxworks_task_activate    1
#define __vxworks_task_deleteforce 2
#define __vxworks_task_delete      3
#define __vxworks_task_suspend     4
#define __vxworks_task_resume      5
#define __vxworks_task_self        6
#define __vxworks_task_priorityset 7
#define __vxworks_task_priorityget 8
#define __vxworks_task_lock        9
#define __vxworks_task_unlock      10
#define __vxworks_task_safe        11
#define __vxworks_task_unsafe      12
#define __vxworks_task_delay       13
#define __vxworks_task_verifyid    14
#define __vxworks_task_nametoid    15
#define __vxworks_sem_bcreate      16
#define __vxworks_sem_ccreate      17
#define __vxworks_sem_mcreate      18
#define __vxworks_sem_delete       19
#define __vxworks_sem_take         20
#define __vxworks_sem_give         21
#define __vxworks_sem_flush        22
#define __vxworks_taskinfo_name    23
#define __vxworks_taskinfo_iddfl   24
#define __vxworks_taskinfo_status  25
#define __vxworks_errno_taskset    26
#define __vxworks_errno_taskget    27
#define __vxworks_kernel_timeslice 28
#define __vxworks_msgq_create      29
#define __vxworks_msgq_delete      30
#define __vxworks_msgq_nummsgs     31
#define __vxworks_msgq_receive     32
#define __vxworks_msgq_send        33
#define __vxworks_tick_get         34
#define __vxworks_tick_set         35
#define __vxworks_sys_clkdisable   36
#define __vxworks_sys_clkenable    37
#define __vxworks_sys_clkrateget   38
#define __vxworks_sys_clkrateset   39
#define __vxworks_wd_create        40
#define __vxworks_wd_delete        41
#define __vxworks_wd_start         42
#define __vxworks_wd_cancel        43
#define __vxworks_wd_wait          44
#define __vxworks_int_context      45

struct wind_arg_bulk {

    u_long a1;
    u_long a2;
    u_long a3;
};

#ifdef __KERNEL__

#ifdef __cplusplus
extern "C" {
#endif

int wind_syscall_init(void);

void wind_syscall_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ */

#endif /* _XENO_VXWORKS_SYSCALL_H */
