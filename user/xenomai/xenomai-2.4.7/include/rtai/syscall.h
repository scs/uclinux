/**
 *
 * @note Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org> 
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

#ifndef _RTAI_SYSCALL_H
#define _RTAI_SYSCALL_H

#include <rtai/types.h>
#include <asm/xenomai/syscall.h>

#if 0
#define __rtai_task_create		0
#define __rtai_task_init		1
#define __rtai_task_make_periodic	2
#define __rtai_task_make_periodic_relative_ns	3
#define __rtai_task_suspend		4
#define __rtai_task_resume		5
#define __rtai_task_delete		6
#define __rtai_task_wait_period		7
#define __rtai_set_oneshot_mode		8
#define __rtai_rt_set_periodic_mode	9
#define __rtai_start_rt_timer		10
#define __rtai_stop_rt_timer		11
#define __rtai_rt_sleep			12
#define __rtai_get_time_ns		13
#define __rtai_request_irq		14
#define __rtai_release_irq		15
#define __rtai_ack_irq			16
#define __rtai_enable_irq		17
#define __rtai_disable_irq		18
#define __rtai_typed_sem_init		19
#define __rtai_sem_delete		20
#define __rtai_sem_signal		21
#define __rtai_sem_wait			22
#define __rtai_sem_wait_if		23
#define __rtai_rtf_create		24
#define __rtai_rtf_destroy		25
#define __rtai_rtf_put			26
#define __rtai_rtf_get			27
#define __rtai_rtf_create_handler	28
#define __rtai_rtf_reset		29
#endif
#define __rtai_shm_heap_open		30
#define __rtai_shm_heap_close		31

struct rtai_arg_bulk {

    u_long a1;
    u_long a2;
    u_long a3;
    u_long a4;
    u_long a5;
};


#ifdef __KERNEL__

#ifdef __cplusplus
extern "C" {
#endif

int __rtai_syscall_init(void);

void __rtai_syscall_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ */

#endif /* !_RTAI_SYSCALL_H */
