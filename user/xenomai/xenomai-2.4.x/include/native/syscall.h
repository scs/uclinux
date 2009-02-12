/*
 * Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _NATIVE_SYSCALL_H
#define _NATIVE_SYSCALL_H

#ifndef __XENO_SIM__
#include <asm/xenomai/syscall.h>
#endif /* __XENO_SIM__ */

#define __native_task_create        0
#define __native_task_bind          1
#define __native_task_start         2
#define __native_task_suspend       3
#define __native_task_resume        4
#define __native_task_delete        5
#define __native_task_yield         6
#define __native_task_set_periodic  7
#define __native_task_wait_period   8
#define __native_task_set_priority  9
#define __native_task_sleep         10
#define __native_task_sleep_until   11
#define __native_task_unblock       12
#define __native_task_inquire       13
#define __native_task_notify        14
#define __native_task_set_mode      15
#define __native_task_self          16
#define __native_task_slice         17
#define __native_task_send          18
#define __native_task_receive       19
#define __native_task_reply         20
#define __native_timer_set_mode     21
#define __native_unimp_22           22
#define __native_timer_read         23
#define __native_timer_tsc          24
#define __native_timer_ns2ticks     25
#define __native_timer_ticks2ns     26
#define __native_timer_inquire      27
#define __native_timer_spin         28
#define __native_sem_create         29
#define __native_sem_bind           30
#define __native_sem_delete         31
#define __native_sem_p              32
#define __native_sem_v              33
#define __native_sem_broadcast      34
#define __native_sem_inquire        35
#define __native_event_create       36
#define __native_event_bind         37
#define __native_event_delete       38
#define __native_event_wait         39
#define __native_event_signal       40
#define __native_event_clear        41
#define __native_event_inquire      42
#define __native_mutex_create       43
#define __native_mutex_bind         44
#define __native_mutex_delete       45
#define __native_mutex_acquire      46
#define __native_mutex_release      47
#define __native_mutex_inquire      48
#define __native_cond_create        49
#define __native_cond_bind          50
#define __native_cond_delete        51
#define __native_cond_wait          52
#define __native_cond_signal        53
#define __native_cond_broadcast     54
#define __native_cond_inquire       55
#define __native_queue_create       56
#define __native_queue_bind         57
#define __native_queue_delete       58
#define __native_queue_alloc        59
#define __native_queue_free         60
#define __native_queue_send         61
#define __native_queue_receive      62
#define __native_queue_inquire      63
#define __native_heap_create        64
#define __native_heap_bind          65
#define __native_heap_delete        66
#define __native_heap_alloc         67
#define __native_heap_free          68
#define __native_heap_inquire       69
#define __native_alarm_create       70
#define __native_alarm_delete       71
#define __native_alarm_start        72
#define __native_alarm_stop         73
#define __native_alarm_wait         74
#define __native_alarm_inquire      75
#define __native_intr_create        76
#define __native_intr_bind          77
#define __native_intr_delete        78
#define __native_intr_wait          79
#define __native_intr_enable        80
#define __native_intr_disable       81
#define __native_intr_inquire       82
#define __native_pipe_create        83
#define __native_pipe_bind          84
#define __native_pipe_delete        85
#define __native_pipe_read          86
#define __native_pipe_write         87
#define __native_pipe_stream        88
#define __native_unimp_89           89
#define __native_io_get_region      90
#define __native_io_put_region      91
#define __native_timer_ns2tsc       92
#define __native_timer_tsc2ns       93
#define __native_queue_write        94
#define __native_queue_read         95

struct rt_arg_bulk {

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

#ifdef CONFIG_XENO_OPT_PERVASIVE

int __native_syscall_init(void);

void __native_syscall_cleanup(void);

#else /* !CONFIG_XENO_OPT_PERVASIVE */

#define __native_syscall_init()	({ 0; })
#define __native_syscall_cleanup()	do { } while(0)

#endif /* !CONFIG_XENO_OPT_PERVASIVE */

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ */

#endif /* _NATIVE_SYSCALL_H */
