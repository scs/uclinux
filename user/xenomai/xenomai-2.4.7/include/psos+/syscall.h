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

#ifndef _PSOS_SYSCALL_H
#define _PSOS_SYSCALL_H

#ifndef __XENO_SIM__
#include <asm/xenomai/syscall.h>
#endif /* __XENO_SIM__ */

#define __psos_t_create     0
#define __psos_t_start      1
#define __psos_t_delete     2
#define __psos_t_suspend    3
#define __psos_t_resume     4
#define __psos_t_ident      5
#define __psos_t_mode       6
#define __psos_t_setpri     7
#define __psos_ev_send      8
#define __psos_ev_receive   9
#define __psos_q_create     10
#define __psos_q_delete     11
#define __psos_q_ident      12
#define __psos_q_receive    13
#define __psos_q_send       14
#define __psos_q_urgent     15
#define __psos_q_broadcast  16
#define __psos_q_vcreate    17
#define __psos_q_vdelete    18
#define __psos_q_vident     19
#define __psos_q_vreceive   20
#define __psos_q_vsend      21
#define __psos_q_vurgent    22
#define __psos_q_vbroadcast 23
#define __psos_sm_create    24
#define __psos_sm_delete    25
#define __psos_sm_ident     26
#define __psos_sm_p         27
#define __psos_sm_v         28
#define __psos_rn_create    29
#define __psos_rn_delete    30
#define __psos_rn_ident     31
#define __psos_rn_getseg    32
#define __psos_rn_retseg    33
#define __psos_rn_bind      34
#define __psos_tm_wkafter   35
#define __psos_tm_cancel    36
#define __psos_tm_evafter   37
#define __psos_tm_get       38
#define __psos_tm_set       39
#define __psos_tm_evwhen    40
#define __psos_tm_wkwhen    41
#define __psos_tm_evevery   42
/* Xenomai extension: get monotonic time (ns) */
#define __psos_tm_getm      43
/* Xenomai extension: send a Linux signal after a specified time */
#define __psos_tm_signal    44
#define __psos_as_send      45
/* Xenomai extension: get raw count of jiffies */
#define __psos_tm_getc      46

#ifdef __KERNEL__

#ifdef __cplusplus
extern "C" {
#endif

int psos_syscall_init(void);

void psos_syscall_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ */

#endif /* _PSOS_SYSCALL_H */
