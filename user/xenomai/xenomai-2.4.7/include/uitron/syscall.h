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

#ifndef _UITRON_SYSCALL_H
#define _UITRON_SYSCALL_H

#ifndef __XENO_SIM__
#include <asm/xenomai/syscall.h>
#endif /* __XENO_SIM__ */

#define __uitron_cre_tsk     0
#define __uitron_del_tsk     1
#define __uitron_sta_tsk     2
#define __uitron_ext_tsk     3
#define __uitron_exd_tsk     4
#define __uitron_ter_tsk     5
#define __uitron_dis_dsp     6
#define __uitron_ena_dsp     7
#define __uitron_chg_pri     8
#define __uitron_rot_rdq     9
#define __uitron_rel_wai     10
#define __uitron_get_tid     11
#define __uitron_ref_tsk     12
#define __uitron_sus_tsk     13
#define __uitron_rsm_tsk     14
#define __uitron_frsm_tsk    15
#define __uitron_slp_tsk     16
#define __uitron_tslp_tsk    17
#define __uitron_wup_tsk     18
#define __uitron_can_wup     19
#define __uitron_cre_sem     20
#define __uitron_del_sem     21
#define __uitron_sig_sem     22
#define __uitron_wai_sem     23
#define __uitron_preq_sem    24
#define __uitron_twai_sem    25
#define __uitron_ref_sem     26
#define __uitron_cre_flg     27
#define __uitron_del_flg     28
#define __uitron_set_flg     29
#define __uitron_clr_flg     30
#define __uitron_wai_flg     31
#define __uitron_pol_flg     32
#define __uitron_twai_flg    33
#define __uitron_ref_flg     34
#define __uitron_cre_mbx     35
#define __uitron_del_mbx     36
#define __uitron_snd_msg     37
#define __uitron_rcv_msg     38
#define __uitron_prcv_msg    39
#define __uitron_trcv_msg    40
#define __uitron_ref_mbx     41

#ifdef __KERNEL__

#ifdef __cplusplus
extern "C" {
#endif

int ui_syscall_init(void);

void ui_syscall_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ */

#endif /* _UITRON_SYSCALL_H */
