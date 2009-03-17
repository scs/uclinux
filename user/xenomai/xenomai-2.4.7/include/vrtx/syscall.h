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

#ifndef _XENO_VRTX_SYSCALL_H
#define _XENO_VRTX_SYSCALL_H

#ifndef __XENO_SIM__
#include <asm/xenomai/syscall.h>
#endif /* __XENO_SIM__ */

#define __vrtx_tecreate    0
#define __vrtx_tdelete     1
#define __vrtx_tpriority   2
#define __vrtx_tresume     3
#define __vrtx_tsuspend    4
#define __vrtx_tslice      5
#define __vrtx_tinquiry    6
#define __vrtx_lock        7
#define __vrtx_unlock      8
#define __vrtx_delay       9
#define __vrtx_adelay      10
#define __vrtx_stime       11
#define __vrtx_gtime       12
#define __vrtx_sclock      13
#define __vrtx_gclock      14
#define __vrtx_mcreate     15
#define __vrtx_mdelete     16
#define __vrtx_mpost       17
#define __vrtx_maccept     18
#define __vrtx_mpend       19
#define __vrtx_minquiry    20
#define __vrtx_qecreate    21
#define __vrtx_qdelete     22
#define __vrtx_qpost       23
#define __vrtx_qbrdcst     24
#define __vrtx_qjam        25
#define __vrtx_qpend       26
#define __vrtx_qaccept     27
#define __vrtx_qinquiry    28
#define __vrtx_post        29
#define __vrtx_accept      30
#define __vrtx_pend        31
#define __vrtx_fcreate     32
#define __vrtx_fdelete     33
#define __vrtx_fpost       34
#define __vrtx_fpend       35
#define __vrtx_fclear      36
#define __vrtx_finquiry    37
#define __vrtx_screate     38
#define __vrtx_sdelete     39
#define __vrtx_spost       40
#define __vrtx_spend       41
#define __vrtx_saccept     42
#define __vrtx_sinquiry    43
#define __vrtx_hcreate     44
#define __vrtx_hbind       45	/* Internal call */
#define __vrtx_hdelete     46
#define __vrtx_halloc      47
#define __vrtx_hfree       48
#define __vrtx_hinquiry    49
#define __vrtx_pcreate     50
#define __vrtx_pbind       51	/* Internal call */
#define __vrtx_pdelete     52
#define __vrtx_gblock      53
#define __vrtx_rblock      54
#define __vrtx_pinquiry    55

struct vrtx_arg_bulk {

    u_long a1;
    u_long a2;
    u_long a3;
};

#ifdef __KERNEL__

#include <linux/time.h>

#ifdef __cplusplus
extern "C" {
#endif

int vrtxsys_init(void);

void vrtxsys_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ */

#endif /* _XENO_VRTX_SYSCALL_H */
