/*
 * File:	  arch/blackfin/kernel/entry.S
 * Based on:
 * Author:
 *
 * Created:
 * Description:
 * Rev:	          $Id$
 *
 * Modified:
 *               Copyright 2004-2005 Analog Devices Inc.
 *
 * Bugs:	  Enter bugs at http:	//blackfin.uclinux.org/
 *
 * This program is free software ;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation	;  either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY ;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program ;  see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/asm-offsets.h>

.text

ENTRY(reschedule)
	r7 = sp;
	r4.l = 0xe000;
	r4.h = 0xffff;
	r7 = r7 & r4;  /*thread_info*/
	p2 = r7;
	p2 = [p2];
	[p2 + (TASK_THREAD + THREAD_KSP)] = sp;
	call _schedule;

ENTRY(_ret_from_fork)
	SP += -12;
	call _schedule_tail;
	SP += 12;
	r0 = [sp + PT_IPEND];
	cc = bittst(r0,1);
	if cc jump in_kernel;
	RESTORE_CONTEXT
	rti;
in_kernel:
	bitclr(r0,1);
	[sp + PT_IPEND] = r0;
	/* do a 'fake' RTI by jumping to [RETI] */
        /* to avoid clearing supervisor mode in child */
	RESTORE_ALL_SYS
	p0 = reti;
	jump (p0);

ENTRY(_sys_fork)
	r0 = -EINVAL;
	rts;

ENTRY(_sys_vfork)
	r0 = sp;
	r0 += 20;
	[--sp] = rets;
	SP += -12;
	call _bfin_vfork;
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(_sys_clone)
	r0 = sp;
	r0 += 20;
	[--sp] = rets;
	SP += -12;
	call _bfin_clone;
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(_sys_sigsuspend)
	r0 = sp;
	r0 += 20;
	[--sp] = rets;
	SP += -12;
	call _do_sigsuspend;
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(_sys_rt_sigsuspend)
	r0 = sp;
	r0 += 20;
	[--sp] = rets;
	SP += -12;
	call _do_rt_sigsuspen;
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(_sys_sigreturn)
	r0 = sp;
	r0 += 20;
	[--sp] = rets;
	SP += -12;
	call _do_sigreturn;
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(_sys_rt_sigreturn)
	r0 = sp;
	r0 += 20;
	[--sp] = rets;
	SP += -12;
	call _do_rt_sigreturn;
	SP += 12;
	rets = [sp++];
	rts;
