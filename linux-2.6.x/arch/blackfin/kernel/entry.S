/*
 *  linux/arch/bfinnommu/kernel/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2004 LG Soft India.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file README.legal in the main directory of this archive
 * for more details.
 *
 * Linux/bfin support by LG Soft India.
 */

#include <linux/config.h>
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/asm-offsets.h>
#include <asm/entry.h>

.text

ENTRY(reschedule)
	r7 = sp;   
	r4.l = 0xe000;
	r4.h = 0xffff;
	
	r7 = r7 & r4;  /*thread_info*/
	p2 = r7; 
	p2 = [p2];
	[p2 + (TASK_THREAD + THREAD_ESP0)] = sp;

	[--sp] = rets;
	jump schedule; 

ENTRY(ret_from_fork)
	SP += -12;
	call schedule_tail; 
	SP += 12;
	r0 = [sp + PT_IPEND];
	cc = bittst(r0,15);
	if cc jump in_kernel;
	RESTORE_CONTEXT
	rti; 
in_kernel:
	/* do a 'fake' RTI by jumping to [RETI] */
        /* to avoid clearing supervisor mode in child */
	RESTORE_ALL_SYS
	p0 = reti;
	jump (p0);

ENTRY(sys_fork)
	r0 = -EINVAL;
	rts;

ENTRY(sys_vfork)
	r0 = sp;
	r0 += 12;
	[--sp] = rets;
	SP += -12;
	call bfin_vfork; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_clone)
	r0 = sp;
	r0 += 12;
	[--sp] = rets;
	SP += -12;
	call bfin_clone; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_sigsuspend)
	r0 = sp;
	r0 +=12;
	[--sp] = rets;
	SP += -12;
	call do_sigsuspend; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_rt_sigsuspend)
	r0 = sp;
	r0 +=12;
	[--sp] = rets;
	SP += -12;
	call do_rt_sigsuspend; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_sigreturn)
	r0 = sp;
	r0 +=12;
	[--sp] = rets;
	SP += -12;
	call do_sigreturn; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_rt_sigreturn)
	r0 = sp;
	r0 +=12;
	[--sp] = rets;
	SP += -12;
	call do_rt_sigreturn; 
	SP += 12;
	rets = [sp++];
	rts;
