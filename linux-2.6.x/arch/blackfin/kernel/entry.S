/*
 *  linux/arch/bfinnommu/mach-bf533/entry.S
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
#include <linux/sys.h>
#include <linux/linkage.h>
#include <asm/thread_info.h>
#include <asm/errno.h>
#include <asm/setup.h>
#include <asm/segment.h>
#include <asm/asm-offsets.h>
#include <asm/entry.h>

.text

.globl trap
.globl reschedule
.globl sys_fork
.globl sys_clone
.globl sys_vfork
.globl sys_sigreturn
.globl sys_rt_sigreturn
.globl sys_sigsuspend
.globl sys_rt_sigsuspend


ENTRY(reschedule)
	r7 = sp;   
	r4.l = 0xe000;
	r4.h = 0xffff;
	
	r7 = r7 & r4;  /*thread_info*/
	p2 = r7; 
	p2 = [p2];
	[p2 + (TASK_THREAD + THREAD_ESP0)] = sp;

	[--sp] = rets;
	call schedule; 
	rets = [sp++];
	rts;

ENTRY(ret_from_fork)
	/* Don't bother with trace yet - akale */
	r0 = r1;
	SP += -12;
	call schedule_tail; 
	SP += 12;
	/* Note: void schedule_tail(struct task_struct *prev)	*/
	
	r0 = [sp + PT_IPEND];
	cc = bittst(r0, 15);
	if cc jump in_kernel;
	RESTORE_ALL
	rti; 
in_kernel:
	/* do a 'fake' RTI by jumping to [RETI] */
        /* to avoid clearing supervisor mode in child */
	RESTORE_ALL
	p0 = reti;
	jump (p0);

ENTRY(sys_fork)
/*	call	bfin_fork;  */
	link 0x0;
	r0 = -EINVAL;
	unlink 0x0;
	rts;

ENTRY(sys_vfork)
	r0 = sp;
	r0 += 12;
	[--sp] = rets;
	SP += -12;
	call	bfin_vfork; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_clone)
	r0 = sp;
	r0 += 12;
	[--sp] = rets;
	SP += -12;
	call	bfin_clone; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_sigsuspend)
	r0 = sp;
	r0 +=12;
	[--sp] = rets;
	SP += -12;
	call	do_sigsuspend; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_rt_sigsuspend)
	r0 = sp;
	r0 +=12;
	[--sp] = rets;
	SP += -12;
	call	do_rt_sigsuspend; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_sigreturn)
	r0 = sp;
	r0 +=12;
	[--sp] = rets;
	SP += -12;
	call	do_sigreturn; 
	SP += 12;
	rets = [sp++];
	rts;

ENTRY(sys_rt_sigreturn)
	r0 = sp;
	r0 +=12;
	[--sp] = rets;
	SP += -12;
	call	do_rt_sigreturn; 
	SP += 12;
	rets = [sp++];
	rts;

