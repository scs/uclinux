 /*
 * File:        arch/blackfin/mach-common/entry.S
 * Based on:
 * Author:      Linus Torvalds
 *              COPYRIGHT 2005 Analog Devices
 * Created:     ?
 * Description: contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
 * Rev:
 *
 * Modified:     LG Soft India
 *
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING.
 * If not, write to the Free Software Foundation,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * 25-Dec-2004 - LG Soft India
 * 	1. Fix in return_from_int, to make sure any pending
 *	system call in ILAT for this process to get
 *	executed, otherwise in case context switch happens,
 *	system call of first process (i.e in ILAT) will be
 *	carried forward to the switched process.
 *	2. Removed Constant references for the following
 *		a.  IPEND
 *		b.  EXCAUSE mask
 *		c.  PAGE Mask
 */

/*
 * NOTE: This code handles signal-recognition, which happens every time
 * after a timer-interrupt and after each system call.
 */


#include <linux/linkage.h>
#include <asm/blackfin.h>
#include <asm/unistd.h>
#include <asm/errno.h>
#include <asm/thread_info.h>  /* TIF_NEED_RESCHED */
#include <asm/asm-offsets.h>

.data
ALIGN
extable:
	.long ex_syscall;	/* 0 */
	.long ex_soft_bp
	.long ex_trap_c
	.long ex_trap_c
	.long ex_spinlock
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c		/* 8 */
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_single_step	/* 16 - STEP */
	.long ex_trap_c		/* 17 - OVFLOW */
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c		/* 24 */
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c		/* 32 */
	.long ex_trap_c		/* 33 - UNDEF_I */
	.long ex_trap_c		/* 34 - ILGAL_I */
	.long ex_dcplb		/* 35 - CPLB_VL */
	.long ex_trap_c		/* 36 - MISALI_D */
	.long ex_trap_c		/* 37 - UNCOV */
	.long ex_dcplb		/* 38 - CPLB_M */
	.long ex_trap_c		/* 39 - CPLB_MHIT */
	.long ex_trap_c		/* 40 - WATCH */
	.long ex_trap_c		/* 41 - ISTRU_VL */
	.long ex_trap_c		/* 42 - MISALI_I */
	.long ex_icplb		/* 43 - CPLB_I_VL */
	.long ex_icplb		/* 44 - CPLB_I_M */
	.long ex_trap_c		/* 45 - CPLB_I_MHIT */
	.long ex_trap_c		/* 46 - ILL_RES */
	.long ex_trap_c
	.long ex_trap_c		/* 48 */
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c		/* 56 */
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
.text

/* Slightly simplified and streamlined entry point for CPLB misses.
 * This one does not lower the level to IRQ5, and thus can be used to
 * patch up CPLB misses on the kernel stack.
 */
ENTRY(ex_dcplb)
	/*
	 * Work around an anomaly: if we see a new DCPLB fault, return
	 * without doing anything.  Then, if we get the same fault again,
	 * handle it.
 	 */
	p5.l = _last_cplb_fault_retx;
	p5.h = _last_cplb_fault_retx;
	r7 = [p5];
	r6 = retx;
	[p5] = r6;
	cc = r6 == r7;
	if !cc jump exception_do_nothing;
	/* fall through */

ENTRY(ex_icplb)
	(R7:6,P5:4) = [sp++];
	ASTAT = [sp++];
	SAVE_ALL_SYS
	call __cplb_hdr;
	RESTORE_ALL_SYS
	SP = RETN;
	rtx;

ENTRY(ex_spinlock)
	/* Transform this into a syscall - twiddle the syscall vector.  */
	p5.l = lo(EVT15);
	p5.h = hi(EVT15);
	r7.l = spinlock_bh;
	r7.h = spinlock_bh;
	[p5] = r7;
	csync;
	/* Fall through.  */

ENTRY(ex_syscall)
	(R7:6,P5:4) = [sp++];
	ASTAT = [sp++];
	raise 15;		/* invoked by TRAP #0, for sys call */
	sp = retn;
	rtx

ENTRY(spinlock_bh)
	SAVE_ALL_SYS
	/* To end up here, vector 15 was changed - so we have to change it
	 * back.
	 */
	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = _evt_system_call;
	p1.h = _evt_system_call;
	[p0] = p1;
	csync;
	r0 = [sp + PT_R0];
	sp += -12;
	call _sys_bfin_spinlock;
	sp += 12;
	[SP + PT_R0] = R0;
	RESTORE_ALL_SYS
	rti;

ENTRY(ex_soft_bp)
	r7 = retx;
	r7 += -2;
	retx = r7;
	jump.s ex_trap_c;

ENTRY(ex_single_step)
	r7 = syscfg;
	bitclr (r7, 0);
	syscfg = R7;
	/* 1. Check if in interrupt handler.
	 * 2. If not, call ex_trap_c.
	 */
	p5.l = lo(IPEND);
	p5.h = hi(IPEND);
	csync;
	r7 = [p5];
	r6 = 0x8 (Z);
	cc = r7 == r6;
	if !cc jump exception_do_nothing;
	r7 = retx;
	r6 = reti;
	cc = r7 == r6;
	if !cc jump ex_trap_c;
exception_do_nothing:
	(R7:6,P5:4) = [sp++];
	ASTAT = [sp++];
	sp = retn;
	rtx;

ENTRY(ex_trap_c)
	/* Call C code (trap_c) to handle the exception, which most
	 * likely involves sending a signal to the current process.
	 * To avoid double faults, lower our priority to IRQ5 first.
	 */
	P5.h = exception_to_level5;
	P5.l = exception_to_level5;
	p4.l = lo(EVT5);
	p4.h = hi(EVT5);
	[p4] = p5;
	csync;

	/* Disable all interrupts, but make sure level 5 is enabled so
	   we can switch to that level.  Save the old mask.  */
	cli r6;
	p4.l = excpt_saved_imask; 
	p4.h = excpt_saved_imask;
	[p4] = r6;
	r6 = 0x3f;
	sti r6;

	(R7:6,P5:4) = [sp++];
	ASTAT = [sp++];
	SP = RETN;
	raise 5;
	rtx;

ENTRY(exception_to_level5)
	SAVE_ALL_SYS

	/* Restore interrupt mask.  We haven't pushed RETI, so this
	   doesn't enable interrupts until we return from this handler.  */
	p4.l = excpt_saved_imask; 
	p4.h = excpt_saved_imask;
	r6 = [p4];
	sti r6;

	/* Restore the hardware error vector.  */
	P5.h = _evt_ivhw;
	P5.l = _evt_ivhw;
	p4.l = lo(EVT5);
	p4.h = hi(EVT5);
	[p4] = p5;
	csync;

        p2.l = lo(IPEND);
        p2.h = hi(IPEND);
	csync;
        r0 = [p2];              /* Read current IPEND */
        [sp + PT_IPEND] = r0;   /* Store IPEND */

	r0 = sp; 	/* stack frame pt_regs pointer argument ==> r0 */
	SP += -12;
	call _trap_c;
	SP += 12;
	call ret_from_exception;
	RESTORE_ALL_SYS
	rti;

ENTRY(_trap) /* Exception: 4th entry into system event table(supervisor mode)*/
	/* Since the kernel stack can be anywhere, it's not guaranteed to be
	 * covered by a CPLB.  Switch to an exception stack; use RETN as a
	 * scratch register (for want of a better option).
	 */
	retn = sp;
	sp.l = exception_stack_top;
	sp.h = exception_stack_top;
	/* Try to deal with syscalls quickly.  */
	[--sp] = ASTAT;
	[--sp] = (R7:6, P5:4);
	r7 = SEQSTAT;		/* reason code is in bit 5:0 */
	r6.l = lo(SEQSTAT_EXCAUSE);
	r6.h = hi(SEQSTAT_EXCAUSE);
	r7 = r7 & r6;
	p5.h = extable;
	p5.l = extable;
	p4 = r7;
	p5 = p5 + (p4 << 2);
	p4 = [p5];
	jump (p4);

badsys:
	r7 = -ENOSYS; 		/* signextending enough */
	[sp + PT_R0] = r7;	/* return value from system call */
	rti;

ENTRY(_execve)
	link SIZEOF_PTREGS;
	p0 = sp;
	r3 = SIZEOF_PTREGS / 4;
	r4 = 0(x);
0:
	[p0++] = r4;
	r3 += -1;
	cc = r3 == 0;
	if !cc jump 0b (bp);

	p0 = sp;
	sp += -16;
	[sp + 12] = p0;
	call _do_execve;
	SP += 16;
	cc = r0 == 0;
	if ! cc jump 1f;
	/* Success.  Copy our temporary pt_regs to the top of the kernel
	 * stack and do a normal exception return.
	 */
	r1 = sp;
	r0 = (-KERNEL_STACK_SIZE) (x);
	r1 = r1 & r0;
	p2 = r1;
	p3 = [p2];
	r0 = KERNEL_STACK_SIZE - 4 (z);
	p1 = r0;
	p1 = p1 + p2;

	p0 = fp;
	r4 = [p0--];
	r3 = SIZEOF_PTREGS / 4;
0:
	r4 = [p0--];
	[p1--] = r4;
	r3 += -1;
	cc = r3 == 0;
	if ! cc jump 0b (bp);

	r0 = (KERNEL_STACK_SIZE - SIZEOF_PTREGS) (z);
	p1 = r0;
	p1 = p1 + p2;
	sp = p1;
	r0 = syscfg;
	[SP + PT_SYSCFG] = r0;
	[p3 + (TASK_THREAD + THREAD_KSP)] = sp;

	RESTORE_CONTEXT;
	rti;
1:
	unlink;
	rts;

ENTRY(system_call)
	/* Store IPEND */
        p2.l = lo(IPEND);
        p2.h = hi(IPEND);
	csync;
	r0 = [p2];
	[sp + PT_IPEND] = r0;

	/* Store RETS for now */
	r0 = rets;
	[sp + PT_RESERVED] = r0;
	/* Set the stack for the current process */
	r7 = sp;
	r6.l = lo(ALIGN_PAGE_MASK);
	r6.h = hi(ALIGN_PAGE_MASK);
	r7 = r7 & r6;  		/*thread_info*/
	p2 = r7;
	p2 = [p2];

	[p2+(TASK_THREAD+THREAD_KSP)] = sp;

	/* Check the System Call */
	r7 = __NR_syscall;
	/*System call number is passed in P0 */
	r5 = p0;
	cc = r5 < r7;
	if ! cc jump badsys;

	/* Execute the appropriate system call */

	p4 = r5;
	p5.l = sys_call_table;
	p5.h = sys_call_table;
	p5 = p5 + (p4 << 2);
	r0 = [sp + PT_R0];
	r1 = [sp + PT_R1];
	r2 = [sp + PT_R2];
	p5 = [p5];

   /* are we tracing syscalls?*/
        r7 = sp;
        r6.l = lo(ALIGN_PAGE_MASK);
        r6.h = hi(ALIGN_PAGE_MASK);
        r7 = r7 & r6;
        p2 = r7;
        r7 = [p2+TI_FLAGS];
        CC = BITTST(r7,TIF_SYSCALL_TRACE);
        if CC JUMP sys_trace;

	[--sp] = r4;
	[--sp] = r3;
	SP += -12;
	call (p5);
	SP += 20;
	[sp + PT_R0] = r0;

resume_userspace:
	r7 = sp;
	r4.l = lo(ALIGN_PAGE_MASK);
	r4.h = hi(ALIGN_PAGE_MASK);
	r7 = r7 & r4;		/*thread_info->flags*/
	p5 = r7;
resume_userspace_1:
	/* Disable interrupts.  */
	[--sp] = reti;
	reti = [sp++];

	r7 = [p5 + TI_FLAGS];
	r4 = _TIF_WORK_MASK;
	r7 =  r7 & r4;

syscall_resched:
	cc = BITTST(r7, TIF_NEED_RESCHED);
	if !cc jump syscall_sigpending;

	/* Reenable interrupts.  */
	[--sp] = reti;
	r0 = [sp++];

	SP += -12;
	call _schedule;
	SP += 12;

	jump resume_userspace_1;

syscall_sigpending:
	cc = BITTST(r7, TIF_SIGPENDING);
	if !cc jump syscall_really_exit;

	/* Reenable interrupts.  */
	[--sp] = reti;
	r0 = [sp++];

	r0 = 0;
	r1 = sp;
	SP += -12;
	call _do_signal;
	SP += 12;

syscall_really_exit:
	r5 = [sp + PT_RESERVED];
	rets = r5;
	rts;

sys_trace:
        [--sp] = r3;
        [--sp] = r2;
        [--sp] = r1;
        [--sp] = r0;
        [--sp] = p5;
        [--sp] = p2;
        [--sp] = p1;
        [--sp] = p0;
        r1 = 0;
        call _syscall_trace;
        p0 = [sp++];
        p1 = [sp++];
        p2 = [sp++];
        p5 = [sp++];
        r0 = [sp++];
        r1 = [sp++];
        r2 = [sp++];
        r3 = [sp++];


        [--sp] = r4;
        [--sp] = r3;
         SP += -12;
        call (p5);
        SP += 20;
        [sp + PT_R0] = r0;

        [--sp] = r3;
        [--sp] = r2;
        [--sp] = r1;
        [--sp] = r0;
        [--sp] = p5;
        [--sp] = p2;
        [--sp] = p1;
        [--sp] = p0;
        r1 = 1;
        call _syscall_trace;
        p0 = [sp++];
        p1 = [sp++];
        p2 = [sp++];
        p5 = [sp++];
        r0 = [sp++];
        r1 = [sp++];
        r2 = [sp++];
        r3 = [sp++];

        jump resume_userspace;

ENTRY(resume)
	/*
	 * Beware - when entering resume, prev (the current task) is
	 * in r0, next (the new task) is in r1.
	 */
	p0 = r0;
	p1 = r1;
	[--sp] = rets;
	[--sp] = fp;

	/* save usp */
	p2 = usp;
	[p0+(TASK_THREAD+THREAD_USP)] = p2;

	/* save current kernel stack pointer */
	[p0+(TASK_THREAD+THREAD_KSP)] = sp;

	/* save program counter */
	r1.l = new_old_task;
	r1.h = new_old_task;
	[p0+(TASK_THREAD+THREAD_PC)] = r1;

	/* restore the kernel stack pointer */
	sp = [p1+(TASK_THREAD+THREAD_KSP)];

	/* restore user stack pointer */
	p0 = [p1+(TASK_THREAD+THREAD_USP)];
	usp = p0;

	/* restore pc */
	p0 = [p1+(TASK_THREAD+THREAD_PC)];
	jump (p0);

	/*
	 * Following code actually lands up in a new (old) task.
	 */

new_old_task:
	fp = [sp++];
	rets = [sp++];

	/*
	 * When we come out of resume, r0 carries "old" task, becuase we are
	 * in "new" task.
	 */
	rts;

ENTRY(ret_from_exception)
        p2.l = lo(IPEND);
        p2.h = hi(IPEND);

	csync;
	r0 = [p2];
	[sp + PT_IPEND] = r0;

1:
	r1 = 0x37(Z);
	r2 = ~r1;
	r2.h = 0;
	r0 = r2 & r0;
        cc = r0 == 0;
        if !cc jump 4f;	/* if not return to user mode, get out */

	/* Make sure any pending system call or deferred exception
	 * return in ILAT for this process to get executed, otherwise
	 * in case context switch happens, system call of
	 * first process (i.e in ILAT) will be carried
	 * forward to the switched process
	 */

        p2.l = lo(ILAT);
        p2.h = hi(ILAT);
        r0 = [p2];
	r1 = (EVT_IVG14 | EVT_IVG15) (z);
        r0 = r0 & r1;
        cc = r0 == 0;
        if !cc jump 5f;

	/* Set the stack for the current process */
	r7 = sp;
	r4.l = lo(ALIGN_PAGE_MASK);
	r4.h = hi(ALIGN_PAGE_MASK);
	r7 = r7 & r4;		/*thread_info->flags*/
	p5 = r7;
	r7 = [p5 + TI_FLAGS];
	r4 = _TIF_WORK_MASK;
	r7 =  r7 & r4;
	cc = r7 == 0;
	if cc jump 4f;

	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = _schedule_and_signal;
	p1.h = _schedule_and_signal;
	[p0] = p1;
	csync;
	raise 15;		/* raise evt14 to do signal or reschedule */
4:
        r0 = syscfg;
        bitclr(r0, 0);
        syscfg = r0;
5:
	rts;

ENTRY(return_from_int)
	/* If someone else already raised IRQ 15, do nothing.  */
	csync;
        p2.l = lo(ILAT);
        p2.h = hi(ILAT);
        r0 = [p2];
	cc = bittst (r0, EVT_IVG15_P);
        if cc jump 2f;

	/* if not return to user mode, get out */
        p2.l = lo(IPEND);
        p2.h = hi(IPEND);
        r0 = [p2];
	r1 = 0x17(Z);
	r2 = ~r1;
	r2.h = 0;
	r0 = r2 & r0;
        r1 = 1;
        r1 = r0 - r1;
        r2 = r0 & r1;
        cc = r2 == 0;
        if !cc jump 2f;

	/* Lower the interrupt level to 15.  */
	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = schedule_and_signal_from_int;
	p1.h = schedule_and_signal_from_int;
	[p0] = p1;
	csync;
	r0 = 0x801f (z);
	STI r0;
	raise 15;	/* raise evt15 to do signal or reschedule */
	rti;
2:
	rts;

ENTRY(_lower_to_irq14)
	r0 = 0x401f;
	sti r0;
	raise 14;
	rti;
ENTRY(_evt14_softirq)
#ifdef CONFIG_DEBUG_HWERR
	r0 = 0x3f;
	sti r0;
#else
	cli r0;
#endif
	[--sp] = RETI;
	SP += 4;
	rts;

schedule_and_signal_from_int:
	/* To end up here, vector 15 was changed - so we have to change it
	 * back.
	 */
	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = _evt_system_call;
	p1.h = _evt_system_call;
	[p0] = p1;
	csync;
	p1 = rets;
	[sp + PT_RESERVED] = p1;

	p0.l = _irq_flags;
	p0.h = _irq_flags;
	r0 = [p0];
	sti r0;

	jump.s resume_userspace;

_schedule_and_signal:
	SAVE_CONTEXT_SYSCALL
	/* To end up here, vector 15 was changed - so we have to change it
	 * back.
	 */
	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = _evt_system_call;
	p1.h = _evt_system_call;
	[p0] = p1;
	csync;
	p0.l = lo(1f);
	p0.h = lo(1f);
	[sp + PT_RESERVED] = P0;
	call resume_userspace;
1:
	RESTORE_CONTEXT
	rti;

.data
ALIGN
ENTRY(sys_call_table)
	.long _sys_ni_syscall	/* 0  -  old "setup()" system call*/
	.long _sys_exit
	.long _sys_fork
	.long _sys_read
	.long _sys_write
	.long _sys_open		/* 5 */
	.long _sys_close
	.long _sys_waitpid
	.long _sys_creat
	.long _sys_link
	.long _sys_unlink	/* 10 */
	.long _sys_execve
	.long _sys_chdir
	.long _sys_time
	.long _sys_mknod
	.long _sys_chmod		/* 15 */
	.long _sys_chown16
	.long _sys_ni_syscall	/* old break syscall holder */
	.long _sys_stat
	.long _sys_lseek
	.long _sys_getpid	/* 20 */
	.long _sys_mount
	.long _sys_oldumount
	.long _sys_setuid16
	.long _sys_getuid16
	.long _sys_stime		/* 25 */
	.long _sys_ptrace
	.long _sys_alarm
	.long _sys_fstat
	.long _sys_pause
	.long _sys_utime		/* 30 */
	.long _sys_ni_syscall	/* old stty syscall holder */
	.long _sys_ni_syscall	/* old gtty syscall holder */
	.long _sys_access
	.long _sys_nice
	.long _sys_ni_syscall	/* 35 */ /* old ftime syscall holder */
	.long _sys_sync
	.long _sys_kill
	.long _sys_rename
	.long _sys_mkdir
	.long _sys_rmdir		/* 40 */
	.long _sys_dup
	.long _sys_pipe
	.long _sys_times
	.long _sys_ni_syscall	/* old prof syscall holder */
	.long _sys_brk		/* 45 */
	.long _sys_setgid16
	.long _sys_getgid16
	.long _sys_signal
	.long _sys_geteuid16
	.long _sys_getegid16	/* 50 */
	.long _sys_acct
	.long _sys_umount	/* recycled never used phys() */
	.long _sys_ni_syscall	/* old lock syscall holder */
	.long _sys_ioctl
	.long _sys_fcntl		/* 55 */
	.long _sys_ni_syscall	/* old mpx syscall holder */
	.long _sys_setpgid
	.long _sys_ni_syscall	/* old ulimit syscall holder */
	.long _sys_ni_syscall
	.long _sys_umask		/* 60 */
	.long _sys_chroot
	.long _sys_ustat
	.long _sys_dup2
	.long _sys_getppid
	.long _sys_getpgrp	/* 65 */
	.long _sys_setsid
	.long _sys_sigaction
	.long _sys_sgetmask
	.long _sys_ssetmask
	.long _sys_setreuid16	/* 70 */
	.long _sys_setregid16
	.long _sys_sigsuspend
	.long _sys_sigpending
	.long _sys_sethostname
	.long _sys_setrlimit	/* 75 */
	.long _sys_old_getrlimit
	.long _sys_getrusage
	.long _sys_gettimeofday
	.long _sys_settimeofday
	.long _sys_getgroups16	/* 80 */
	.long _sys_setgroups16
	.long _old_select
	.long _sys_symlink
	.long _sys_lstat
	.long _sys_readlink	/* 85 */
	.long _sys_uselib
	.long _sys_ni_syscall	/* sys_swapon */
	.long _sys_reboot
	.long _old_readdir
	.long _old_mmap		/* 90 */
	.long _sys_munmap
	.long _sys_truncate
	.long _sys_ftruncate
	.long _sys_fchmod
	.long _sys_fchown16	/* 95 */
	.long _sys_getpriority
	.long _sys_setpriority
	.long _sys_ni_syscall	/* old profil syscall holder */
	.long _sys_statfs
	.long _sys_fstatfs	/* 100 */
	.long _sys_ni_syscall
	.long _sys_socketcall
	.long _sys_syslog
	.long _sys_setitimer
	.long _sys_getitimer	/* 105 */
	.long _sys_newstat
	.long _sys_newlstat
	.long _sys_newfstat
	.long _sys_ni_syscall
	.long _sys_ni_syscall	/* iopl for i386 */ /* 110 */
	.long _sys_vhangup
	.long _sys_ni_syscall	/* obsolete idle() syscall */
	.long _sys_ni_syscall	/* vm86old for i386 */
	.long _sys_wait4
	.long _sys_ni_syscall	/* 115 */ /* sys_swapoff */
	.long _sys_sysinfo
	.long _sys_ipc
	.long _sys_fsync
	.long _sys_sigreturn
	.long _sys_clone		/* 120 */
	.long _sys_setdomainname
	.long _sys_newuname
	.long _sys_cacheflush	/* modify_ldt for i386 */
	.long _sys_adjtimex
	.long _sys_ni_syscall	/* 125 */ /* sys_mprotect */
	.long _sys_sigprocmask
	.long _sys_ni_syscall	/* old "creat_module" */
	.long _sys_init_module
	.long _sys_delete_module
	.long _sys_ni_syscall	/* 130: old "get_kernel_syms" */
	.long _sys_quotactl
	.long _sys_getpgid
	.long _sys_fchdir
	.long _sys_bdflush
	.long _sys_sysfs		/* 135 */
	.long _sys_personality
	.long _sys_ni_syscall	/* for afs_syscall */
	.long _sys_setfsuid16
	.long _sys_setfsgid16
	.long _sys_llseek	/* 140 */
	.long _sys_getdents
	.long _sys_select
	.long _sys_flock
	.long _sys_ni_syscall	/* sys_msync */
	.long _sys_readv		/* 145 */
	.long _sys_writev
	.long _sys_getsid
	.long _sys_fdatasync
	.long _sys_sysctl
	.long _sys_ni_syscall	/* 150 */ /* sys_mlock */
	.long _sys_ni_syscall	/* sys_munlock */
	.long _sys_ni_syscall	/* sys_mlockall */
	.long _sys_ni_syscall	/* sys_munlockall */
	.long _sys_sched_setparam
	.long _sys_sched_getparam /* 155 */
	.long _sys_sched_setscheduler
	.long _sys_sched_getscheduler
	.long _sys_sched_yield
	.long _sys_sched_get_priority_max
	.long _sys_sched_get_priority_min  /* 160 */
	.long _sys_sched_rr_get_interval
	.long _sys_nanosleep
	.long _sys_ni_syscall	/* sys_mremap */
	.long _sys_setresuid16
	.long _sys_getresuid16	/* 165 */
	.long _sys_ni_syscall	/* for vm86 */
	.long _sys_ni_syscall	/* old "query_module" */
	.long _sys_poll
	.long _sys_ni_syscall	/* sys_nfsservctl */
	.long _sys_setresgid16	/* 170 */
	.long _sys_getresgid16
	.long _sys_prctl
	.long _sys_rt_sigreturn
	.long _sys_rt_sigaction
	.long _sys_rt_sigprocmask /* 175 */
	.long _sys_rt_sigpending
	.long _sys_rt_sigtimedwait
	.long _sys_rt_sigqueueinfo
	.long _sys_rt_sigsuspend
	.long _sys_pread64	/* 180 */
	.long _sys_pwrite64
	.long _sys_lchown16
	.long _sys_getcwd
	.long _sys_capget
	.long _sys_capset	/* 185 */
	.long _sys_sigaltstack
	.long _sys_sendfile
	.long _sys_ni_syscall	/* streams1 */
	.long _sys_ni_syscall	/* streams2 */
	.long _sys_vfork		/* 190 */
	.long _sys_getrlimit
	.long _sys_mmap2
	.long _sys_truncate64
	.long _sys_ftruncate64
	.long _sys_stat64	/* 195 */
	.long _sys_lstat64
	.long _sys_fstat64
	.long _sys_chown
	.long _sys_getuid
	.long _sys_getgid	/* 200 */
	.long _sys_geteuid
	.long _sys_getegid
	.long _sys_setreuid
	.long _sys_setregid
	.long _sys_getgroups	/* 205 */
	.long _sys_setgroups
	.long _sys_fchown
	.long _sys_setresuid
	.long _sys_getresuid
	.long _sys_setresgid	/* 210 */
	.long _sys_getresgid
	.long _sys_lchown
	.long _sys_setuid
	.long _sys_setgid
	.long _sys_setfsuid	/* 215 */
	.long _sys_setfsgid
	.long _sys_pivot_root
	.long _sys_ni_syscall	/* sys_mincore */
	.long _sys_ni_syscall	/* sys_madvise */
	.long _sys_getdents64	/* 220 */
	.long _sys_fcntl64
	.long _sys_ni_syscall	/* reserved for TUX */
	.long _sys_ni_syscall
	.long _sys_gettid
	.long _sys_ni_syscall	/* 225 */ /* sys_readahead */
	.long _sys_setxattr
	.long _sys_lsetxattr
	.long _sys_fsetxattr
	.long _sys_getxattr
	.long _sys_lgetxattr	/* 230 */
	.long _sys_fgetxattr
	.long _sys_listxattr
	.long _sys_llistxattr
	.long _sys_flistxattr
	.long _sys_removexattr	/* 235 */
	.long _sys_lremovexattr
	.long _sys_fremovexattr
	.long _sys_tkill
	.long _sys_sendfile64
	.long _sys_futex		/* 240 */
	.long _sys_sched_setaffinity
	.long _sys_sched_getaffinity
	.long _sys_ni_syscall	/* sys_set_thread_area */
	.long _sys_ni_syscall	/* sys_get_thread_area */
	.long _sys_io_setup	/* 245 */
	.long _sys_io_destroy
	.long _sys_io_getevents
	.long _sys_io_submit
	.long _sys_io_cancel
	.long _sys_ni_syscall	/* 250 */ /* sys_alloc_hugepages */
	.long _sys_ni_syscall	/* sys_freec_hugepages */
	.long _sys_exit_group
	.long _sys_lookup_dcookie
	.long _sys_bfin_spinlock
	.rept 2
	.long _sys_ni_syscall
	.endr
excpt_saved_imask:
	.long 0;
/* Put this in the kernel data section - that should always be covered by
 * a CPLB.
 */
exception_stack:
	.rept 1024
	.long 0;
	.endr
exception_stack_top:
