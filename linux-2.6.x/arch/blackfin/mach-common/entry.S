/* 
 *  linux/arch/bfinnommu/mach-bf533/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2004        LG Soft India
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file README.legal in the main directory of this archive
 * for more details.
 *
 * Blackfin BF533/2.6 fixes : LG Soft India	
 *
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
 * entry.S  contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
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
	.long ex_syscall;
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_spinlock
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
	.long ex_trap_c
.text

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
	rtx

ENTRY(spinlock_bh)
	SAVE_ALL_SYS
	/* To end up here, vector 15 was changed - so we have to change it
	   back.  */
	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = evt_system_call;
	p1.h = evt_system_call;
	[p0] = p1;
	csync;
	r0 = [sp + PT_R0];
	sp += -12;
	call sys_bfin_spinlock;
	sp += 12;
	[SP + PT_R0] = R0;
	RESTORE_ALL_SYS
	rti;

ENTRY(ex_trap_c)
	(R7:6,P5:4) = [sp++];
	ASTAT = [sp++];
	SAVE_ALL_SYS;
        p2.l = lo(IPEND);
        p2.h = hi(IPEND);
	csync;
        r0 = [p2];              /* Read current IPEND */
        [sp + PT_IPEND] = r0;   /* Store IPEND */

	r0 = sp; 		/* stack frame pt_regs pointer argument ==> r0 */
	SP += -12;
	call trap_c;
	SP += 12; 
	call ret_from_exception;
	RESTORE_ALL_SYS
	rtx;
	
ENTRY(trap) /* Exception: 4th entry into system event table(supervisor mode)*/
	/* Try to deal with syscalls quickly.  */
	[--sp] = ASTAT;
	[--sp] = (R7:6, P5:4);
	r7 = SEQSTAT;	/* reason code is in bit 5:0 */
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

ENTRY(execve)
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
	call do_execve;
	SP += 16;
	cc = r0 == 0;
	if ! cc jump 1f;
	/* Success.  Copy our temporary pt_regs to the top of the kernel
	   stack and do a normal exception return.  */
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
	call schedule;
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
	call do_signal; 
	SP += 12;

syscall_really_exit:
	r5 = [sp + PT_RESERVED];
	rets = r5;
	rts;

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
	r1 = 0x17(Z);
	r2 = ~r1;
	r2.h = 0;
	r0 = r2 & r0;
        r1 = 1;
        r1 = r0 - r1;
        r2 = r0 & r1;
        cc = r2 == 0;
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

ENTRY(_evt14_softirq)
	rti;

schedule_and_signal_from_int:
	/* To end up here, vector 15 was changed - so we have to change it
	   back.  */
	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = evt_system_call;
	p1.h = evt_system_call;
	[p0] = p1;
	csync;
	p1 = rets;
	[sp + PT_RESERVED] = p1;

	p0.l = irq_flags;
	p0.h = irq_flags;
	r0 = [p0];
	sti r0;

	jump.s resume_userspace;

_schedule_and_signal:
	SAVE_CONTEXT_SYSCALL
	/* To end up here, vector 15 was changed - so we have to change it
	   back.  */
	p0.l = lo(EVT15);
	p0.h = hi(EVT15);
	p1.l = evt_system_call;
	p1.h = evt_system_call;
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
	.long sys_ni_syscall	/* 0  -  old "setup()" system call*/
	.long sys_exit
	.long sys_fork
	.long sys_read
	.long sys_write
	.long sys_open		/* 5 */
	.long sys_close
	.long sys_waitpid
	.long sys_creat
	.long sys_link
	.long sys_unlink	/* 10 */
	.long sys_execve
	.long sys_chdir
	.long sys_time
	.long sys_mknod
	.long sys_chmod		/* 15 */
	.long sys_chown16
	.long sys_ni_syscall	/* old break syscall holder */
	.long sys_stat
	.long sys_lseek
	.long sys_getpid	/* 20 */
	.long sys_mount
	.long sys_oldumount
	.long sys_setuid16
	.long sys_getuid16
	.long sys_stime		/* 25 */
	.long sys_ptrace
	.long sys_alarm
	.long sys_fstat
	.long sys_pause
	.long sys_utime		/* 30 */
	.long sys_ni_syscall	/* old stty syscall holder */
	.long sys_ni_syscall	/* old gtty syscall holder */
	.long sys_access
	.long sys_nice
	.long sys_ni_syscall	/* 35 */ /* old ftime syscall holder */
	.long sys_sync
	.long sys_kill
	.long sys_rename
	.long sys_mkdir
	.long sys_rmdir		/* 40 */
	.long sys_dup
	.long sys_pipe
	.long sys_times
	.long sys_ni_syscall	/* old prof syscall holder */
	.long sys_brk		/* 45 */
	.long sys_setgid16
	.long sys_getgid16
	.long sys_signal
	.long sys_geteuid16
	.long sys_getegid16	/* 50 */
	.long sys_acct
	.long sys_umount	/* recycled never used phys() */
	.long sys_ni_syscall	/* old lock syscall holder */
	.long sys_ioctl
	.long sys_fcntl		/* 55 */
	.long sys_ni_syscall	/* old mpx syscall holder */
	.long sys_setpgid
	.long sys_ni_syscall	/* old ulimit syscall holder */
	.long sys_ni_syscall
	.long sys_umask		/* 60 */
	.long sys_chroot
	.long sys_ustat
	.long sys_dup2
	.long sys_getppid
	.long sys_getpgrp	/* 65 */
	.long sys_setsid
	.long sys_sigaction
	.long sys_sgetmask
	.long sys_ssetmask
	.long sys_setreuid16	/* 70 */
	.long sys_setregid16
	.long sys_sigsuspend
	.long sys_sigpending
	.long sys_sethostname
	.long sys_setrlimit	/* 75 */
	.long sys_old_getrlimit
	.long sys_getrusage
	.long sys_gettimeofday
	.long sys_settimeofday
	.long sys_getgroups16	/* 80 */
	.long sys_setgroups16
	.long old_select
	.long sys_symlink
	.long sys_lstat
	.long sys_readlink	/* 85 */
	.long sys_uselib
	.long sys_ni_syscall	/* sys_swapon */
	.long sys_reboot
	.long old_readdir
	.long old_mmap		/* 90 */
	.long sys_munmap
	.long sys_truncate
	.long sys_ftruncate
	.long sys_fchmod
	.long sys_fchown16	/* 95 */
	.long sys_getpriority
	.long sys_setpriority
	.long sys_ni_syscall	/* old profil syscall holder */
	.long sys_statfs
	.long sys_fstatfs	/* 100 */
	.long sys_ni_syscall
	.long sys_socketcall
	.long sys_syslog
	.long sys_setitimer
	.long sys_getitimer	/* 105 */
	.long sys_newstat
	.long sys_newlstat
	.long sys_newfstat
	.long sys_ni_syscall
	.long sys_ni_syscall	/* iopl for i386 */ /* 110 */
	.long sys_vhangup
	.long sys_ni_syscall	/* obsolete idle() syscall */
	.long sys_ni_syscall	/* vm86old for i386 */
	.long sys_wait4
	.long sys_ni_syscall	/* 115 */ /* sys_swapoff */
	.long sys_sysinfo
	.long sys_ipc
	.long sys_fsync
	.long sys_sigreturn
	.long sys_clone		/* 120 */
	.long sys_setdomainname
	.long sys_newuname
	.long sys_cacheflush	/* modify_ldt for i386 */
	.long sys_adjtimex
	.long sys_ni_syscall	/* 125 */ /* sys_mprotect */
	.long sys_sigprocmask
	.long sys_ni_syscall	/* old "creat_module" */
	.long sys_init_module
	.long sys_delete_module
	.long sys_ni_syscall	/* 130: old "get_kernel_syms" */
	.long sys_quotactl
	.long sys_getpgid
	.long sys_fchdir
	.long sys_bdflush
	.long sys_sysfs		/* 135 */
	.long sys_personality
	.long sys_ni_syscall	/* for afs_syscall */
	.long sys_setfsuid16
	.long sys_setfsgid16
	.long sys_llseek	/* 140 */
	.long sys_getdents
	.long sys_select
	.long sys_flock
	.long sys_ni_syscall	/* sys_msync */
	.long sys_readv		/* 145 */
	.long sys_writev
	.long sys_getsid
	.long sys_fdatasync
	.long sys_sysctl
	.long sys_ni_syscall	/* 150 */ /* sys_mlock */
	.long sys_ni_syscall	/* sys_munlock */
	.long sys_ni_syscall	/* sys_mlockall */
	.long sys_ni_syscall	/* sys_munlockall */
	.long sys_sched_setparam
	.long sys_sched_getparam /* 155 */
	.long sys_sched_setscheduler
	.long sys_sched_getscheduler
	.long sys_sched_yield
	.long sys_sched_get_priority_max
	.long sys_sched_get_priority_min  /* 160 */
	.long sys_sched_rr_get_interval
	.long sys_nanosleep
	.long sys_ni_syscall	/* sys_mremap */
	.long sys_setresuid16
	.long sys_getresuid16	/* 165 */
	.long sys_ni_syscall	/* for vm86 */
	.long sys_ni_syscall	/* old "query_module" */
	.long sys_poll
	.long sys_ni_syscall	/* sys_nfsservctl */
	.long sys_setresgid16	/* 170 */
	.long sys_getresgid16
	.long sys_prctl
	.long sys_rt_sigreturn
	.long sys_rt_sigaction
	.long sys_rt_sigprocmask /* 175 */
	.long sys_rt_sigpending
	.long sys_rt_sigtimedwait
	.long sys_rt_sigqueueinfo
	.long sys_rt_sigsuspend
	.long sys_pread64	/* 180 */
	.long sys_pwrite64
	.long sys_lchown16
	.long sys_getcwd
	.long sys_capget
	.long sys_capset	/* 185 */
	.long sys_sigaltstack
	.long sys_sendfile
	.long sys_ni_syscall	/* streams1 */
	.long sys_ni_syscall	/* streams2 */
	.long sys_vfork		/* 190 */
	.long sys_getrlimit
	.long sys_mmap2
	.long sys_truncate64
	.long sys_ftruncate64
	.long sys_stat64	/* 195 */
	.long sys_lstat64
	.long sys_fstat64
	.long sys_chown
	.long sys_getuid
	.long sys_getgid	/* 200 */
	.long sys_geteuid
	.long sys_getegid
	.long sys_setreuid
	.long sys_setregid
	.long sys_getgroups	/* 205 */
	.long sys_setgroups
	.long sys_fchown
	.long sys_setresuid
	.long sys_getresuid
	.long sys_setresgid	/* 210 */
	.long sys_getresgid
	.long sys_lchown
	.long sys_setuid
	.long sys_setgid
	.long sys_setfsuid	/* 215 */
	.long sys_setfsgid
	.long sys_pivot_root
	.long sys_ni_syscall	/* sys_mincore */
	.long sys_ni_syscall	/* sys_madvise */
	.long sys_getdents64	/* 220 */
	.long sys_fcntl64
	.long sys_ni_syscall	/* reserved for TUX */
	.long sys_ni_syscall
	.long sys_gettid
	.long sys_ni_syscall	/* 225 */ /* sys_readahead */
	.long sys_setxattr
	.long sys_lsetxattr
	.long sys_fsetxattr
	.long sys_getxattr
	.long sys_lgetxattr	/* 230 */
	.long sys_fgetxattr
	.long sys_listxattr
	.long sys_llistxattr
	.long sys_flistxattr
	.long sys_removexattr	/* 235 */
	.long sys_lremovexattr
	.long sys_fremovexattr
	.long sys_tkill
	.long sys_sendfile64
	.long sys_futex		/* 240 */
	.long sys_sched_setaffinity
	.long sys_sched_getaffinity
	.long sys_ni_syscall	/* sys_set_thread_area */
	.long sys_ni_syscall	/* sys_get_thread_area */
	.long sys_io_setup	/* 245 */
	.long sys_io_destroy
	.long sys_io_getevents
	.long sys_io_submit
	.long sys_io_cancel
	.long sys_ni_syscall	/* 250 */ /* sys_alloc_hugepages */
	.long sys_ni_syscall	/* sys_freec_hugepages */
	.long sys_exit_group
	.long sys_lookup_dcookie
	.long sys_bfin_spinlock
	.rept 2
	.long (sys_ni_syscall)
	.endr
