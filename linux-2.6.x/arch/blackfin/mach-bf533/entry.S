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
 */

/*
 * entry.S  contains the system-call and fault low-level handling routines.
 * This also contains the timer-interrupt handler, as well as all interrupts
 * and faults that can result in a task-switch.
 *
 * NOTE: This code handles signal-recognition, which happens every time
 * after a timer-interrupt and after each system call.
 */


#include <linux/sys.h>
#include <linux/config.h>
#include <linux/linkage.h>
#include <asm/unistd.h>		
#include <asm/setup.h>
#include <asm/errno.h>
#include <asm/setup.h>
#include <asm/traps.h>
#include <asm/entry.h>
#include <asm/thread_info.h>  /* TIF_NEED_RESCHED */
#include <asm/ptrace.h>  
#include <asm/asm-offsets.h>

.text

.globl system_call
.globl trap 
.globl resume
.globl sys_call_table

ENTRY(trap) /* Exception: 4th entry into system event table(supervisor mode)*/
	SAVE_ALL_SYS
	
        p2.l = 0x2108;
        p2.h = 0xffe0;
        r0 = [p2];              /* Read current IPEND */
	csync;
        [sp + PT_IPEND] = r0;   /* Store IPEND */

	r1 = [sp + PT_SEQSTAT];	/* reason code is in bit 5:0 */
	r0.l = 0x3f;
	r0.h = 0x0;
	r1 = r1 & r0;
	CC = r1 == 0;
	if ! cc jump 1f;
	raise 14;		/* invoked by TRAP #0, for sys call */
	RESTORE_ALL_SYS           
	rtx;
1:
	r0 = sp; 		/* stack frame pt_regs pointer argument ==> r0 */
	SP += -12;
	call trap_c;
	SP += 12; 


	call ret_from_exception;
	
	RESTORE_ALL_SYS
	rtx;

badsys:
	r7 = -ENOSYS; 		/* signextending enough */
	[sp + PT_R0] = r7;	/* return value from system call */
	rti;	

do_trace:
	r7 = -ENOSYS;
	[sp + PT_R0] = r7;	/* needed for strace */
	sp += -4;		/* why minus then plus again ??? Tony */
	SP += -12;
	call syscall_trace; 
	SP += 12;
	sp += 4;
	r5 = [sp+PT_R5];
	r0 = -ENOSYS;
	r7 = NR_syscalls;
	cc = r5 < r7;
	if ! cc jump 1f;
	p4 = r1;
	p5.l = sys_call_table;
	p5.h = sys_call_table;
	p5 = p5 + (p4 << 2);
	r0 = [sp + PT_R0];	/* confirm the system call args */
	r1 = [sp + PT_R1];
	r2 = [sp + PT_R2];
	jump (p5);
1:
	[sp + PT_R0] = r0;	/* save the return value */
	sp += -4;		/* dummy return address  */
	SP += -12;
	jump.l syscall_trace;   /* void syscall_trace(void) */ 

ENTRY(system_call)
	/* Store IPEND */
	p2.l = 0x2108;
	p2.h = 0xffe0;
	r0 = [p2];
	csync;
	[sp + PT_IPEND] = r0;

	/* Store RETS for now */
	r0 = rets;
	[sp + PT_RESERVED] = r0;
	/* Set the stack for the current process */
	r7 = sp;  
	r6.l = 0xe000;
	r6.h = 0xffff;
	r7 = r7 & r6;  		/*thread_info*/
	p2 = r7; 
	p2 = [p2];

	[p2+(TASK_THREAD+THREAD_ESP0)] = sp;

	/* Check the System Call */
	r7 = __NR_syscall; 
	cc = r5 < r7;		/* r5 = number of system call */
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

	r6 = __NR__newselect;		/*FIX for select call*/
	cc = r5 == r6;
	if cc jump l_next;

	r6 = __NR_rt_sigaction;		/*FIX for rt_sigaction call*/
	cc = r5 == r6;
	if cc jump l_next_4;

	r6 = __NR_wait4;		/*FIX for wait4 call*/
	cc = r5 == r6;
	if cc jump l_next_4;
	
	r6 = __NR_rt_sigprocmask;	/*FIX for rt_sigprocmask call*/
	cc = r5 == r6;
	if cc jump l_next_4;

	r6 = __NR_rt_sigtimedwait;	/*FIX for rt_sigtimedwait call*/
	cc = r5 == r6;
	if cc jump l_next_4;

	r6 = __NR_mount;		/*FIX for mount call*/
	cc = r5 == r6;
	if cc jump l_next;
	
	r6 = __NR_mremap;		/*FIX for mremap call*/
	cc = r5 == r6;
	if cc jump l_next_4;

	r6 = __NR_sendfile;		/*FIX for sendfile call*/
	cc = r5 == r6;
	if cc jump l_next_4;

	r6 = __NR_ptrace;		/*FIX for ptrace call*/
	cc = r5 == r6;
	if cc jump l_next_4;

	r6 = __NR_init_module;		/*FIX for init_module call*/
	cc = r5 == r6;
	if cc jump l_next;

	r6 = __NR_ipc;			/*FIX for ipc call*/
	cc = r5 == r6;
	if cc jump l_next;

	r6 = __NR_pread;		/*FIX for pread64 call*/
	cc = r5 == r6;
	if cc jump l_next;
	
	r6 = __NR_pwrite;		/*FIX for pwrite64 call*/
	cc = r5 == r6;
	if cc jump l_next;

	r6 = __NR_llseek;		/*FIX for llseek call*/
	cc = r5 == r6;
	if cc jump l_next;

	SP += -12;
	call (p5);
	SP += 12;
l_before:
	[sp + PT_R0] = r0;
	
	/* Check whether we need to drop to user mode */
	r0 = [sp + PT_IPEND];
	CC = r0 == 0;
	if !CC jump exit_syscall;
	call kernel_to_user_mode;
exit_syscall:
	/* Only allow interrupts when we are really the last one on
	 * the kernel stack, otherwise stack overflow can occur during
         * heavy interrupt load
	 */
	r7 = sp;
	r4.l = 0xe000;
	r4.h = 0xffff;
	r7 = r7 & r4;		/*thread_info->flags*/
	p5 = r7;
	r7 = [p5 + TI_FLAGS];
	[--sp] = r4;
	r4 = _TIF_WORK_MASK;
	r7 =  r7 & r4;
	r4 = [sp++]
	cc = BITTST(r7, TIF_NEED_RESCHED);
	if cc jump syscall_sigpending; 
	call reschedule;

syscall_sigpending:
	[--sp] = p3;
	p3 = [p5];
	r7 = [p3 + TASK_SIGPENDING];
	p3 = [sp++];		
	cc = r7 == 0;
	if cc jump syscall_really_exit;
	call Lsignal_return;

syscall_really_exit:
	r0 = [sp + PT_RESERVED];
	rets = r0;
	rts;

Lsignal_return:
	r0 = 0;
	r1 = sp;
	[--sp] = rets;
	SP += -12;
	call do_signal; 
	SP += 12;
	rets = [sp++];
	rts;

/* Force kernel return from interrupt 15 to user mode -- Steven Chen*/
kernel_to_user_mode:
	[--sp] = rets;
	r0 = [sp++];
	reti = r0;
	rti;

resume:
	/*
	 * Beware - when entering resume, prev (the current task) is
	 * in r0, next (the new task) is in r1.
	 */

	p0 = r0;
	p1 = r1;

	[--sp] = rets;
	[--sp] = (r7:6, p5:3);
	[--sp] = fp;

	/* save seqstat */
	r7 = seqstat;
	[p0+(TASK_THREAD+THREAD_SR)] = r7;

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

	/* restore status register */
	r7 = [p1+(TASK_THREAD+THREAD_SR)];
	seqstat = r7;

	/* restore pc */
	p0 = [p1+(TASK_THREAD+THREAD_PC)];
	jump (p0); 

	/*
	 * While we don't rely on compiler magic, nothing prevents us from
	 * simple jumps.
	 * Following code actually lands up in a new (old) task. .. akale
	 */

new_old_task:	
	fp = [sp++];

	/* You may get assembler errors if you modify following instruction.
	 * Had to do lots of experiments to get it right. The assembler simply
	 * doesn't accept a correct syntax - amit */
	( R7:6, p5 : 3) = [sp++];

	rets = [sp++];

	/*
	 * When we come out of resume, r0 carries "old" task, becuase we are
	 * in "new" task.
	 */

	rts;

l_next:
	[--sp] = r4;
	[--sp] = r3;
	SP += -12;
	call (P5);
	SP += 20;
	jump l_before;

l_next_4:
	[--sp] = r3;
	SP += -12;
	call (P5);
	SP += 16;
	jump l_before;

ret_from_exception:
	p2.l = 0x2108;
	p2.h = 0xffe0;
	r0 = [p2];
	csync;
	[sp + PT_IPEND] = r0;


	r0 = [sp + PT_IPEND];
	CC = bittst(r0, 15);	/* check if returning to kernel*/
	if cc jump 4f;   /* if so, skip resched, signals*/   
	cc = bittst(r0, 3);	/* check if return from exception */
	if cc jump 1f;
	/* reduce the nested interrupt IVG14 --> IVG 15, */
	[--sp] = rets;
	call kernel_to_user_mode; 
	rets = [sp++];
	r0.l = 0x2;
	r0.h = 0x0;	/* flag for return to user mode */
	[sp + PT_IPEND] = r0;

1:	/* Set the stack for the current process */
	r7 = sp;
	r4.l = 0xe000;
	r4.h = 0xffff;
	r7 = r7 & r4;		/*thread_info->flags*/
	p5 = r7;
	r7 = [p5 + TI_FLAGS];
	[--sp] = r4;
	r4 = _TIF_WORK_MASK;
	r7 =  r7 & r4;
	r4 = [sp++]
	cc = BITTST(r7, TIF_NEED_RESCHED);
	cc = r7 == 0;
	if !cc jump 3f; 
	[--sp] = rets;
	call reschedule;
	rets = [sp++];
	jump ret_from_exception;

3:
	[--sp] = p3;
	p3 = [p5];
	r7 = [p3 + TASK_SIGPENDING];
	p3 = [sp++];		
	cc = r7 == 0;
	if cc jump 4f;

	r0 = rets;
	[sp + PT_RESERVED] = r0;

	call Lsignal_return;

	r7 = [sp+PT_RESERVED];
	rets = r7;
4:
	rts;

.data
ALIGN
sys_call_table:	
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

	/* no recognization now by bfin-gcc */
/*	.rept NR_syscalls-(.-SYMBOL_NAME(sys_call_table))/4	*/
	.rept 3
	.long (sys_ni_syscall)
	.endr
