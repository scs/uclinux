/*
 * Copied from ia64/kernel/entry.S
 *
 * Copyright (C) 1998-2003 Hewlett-Packard Co
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 * Copyright (C) 1999, 2002-2003
 *	Asit Mallick <Asit.K.Mallick@intel.com>
 * 	Don Dugger <Don.Dugger@intel.com>
 *	Suresh Siddha <suresh.b.siddha@intel.com>
 *	Fenghua Yu <fenghua.yu@intel.com>
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 *
 * Copyright &copy; 2004,2005 Philippe Gerum <rpm@xenomai.org>.
 * Copyright &copy; 2004 The HYADES project <http://www.hyades-itea.org>
 */
/*
 * ia64_switch_to now places correct virtual mapping in in TR2 for
 * kernel stack. This allows us to handle interrupts without changing
 * to physical mode.
 *
 * Jonathan Nicklin	<nicklin@missioncriticallinux.com>
 * Patrick O'Rourke	<orourke@missioncriticallinux.com>
 * 11/07/2000
 /
/*
 * Global (preserved) predicate usage on syscall entry/exit path:
 *
 *	pKStk:		See entry.h.
 *	pUStk:		See entry.h.
 *	pSys:		See entry.h.
 *	pNonSys:	!pSys
 */

#include <linux/config.h>
#include <entry.h>

#include <asm/asmmacro.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include <asm/kregs.h>
#include <asm/pgtable.h>
#include <asm/percpu.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/unistd.h>    


/* int rthal_prepare_stack(__u64 stackbase) */
	
GLOBAL_ENTRY(rthal_prepare_stack)
	.prologue
	alloc r16=ar.pfs,1,8,0,8
	.rotr v[2]			// declare our 2 aliases for rotating
	adds sp=-16,sp
	DO_SAVE_SWITCH_STACK
	.body
	;;
	mov r18=in0		        // r18 = stackbase (copy destination)
	mov r19=IA64_SWITCH_STACK_SIZE-8
	;;
	shr r19=r19,3			// r19=(8-bytes word count)-1
	adds r18=-8,r18			// simulate initial pre-decrementation of dest index
	adds r20=IA64_SWITCH_STACK_SIZE+8,sp // r20=((struct switch_stack *)sp + 1) + 8-bytes padding
	;; 
	mov ar.lc=r19			// loop count in repeat/until fashion
	mov ar.ec=2			// two pipeline stages are active when copying
	mov pr.rot=1<<16		// use p16(=1) and p17(=0) for predicates
	;;
copy_domain_stack:
(p16)	ld8 v[0]=[r20],-8
(p17)	st8 [r18]=v[1],-8
	br.ctop.dptk.few copy_domain_stack
	;;
	.restore sp
	adds sp=IA64_SWITCH_STACK_SIZE+16,sp
	mov ar.pfs=r16
	br.ret.sptk.many rp
END(rthal_prepare_stack)

/*
 * void rthal_thread_switch(__u64 *prev_ksp, __u64 *next_ksp, int user_p)
 *
 * Most of this code has been lifted from the original ia64_switch_to() routine
 * from linux/arch/ia64/kernel/entry.S, and adapted to perform hybrid
 * scheduling between kernel and user-space Xenomai threads.
 */
GLOBAL_ENTRY(rthal_thread_switch)
	.prologue
	alloc r16=ar.pfs,3,0,0,0
	DO_SAVE_SWITCH_STACK
	.body

	mov r22=in0
	mov r21=in1
	;;
	st8 [r22]=sp			// save kernel stack pointer of old task
	cmp.eq p7,p6=r0,in2		// kernel-based Xenomai thread?
	;;
(p7)	ld8 sp=[r21]			// load stack pointer of incoming Xenomai kernel thread
(p7)	br.cond.dpnt .same_current	// If yes, then don't bother for mapping.

	movl r25=init_task
	mov r27=IA64_KR(CURRENT_STACK)
	adds r22=-IA64_TASK_THREAD_KSP_OFFSET,in1
	;;
	dep r20=0,r22,61,3		// physical address of "next"
	;;
	shr.u r26=r20,IA64_GRANULE_SHIFT
	cmp.eq p7,p6=r25,r22
	;;
(p6)	cmp.eq p7,p6=r26,r27
(p6)	br.cond.dpnt .map
	;;
.done:
	ld8 sp=[r21]			// load kernel stack pointer of new task
	mov IA64_KR(CURRENT)=r22	// update "current" application register
	mov r13=r22			// set "current" pointer
	;;
.same_current:	
	DO_LOAD_SWITCH_STACK

#ifdef CONFIG_SMP
	sync.i				// ensure "fc"s done by this CPU are visible on other CPUs
#endif
	br.ret.sptk.many rp		// boogie on out in new context

.map:
	rsm psr.ic			// interrupts (psr.i) are already disabled here
	movl r25=PAGE_KERNEL
	;;
	srlz.d
	or r23=r25,r20			// construct PA | page properties
	mov r25=IA64_GRANULE_SHIFT<<2
	;;
	mov cr.itir=r25
	mov cr.ifa=r22			// VA of next task...
	;;
	mov r25=IA64_TR_CURRENT_STACK
	mov IA64_KR(CURRENT_STACK)=r26	// remember last page we mapped...
	;;
	itr.d dtr[r25]=r23		// wire in new mapping...
	ssm psr.ic			// reenable the psr.ic bit
	;;
	srlz.d
	br.cond.sptk .done
END(rthal_thread_switch)
