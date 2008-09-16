/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 *
 * 64-bit PowerPC adoption
 *   copyright (C) 2005 Taneli Vähäkangas and Heikki Lindholm
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
 * along with Xenomai; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _XENO_ASM_POWERPC_SYSTEM_H
#define _XENO_ASM_POWERPC_SYSTEM_H

#ifdef __KERNEL__

#include <linux/ptrace.h>
#include <asm-generic/xenomai/system.h>

#ifdef CONFIG_PPC64
#define XNARCH_THREAD_STACKSZ   16384
#else
#define XNARCH_THREAD_STACKSZ   4096
/* FIXME: Work-around to bypass the issues raised by using vmalloc'ed
   memory over Xenomai kernel threads. We are possibly mishandling
   minor faults aimed at kernel mapping propagation on this arch --
   this should be fixed at Adeos level. */
#define XNARCH_SCATTER_HEAPSZ   (128 * 1024)	/* Remain inside kmalloc() bounds. */
#endif

#define xnarch_stack_size(tcb)  ((tcb)->stacksize)
#define xnarch_user_task(tcb)   ((tcb)->user_task)
#define xnarch_user_pid(tcb)    ((tcb)->user_task->pid)

struct xnthread;
struct task_struct;

typedef struct xnarchtcb {	/* Per-thread arch-dependent block */

	/* User mode side */
	struct task_struct *user_task;	/* Shadowed user-space task */
	struct task_struct *active_task;	/* Active user-space task */
	struct thread_struct *tsp;	/* Pointer to the active thread struct (&ts or &user->thread). */

	/* Kernel mode side */
	struct thread_struct ts;	/* Holds kernel-based thread context. */
#ifdef CONFIG_XENO_HW_FPU
	/* We only care for basic FPU handling in kernel-space; Altivec
	   and SPE are not available to kernel-based nucleus threads. */
	rthal_fpenv_t *fpup;	/* Pointer to the FPU backup area */
	struct task_struct *user_fpu_owner;
	unsigned long user_fpu_owner_prev_msr;
	/* Pointer the the FPU owner in userspace:
	   - NULL for RT K threads,
	   - last_task_used_math for Linux US threads (only current or NULL when MP)
	   - current for RT US threads.
	 */
#define xnarch_fpu_ptr(tcb)     ((tcb)->fpup)
#else				/* !CONFIG_XENO_HW_FPU */
#define xnarch_fpu_ptr(tcb)     NULL
#endif				/* CONFIG_XENO_HW_FPU */

	unsigned stacksize;	/* Aligned size of stack (bytes) */
	unsigned long *stackbase;	/* Stack space */

	/* Init block */
	struct xnthread *self;
	int imask;
	const char *name;
	void (*entry) (void *cookie);
	void *cookie;

} xnarchtcb_t;

typedef struct xnarch_fltinfo {

	unsigned exception;
	struct pt_regs *regs;

} xnarch_fltinfo_t;

#define xnarch_fault_trap(fi)   ((unsigned int)(fi)->regs->trap)
#define xnarch_fault_code(fi)   ((fi)->regs->dar)
#define xnarch_fault_pc(fi)     ((fi)->regs->nip)
#define xnarch_fault_pc(fi)     ((fi)->regs->nip)
/* FIXME: FPU faults ignored by the nanokernel on PPC. */
#define xnarch_fault_fpu_p(fi)  (0)
/* The following predicates are only usable over a regular Linux stack
   context. */
#define xnarch_fault_pf_p(fi)   ((fi)->exception == IPIPE_TRAP_ACCESS)
#ifdef CONFIG_PPC64
#define xnarch_fault_bp_p(fi)   ((current->ptrace & PT_PTRACED) && \
				 ((fi)->exception == IPIPE_TRAP_IABR || \
				  (fi)->exception == IPIPE_TRAP_SSTEP))
#else /* !CONFIG_PPC64 */
#define xnarch_fault_bp_p(fi)   ((current->ptrace & PT_PTRACED) && \
				 ((fi)->exception == IPIPE_TRAP_IABR || \
				  (fi)->exception == IPIPE_TRAP_SSTEP || \
				  (fi)->exception == IPIPE_TRAP_DEBUG))
#endif /* CONFIG_PPC64 */

#define xnarch_fault_notify(fi) (!xnarch_fault_bp_p(fi))

#ifdef __cplusplus
extern "C" {
#endif

static inline void *xnarch_alloc_host_mem(u_long bytes)
{
	if (bytes > 128 * 1024)
		return vmalloc(bytes);

	return kmalloc(bytes, GFP_KERNEL);
}

static inline void xnarch_free_host_mem(void *chunk, u_long bytes)
{
	if (bytes > 128 * 1024)
		vfree(chunk);
	else
		kfree(chunk);
}

#ifdef __cplusplus
}
#endif

#else /* !__KERNEL__ */

#include <nucleus/system.h>
#include <bits/local_lim.h>

#endif /* __KERNEL__ */

#endif /* !_XENO_ASM_POWERPC_SYSTEM_H */
