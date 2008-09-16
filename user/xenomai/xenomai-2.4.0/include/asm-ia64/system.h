/*
 * Copyright &copy; 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 * Copyright &copy; 2004 The HYADES project <http://www.hyades-itea.org>
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

#ifndef _XENO_ASM_IA64_SYSTEM_H
#define _XENO_ASM_IA64_SYSTEM_H

#ifdef __KERNEL__

#include <linux/ptrace.h>

#define xnarch_fault_um(fi)     (user_mode((fi)->ia64.regs))

#include <asm-generic/xenomai/system.h>

#define XNARCH_THREAD_STACKSZ  KERNEL_STACK_SIZE

#define xnarch_stack_size(tcb)  ((tcb)->stacksize)
#define xnarch_user_task(tcb)   ((tcb)->user_task)
#define xnarch_user_pid(tcb)    ((tcb)->user_task->pid)

struct xnthread;
struct task_struct;

typedef struct xnarch_stack {
    struct xnarch_stack *next;
} xnarch_stack_t;

typedef struct xnarchtcb {      /* Per-thread arch-dependent block */

    __u64 *kspp;
    struct ia64_fpreg *fpup;
#define xnarch_fpu_ptr(tcb)     ((tcb)->fpup)

    /* User mode side */
    struct task_struct *user_task;      /* Shadowed user-space task */
    struct task_struct *active_task;    /* Active user-space task */

    /* Kernel mode side */
    __u64 ksp;
    struct ia64_fpreg fph[96];	/* FPU backup area for kernel-based tasks. */

    unsigned stacksize;         /* Aligned size of stack (bytes) */
    xnarch_stack_t *stackbase;	/* Stack space */
    const char *name;

} xnarchtcb_t;

int xnarch_alloc_stack(xnarchtcb_t *tcb,
		       unsigned stacksize);

void xnarch_free_stack(xnarchtcb_t *tcb);

typedef struct xnarch_fltinfo {

    ia64trapinfo_t ia64;
    unsigned trap;

} xnarch_fltinfo_t;

#define xnarch_fault_trap(fi)  ((fi)->trap)
#define xnarch_fault_code(fi)  ((fi)->ia64.isr)
#define xnarch_fault_pc(fi)    ((fi)->ia64.regs->cr_iip)
/* Fault is caused by use of FPU while FPU disabled. */
#define xnarch_fault_fpu_p(fi) ((fi)->trap == IPIPE_FPDIS_TRAP)
/* The following predicates are only usable over a regular Linux stack
   context. */
#define xnarch_fault_pf_p(fi)   ((fi)->trap == IPIPE_PF_TRAP)
#define xnarch_fault_bp_p(fi)   ((current->ptrace & PT_PTRACED) && \
                                 (fi)->trap == IPIPE_DEBUG_TRAP)
#define xnarch_fault_notify(fi) (!xnarch_fault_bp_p(fi))

#ifdef __cplusplus
extern "C" {
#endif

static inline void *xnarch_alloc_host_mem (u_long bytes)

{
    if (bytes > 128*1024)
        return vmalloc(bytes);

    return kmalloc(bytes,GFP_KERNEL);
}

static inline void xnarch_free_host_mem (void *chunk, u_long bytes)

{
    if (bytes > 128*1024)
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

#endif /* !_XENO_ASM_IA64_SYSTEM_H */
