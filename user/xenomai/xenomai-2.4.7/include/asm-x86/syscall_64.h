/*
 * Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org>.
 *
 * Xenomai is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License,
 * or (at your option) any later version.
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

#ifndef _XENO_ASM_X86_SYSCALL_64_H
#define _XENO_ASM_X86_SYSCALL_64_H
#define _XENO_ASM_X86_SYSCALL_H

#include <asm-generic/xenomai/syscall.h>

#define __xn_mux_code(shifted_id,op) ((op << 24)|shifted_id|(__xn_sys_mux & 0x7fff))
#define __xn_mux_shifted_id(id) ((id << 16) & 0xff0000)

#ifdef __KERNEL__

#include <linux/errno.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>
#include <asm/xenomai/wrappers.h>

/* Register mapping for accessing syscall args. */

#define __xn_reg_mux(regs)    ((regs)->x86reg_origax)
#define __xn_reg_rval(regs)   ((regs)->x86reg_ax)
#define __xn_reg_arg1(regs)   ((regs)->x86reg_di)
#define __xn_reg_arg2(regs)   ((regs)->x86reg_si)
#define __xn_reg_arg3(regs)   ((regs)->x86reg_dx)
#define __xn_reg_arg4(regs)   ((regs)->r10) /* entry.S convention here. */
#define __xn_reg_arg5(regs)   ((regs)->r8)

#define __xn_reg_mux_p(regs)  ((__xn_reg_mux(regs) & 0x7fff) == __xn_sys_mux)
#define __xn_mux_id(regs)     ((__xn_reg_mux(regs) >> 16) & 0xff)
#define __xn_mux_op(regs)     ((__xn_reg_mux(regs) >> 24) & 0xff)

/* Our own set of copy-to/from-user macros which must bypass
   might_sleep() checks. The caller cannot fault and is expected to
   have checked for bad range before using the copy macros, so we
   should not have to care about the result. */
#define __xn_copy_from_user(task,dstP,srcP,n)  \
    ({ int __err__ = __copy_from_user_inatomic(dstP,srcP,n); __err__; })
#define __xn_copy_to_user(task,dstP,srcP,n)  \
    ({ int __err__ = __copy_to_user_inatomic(dstP,srcP,n); __err__; })
#define __xn_put_user(task,src,dstP)		__put_user(src,dstP)
#define __xn_get_user(task,dst,srcP)		__get_user(dst,srcP)
#define __xn_strncpy_from_user(task,dstP,srcP,n) rthal_strncpy_from_user(dstP,srcP,n)

#define __xn_range_ok(task,addr,size) ({ \
	unsigned long flag,sum; \
	asm("addq %3,%1 ; sbbq %0,%0; cmpq %1,%4; sbbq $0,%0" \
		:"=&r" (flag), "=r" (sum) \
	        :"1" (addr),"g" ((long)(size)),"g" (task_thread_info(task)->addr_limit.seg)); \
	flag == 0; })

/* We consider any address lower than the natural page size as spurious. */
#define __xn_access_ok(task,type,addr,size)    ((unsigned long)(addr) >= PAGE_SIZE && \
						__xn_range_ok(task, addr, size))

/* Purposedly used inlines and not macros for the following routines
   so that we don't risk spurious side-effects on the value arg. */

static inline void __xn_success_return(struct pt_regs *regs, int v)
{
	__xn_reg_rval(regs) = v;
}

static inline void __xn_error_return(struct pt_regs *regs, int v)
{
	__xn_reg_rval(regs) = v;
}

static inline void __xn_status_return(struct pt_regs *regs, int v)
{
	__xn_reg_rval(regs) = v;
}

static inline int __xn_interrupted_p(struct pt_regs *regs)
{
	return __xn_reg_rval(regs) == -EINTR;
}

#else /* !__KERNEL__ */

/*
 * Some of the following macros have been adapted from glibc's syscall
 * mechanism implementation: sysdeps/unix/sysv/linux/x86_64/sysdep.h.
*  Copyright (C) 2001,02,03,04 Free Software Foundation, Inc.
 *
 * The following code defines an inline syscall mechanism used by
 * Xenomai's real-time interfaces to invoke the skin module services
 * in kernel space.
 */

#define LOAD_ARGS_0()
#define LOAD_REGS_0
#define ASM_ARGS_0

#define LOAD_ARGS_1(a1)				\
	long int __arg1 = (long) (a1);			\
	LOAD_ARGS_0 ()
#define LOAD_REGS_1					\
	register long int _a1 asm ("rdi") = __arg1;	\
	LOAD_REGS_0
#define ASM_ARGS_1	ASM_ARGS_0, "r" (_a1)

#define LOAD_ARGS_2(a1, a2)				\
  long int __arg2 = (long) (a2);			\
  LOAD_ARGS_1 (a1)
#define LOAD_REGS_2					\
  register long int _a2 asm ("rsi") = __arg2;		\
  LOAD_REGS_1
#define ASM_ARGS_2	ASM_ARGS_1, "r" (_a2)

#define LOAD_ARGS_3(a1, a2, a3)			\
  long int __arg3 = (long) (a3);			\
  LOAD_ARGS_2 (a1, a2)
#define LOAD_REGS_3					\
  register long int _a3 asm ("rdx") = __arg3;		\
  LOAD_REGS_2
#define ASM_ARGS_3	ASM_ARGS_2, "r" (_a3)

#define LOAD_ARGS_4(a1, a2, a3, a4)			\
  long int __arg4 = (long) (a4);			\
  LOAD_ARGS_3 (a1, a2, a3)
#define LOAD_REGS_4					\
  register long int _a4 asm ("r10") = __arg4;		\
  LOAD_REGS_3
#define ASM_ARGS_4	ASM_ARGS_3, "r" (_a4)

#define LOAD_ARGS_5(a1, a2, a3, a4, a5)		\
  long int __arg5 = (long) (a5);			\
  LOAD_ARGS_4 (a1, a2, a3, a4)
#define LOAD_REGS_5					\
  register long int _a5 asm ("r8") = __arg5;		\
  LOAD_REGS_4
#define ASM_ARGS_5	ASM_ARGS_4, "r" (_a5)

#define DO_SYSCALL(name, nr, args...)					\
	({								\
	  unsigned long __resultvar;					\
	  LOAD_ARGS_##nr (args)						\
	  LOAD_REGS_##nr						\
	  asm volatile("syscall\n\t"					\
		       : "=a" (__resultvar)				\
		       : "0" (name) ASM_ARGS_##nr			\
		       : "memory", "cc", "r11", "cx");			\
	  (long)__resultvar;						\
	})

#define XENOMAI_SYS_MUX(nr, op, args...) \
	DO_SYSCALL(__xn_mux_code(0,op), nr, args)

#define XENOMAI_SKIN_MUX(nr, shifted_id, op, args...) \
	DO_SYSCALL(__xn_mux_code(shifted_id,op), nr, args)

#define XENOMAI_SYSCALL0(op)                XENOMAI_SYS_MUX(0,op)
#define XENOMAI_SYSCALL1(op,a1)             XENOMAI_SYS_MUX(1,op,a1)
#define XENOMAI_SYSCALL2(op,a1,a2)          XENOMAI_SYS_MUX(2,op,a1,a2)
#define XENOMAI_SYSCALL3(op,a1,a2,a3)       XENOMAI_SYS_MUX(3,op,a1,a2,a3)
#define XENOMAI_SYSCALL4(op,a1,a2,a3,a4)    XENOMAI_SYS_MUX(4,op,a1,a2,a3,a4)
#define XENOMAI_SYSCALL5(op,a1,a2,a3,a4,a5) XENOMAI_SYS_MUX(5,op,a1,a2,a3,a4,a5)
#define XENOMAI_SYSBIND(a1,a2,a3,a4)        XENOMAI_SYS_MUX(4,__xn_sys_bind,a1,a2,a3,a4)

#define XENOMAI_SKINCALL0(id,op)                XENOMAI_SKIN_MUX(0,id,op)
#define XENOMAI_SKINCALL1(id,op,a1)             XENOMAI_SKIN_MUX(1,id,op,a1)
#define XENOMAI_SKINCALL2(id,op,a1,a2)          XENOMAI_SKIN_MUX(2,id,op,a1,a2)
#define XENOMAI_SKINCALL3(id,op,a1,a2,a3)       XENOMAI_SKIN_MUX(3,id,op,a1,a2,a3)
#define XENOMAI_SKINCALL4(id,op,a1,a2,a3,a4)    XENOMAI_SKIN_MUX(4,id,op,a1,a2,a3,a4)
#define XENOMAI_SKINCALL5(id,op,a1,a2,a3,a4,a5) XENOMAI_SKIN_MUX(5,id,op,a1,a2,a3,a4,a5)

#define CONFIG_XENO_HW_DIRECT_TSC 1 /* x86_64 always has a TSC */

static inline unsigned long long __xn_rdtsc(void)
{
	unsigned long long t;
	unsigned int __a,__d;
	asm volatile("rdtsc" : "=a" (__a), "=d" (__d));
	t = ((unsigned long)__a) | (((unsigned long)__d)<<32);
	return t;
}

#endif /* __KERNEL__ */

#endif /* !_XENO_ASM_X86_SYSCALL_64_H */
