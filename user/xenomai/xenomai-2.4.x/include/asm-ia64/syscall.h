/*
 * Copyright &copy; 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 * Copyright &copy; 2004 The HYADES project <http://www.hyades-itea.org>
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

#ifndef _XENO_ASM_IA64_SYSCALL_H
#define _XENO_ASM_IA64_SYSCALL_H

#include <asm-generic/xenomai/syscall.h>

#define __xn_mux_code(shifted_id,op) ((op << 24)|shifted_id|(__xn_sys_mux & 0xffffUL))
#define __xn_mux_shifted_id(id) ((id << 16) & 0xff0000UL)

#ifdef __KERNEL__

#include <linux/errno.h>
#include <asm/ptrace.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

/* Register mapping for accessing syscall args. */

#define __xn_reg_mux(regs)    (regs->r15)
#define __xn_reg_rval(regs)   (regs->r8)
#define __xn_reg_err(regs)    (regs->r10)
#define __xn_reg_arg1(regs)   (regs->r16)
#define __xn_reg_arg2(regs)   (regs->r17)
#define __xn_reg_arg3(regs)   (regs->r18)
#define __xn_reg_arg4(regs)   (regs->r19)
#define __xn_reg_arg5(regs)   (regs->r20)

#define __xn_reg_mux_p(regs)        ((__xn_reg_mux(regs) & 0xffff) == __xn_sys_mux)
#define __xn_mux_id(regs)           ((__xn_reg_mux(regs) >> 16) & 0xff)
#define __xn_mux_op(regs)           ((__xn_reg_mux(regs) >> 24) & 0xff)

/* Our own set of copy-to/from-user macros which must bypass
   might_sleep() checks. The caller cannot fault and is expected to
   have checked for bad range before using the copy macros, so we
   should not have to care about the result. */
#define __xn_copy_from_user(task,dstP,srcP,n)  \
    ({ int __err__ = __copy_from_user_inatomic(dstP,srcP,n); __err__; })
#define __xn_copy_to_user(task,dstP,srcP,n)  \
    ({ int __err__ = __copy_to_user_inatomic(dstP,srcP,n); __err__; })
#define __xn_put_user(task,src,dstP)          __put_user(src,dstP)
#define __xn_get_user(task,dst,srcP)          __get_user(dst,srcP)

static inline long __xn_strncpy_from_user(struct task_struct *p,
					  char *dstP, const char __user *srcP, long n)
{
    return __strncpy_from_user(dstP,srcP,n);
}

#define __xn_access_ok(task,type,addr,size)  wrap_access_ok(task,addr,size)

/* Purposedly used inlines and not macros for the following routines
   so that we don't risk spurious side-effects on the value arg. */

static inline void __xn_success_return(struct pt_regs *regs, int v)
{
    __xn_reg_err(regs) = 0;
    __xn_reg_rval(regs) = v;
}

static inline void __xn_error_return(struct pt_regs *regs, int v)
{
    __xn_reg_err(regs) = -1;
    __xn_reg_rval(regs) = -v;
}

static inline void __xn_status_return(struct pt_regs *regs, int v)
{
    if(v < 0)
        __xn_error_return(regs, v);
    else
        __xn_success_return(regs, v);
}

static inline int __xn_interrupted_p(struct pt_regs *regs)
{
    return __xn_reg_err(regs) == -1 && __xn_reg_rval(regs) == EINTR;
}

#else /* !__KERNEL__ */

#include <asm/unistd.h>

/*
 * Some of the following macros have been adapted from glibc's syscall
 * mechanism implementation:
 * Copyright (C) 1992,1993,1995-2000,2002,2003 Free Software Foundation, Inc.
 * Contributed by Ulrich Drepper, <drepper@gnu.org>, August 1995.
 *
 * The following code defines an inline syscall mechanism used by
 * Xenomai's real-time interfaces to invoke the skin module
 * services in kernel space.
 */

#define LOAD_ARGS_0()   do { } while (0)
#define LOAD_ARGS_1(out0)				\
  register long _out0 asm ("out0") = (long) (out0);	\
  LOAD_ARGS_0 ()
#define LOAD_ARGS_2(out0, out1)				\
  register long _out1 asm ("out1") = (long) (out1);	\
    LOAD_ARGS_1 (out0)					
#define LOAD_ARGS_3(out0, out1, out2)			\
  register long _out2 asm ("out2") = (long) (out2);	\
  LOAD_ARGS_2 (out0, out1)
#define LOAD_ARGS_4(out0, out1, out2, out3)		\
  register long _out3 asm ("out3") = (long) (out3);	\
  LOAD_ARGS_3 (out0, out1, out2)
#define LOAD_ARGS_5(out0, out1, out2, out3, out4)	\
  register long _out4 asm ("out4") = (long) (out4);	\
  LOAD_ARGS_4 (out0, out1, out2, out3)

#define ASM_ARGS_0
#define ASM_ARGS_1      ASM_ARGS_0, "r" (_out0)
#define ASM_ARGS_2      ASM_ARGS_1, "r" (_out1)
#define ASM_ARGS_3      ASM_ARGS_2, "r" (_out2)
#define ASM_ARGS_4      ASM_ARGS_3, "r" (_out3)
#define ASM_ARGS_5      ASM_ARGS_4, "r" (_out4)

#define ASM_CLOBBERS_0	ASM_CLOBBERS_1, "out0"
#define ASM_CLOBBERS_1	ASM_CLOBBERS_2, "out1"
#define ASM_CLOBBERS_2	ASM_CLOBBERS_3, "out2"
#define ASM_CLOBBERS_3	ASM_CLOBBERS_4, "out3"
#define ASM_CLOBBERS_4	ASM_CLOBBERS_5, "out4"
#define ASM_CLOBBERS_5	, "out5", "out6", "out7",			\
  /* Non-stacked integer registers, minus r8, r10, r15.  */             \
  "r2", "r3", "r9", "r11", "r12", "r13", "r14", "r16", "r17",           \
  "r18", "r19", "r20", "r21", "r22", "r23", "r24", "r25", "r26", "r27",	\
  "r28", "r29", "r30", "r31",						\
  /* Predicate registers.  */						\
  "p6", "p7", "p8", "p9", "p10", "p11", "p12", "p13", "p14", "p15",	\
  /* Non-rotating fp registers.  */					\
  "f6", "f7", "f8", "f9", "f10", "f11", "f12", "f13", "f14", "f15",	\
  /* Branch registers.  */						\
  "b6", "b7"

#define XENOMAI_SKIN_MUX(nr, shifted_id, op, args...)			\
  ({									\
    register long _r15 asm ("r15") = (__xn_mux_code(shifted_id,op));	\
    register long _retval asm ("r8");					\
    register long err asm ("r10");					\
    LOAD_ARGS_##nr (args);						\
    __asm __volatile ("break %3;;\n\t"					\
		      : "=r" (_retval), "=r" (_r15), "=r" (err)		\
		      : "i" (__BREAK_SYSCALL), "1" (_r15)		\
			ASM_ARGS_##nr					\
		      : "memory" ASM_CLOBBERS_##nr);			\
    err < 0 ? -_retval : _retval; })

#define XENOMAI_SYS_MUX(nr, op, args...) XENOMAI_SKIN_MUX(nr, 0, op , ##args)

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

#define CONFIG_XENO_HW_DIRECT_TSC 1

static inline unsigned long long __xn_rdtsc (void)
{
    unsigned long long t;
    __asm__ __volatile__("mov %0=ar.itc;;" : "=r"(t) :: "memory");
    return t;
}

#endif /* __KERNEL__ */

#endif /* !_XENO_ASM_IA64_SYSCALL_H */
