/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_X86_SYSCALL_32_H
#define _XENO_ASM_X86_SYSCALL_32_H
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
#define __xn_reg_arg1(regs)   ((regs)->x86reg_bx)
#define __xn_reg_arg2(regs)   ((regs)->x86reg_cx)
#define __xn_reg_arg3(regs)   ((regs)->x86reg_dx)
#define __xn_reg_arg4(regs)   ((regs)->x86reg_si)
#define __xn_reg_arg5(regs)   ((regs)->x86reg_di)

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
#define __xn_put_user(task,src,dstP)           __put_user(src,dstP)
#define __xn_get_user(task,dst,srcP)           __get_user(dst,srcP)
#define __xn_strncpy_from_user(task,dstP,srcP,n)    wrap_strncpy_from_user(dstP,srcP,n)

#define __xn_range_ok(task,addr,size)    wrap_range_ok(task,addr,size)
/* WP bit must work for using the shadow support, so we only need
   trivial range checking here. Note: we consider any address lower
   than the natural page size as spurious. */
#define __xn_access_ok(task,type,addr,size)    (/*(unsigned long)(addr) >= PAGE_SIZE && */ \
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
 * mechanism implementation:
 * Copyright (C) 1992,1993,1995-2000,2002,2003 Free Software Foundation, Inc.
 * Contributed by Ulrich Drepper, <drepper@gnu.org>, August 1995.
 *
 * The following code defines an inline syscall mechanism used by
 * Xenomai's real-time interfaces to invoke the skin module services
 * in kernel space.
 */

#ifdef CONFIG_XENO_X86_SEP
/* This form relies on the kernel's vsyscall support in order to use
   the SEP instructions which must be supported by the hardware. We
   also depend on the NPTL providing us a pointer to the vsyscall DSO
   entry point, to which we branch to instead of issuing a trap. */
#define DOSYSCALL  "call *%%gs:0x10\n\t"
#else /* CONFIG_XENO_X86_SEP */
#define DOSYSCALL  "int $0x80\n\t"
#endif /* CONFIG_XENO_X86_SEP */

/* The one that cannot fail. */
#define DOSYSCALLSAFE  "int $0x80\n\t"

asm (".L__X'%ebx = 1\n\t"
     ".L__X'%ecx = 2\n\t"
     ".L__X'%edx = 2\n\t"
     ".L__X'%eax = 3\n\t"
     ".L__X'%esi = 3\n\t"
     ".L__X'%edi = 3\n\t"
     ".L__X'%ebp = 3\n\t"
     ".L__X'%esp = 3\n\t"
     ".macro bpushl name reg\n\t"
     ".if 1 - \\name\n\t"
     ".if 2 - \\name\n\t"
     "pushl %ebx\n\t"
     ".else\n\t"
     "xchgl \\reg, %ebx\n\t"
     ".endif\n\t"
     ".endif\n\t"
     ".endm\n\t"
     ".macro bpopl name reg\n\t"
     ".if 1 - \\name\n\t"
     ".if 2 - \\name\n\t"
     "popl %ebx\n\t"
     ".else\n\t"
     "xchgl \\reg, %ebx\n\t"
     ".endif\n\t"
     ".endif\n\t"
     ".endm\n\t"
     ".macro bmovl name reg\n\t"
     ".if 1 - \\name\n\t"
     ".if 2 - \\name\n\t"
     "movl \\reg, %ebx\n\t"
     ".endif\n\t"
     ".endif\n\t"
     ".endm\n\t");

#define XENOMAI_SYS_MUX(nr, op, args...) \
  ({								      \
    unsigned resultvar;						      \
    asm volatile (						      \
    LOADARGS_##nr						      \
    "movl %1, %%eax\n\t"					      \
    DOSYSCALL							      \
    RESTOREARGS_##nr						      \
    : "=a" (resultvar)						      \
    : "i" (__xn_mux_code(0,op)) ASMFMT_##nr(args) : "memory", "cc");  \
    (int) resultvar; })

#define XENOMAI_SYS_MUX_SAFE(nr, op, args...) \
  ({								      \
    unsigned resultvar;						      \
    asm volatile (						      \
    LOADARGS_##nr						      \
    "movl %1, %%eax\n\t"					      \
    DOSYSCALLSAFE						      \
    RESTOREARGS_##nr						      \
    : "=a" (resultvar)						      \
    : "i" (__xn_mux_code(0,op)) ASMFMT_##nr(args) : "memory", "cc");  \
    (int) resultvar; })

#define XENOMAI_SKIN_MUX(nr, shifted_id, op, args...) \
  ({								      \
    int muxcode = __xn_mux_code(shifted_id,op);			      \
    unsigned resultvar;						      \
    asm volatile (						      \
    LOADARGS_##nr						      \
    "movl %1, %%eax\n\t"					      \
    DOSYSCALL							      \
    RESTOREARGS_##nr						      \
    : "=a" (resultvar)						      \
    : "m" (muxcode) ASMFMT_##nr(args) : "memory", "cc");	      \
    (int) resultvar; })

#define LOADARGS_0
#define LOADARGS_1 \
    "bpushl .L__X'%k2, %k2\n\t" \
    "bmovl .L__X'%k2, %k2\n\t"
#define LOADARGS_2	LOADARGS_1
#define LOADARGS_3	LOADARGS_1
#define LOADARGS_4	LOADARGS_1
#define LOADARGS_5	LOADARGS_1

#define RESTOREARGS_0
#define RESTOREARGS_1 \
    "bpopl .L__X'%k2, %k2\n\t"
#define RESTOREARGS_2	RESTOREARGS_1
#define RESTOREARGS_3	RESTOREARGS_1
#define RESTOREARGS_4	RESTOREARGS_1
#define RESTOREARGS_5	RESTOREARGS_1

#define ASMFMT_0()
#define ASMFMT_1(arg1) \
	, "acdSD" (arg1)
#define ASMFMT_2(arg1, arg2) \
	, "adSD" (arg1), "c" (arg2)
#define ASMFMT_3(arg1, arg2, arg3) \
	, "aSD" (arg1), "c" (arg2), "d" (arg3)
#define ASMFMT_4(arg1, arg2, arg3, arg4) \
	, "aD" (arg1), "c" (arg2), "d" (arg3), "S" (arg4)
#define ASMFMT_5(arg1, arg2, arg3, arg4, arg5) \
	, "a" (arg1), "c" (arg2), "d" (arg3), "S" (arg4), "D" (arg5)

#define XENOMAI_SYSCALL0(op)                XENOMAI_SYS_MUX(0,op)
#define XENOMAI_SYSCALL1(op,a1)             XENOMAI_SYS_MUX(1,op,a1)
#define XENOMAI_SYSCALL2(op,a1,a2)          XENOMAI_SYS_MUX(2,op,a1,a2)
#define XENOMAI_SYSCALL3(op,a1,a2,a3)       XENOMAI_SYS_MUX(3,op,a1,a2,a3)
#define XENOMAI_SYSCALL4(op,a1,a2,a3,a4)    XENOMAI_SYS_MUX(4,op,a1,a2,a3,a4)
#define XENOMAI_SYSCALL5(op,a1,a2,a3,a4,a5) XENOMAI_SYS_MUX(5,op,a1,a2,a3,a4,a5)
#define XENOMAI_SYSBIND(a1,a2,a3,a4)        XENOMAI_SYS_MUX_SAFE(4,__xn_sys_bind,a1,a2,a3,a4)

#define XENOMAI_SKINCALL0(id,op)                XENOMAI_SKIN_MUX(0,id,op)
#define XENOMAI_SKINCALL1(id,op,a1)             XENOMAI_SKIN_MUX(1,id,op,a1)
#define XENOMAI_SKINCALL2(id,op,a1,a2)          XENOMAI_SKIN_MUX(2,id,op,a1,a2)
#define XENOMAI_SKINCALL3(id,op,a1,a2,a3)       XENOMAI_SKIN_MUX(3,id,op,a1,a2,a3)
#define XENOMAI_SKINCALL4(id,op,a1,a2,a3,a4)    XENOMAI_SKIN_MUX(4,id,op,a1,a2,a3,a4)
#define XENOMAI_SKINCALL5(id,op,a1,a2,a3,a4,a5) XENOMAI_SKIN_MUX(5,id,op,a1,a2,a3,a4,a5)

#ifdef CONFIG_X86_TSC

#define CONFIG_XENO_HW_DIRECT_TSC 1

static inline unsigned long long __xn_rdtsc (void)

{
    unsigned long long t;
    __asm__ __volatile__( "rdtsc" : "=A" (t));
    return t;
}

#endif  /* CONFIG_X86_TSC */

#endif /* __KERNEL__ */

#endif /* !_XENO_ASM_X86_SYSCALL_32_H */
