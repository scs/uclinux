/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 *
 * ARM port
 *   Copyright (C) 2005 Stelian Pop
 *
 * Copyright (C) 2007 Sebastian Smolorz <ssm@emlix.com>
 *	Support for TSC emulation in user space for decrementing counters
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

#ifndef _XENO_ASM_ARM_SYSCALL_H
#define _XENO_ASM_ARM_SYSCALL_H

#include <asm-generic/xenomai/syscall.h>
#include <asm/xenomai/features.h>

#define __xn_mux_code(shifted_id,op) ((op << 24)|shifted_id|(__xn_sys_mux & 0xffff))
#define __xn_mux_shifted_id(id) ((id << 16) & 0xff0000)

#define XENO_ARM_SYSCALL        0x000F0042	/* carefully chosen... */

#ifdef __KERNEL__

#include <linux/errno.h>
#include <asm/uaccess.h>
#include <asm/ptrace.h>

/* Register mapping for accessing syscall args. */

#define __xn_reg_mux(regs)      ((regs)->ARM_ORIG_r0)
#define __xn_reg_rval(regs)     ((regs)->ARM_r0)
#define __xn_reg_arg1(regs)     ((regs)->ARM_r1)
#define __xn_reg_arg2(regs)     ((regs)->ARM_r2)
#define __xn_reg_arg3(regs)     ((regs)->ARM_r3)
#define __xn_reg_arg4(regs)     ((regs)->ARM_r4)
#define __xn_reg_arg5(regs)     ((regs)->ARM_r5)

/* In OABI_COMPAT mode, handle both OABI and EABI userspace syscalls */
#ifdef CONFIG_OABI_COMPAT
#define __xn_reg_mux_p(regs)    ( ((regs)->ARM_r7 == __NR_OABI_SYSCALL_BASE + XENO_ARM_SYSCALL) || \
                                  ((regs)->ARM_r7 == __NR_SYSCALL_BASE + XENO_ARM_SYSCALL) )
#else
#define __xn_reg_mux_p(regs)      ((regs)->ARM_r7 == __NR_SYSCALL_BASE + XENO_ARM_SYSCALL)
#endif

#define __xn_mux_id(regs)       ((__xn_reg_mux(regs) >> 16) & 0xff)
#define __xn_mux_op(regs)       ((__xn_reg_mux(regs) >> 24) & 0xff)

/* Our own set of copy-to/from-user macros which must bypass
   might_sleep() checks. The caller cannot fault and is expected to
   have checked for bad range before using the copy macros, so we
   should not have to care about the result. */
#define __xn_copy_from_user(task,dstP,srcP,n)  \
    ({ int __err__ = __copy_from_user_inatomic(dstP,srcP,n); __err__; })
#define __xn_copy_to_user(task,dstP,srcP,n)  \
    ({ int __err__ = __copy_to_user_inatomic(dstP,srcP,n); __err__; })
#define __xn_put_user(task,src,dstP)                __put_user(src,dstP)
#define __xn_get_user(task,dst,srcP)                __get_user(dst,srcP)
#define __xn_strncpy_from_user(task,dstP,srcP,n)    \
  ({ int __err__ = __strncpy_from_user(dstP,srcP,n); __err__; })

#define __xn_access_ok(task,type,addr,size)         wrap_range_ok(task,addr,size)

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
 * Some of the following macros have been adapted from Linux's
 * implementation of the syscall mechanism in <asm-arm/unistd.h>:
 *
 * The following code defines an inline syscall mechanism used by
 * Xenomai's real-time interfaces to invoke the skin module
 * services in kernel space.
 */

#define LOADARGS_0(muxcode, dummy...)		\
    __r0 = (unsigned long) (muxcode)
#define LOADARGS_1(muxcode, arg1)		\
    LOADARGS_0(muxcode);			\
    __r1 = (unsigned long) (arg1)
#define LOADARGS_2(muxcode, arg1, arg2)       	\
    LOADARGS_1(muxcode, arg1);			\
    __r2 = (unsigned long) (arg2)
#define LOADARGS_3(muxcode, arg1, arg2, arg3) 	\
    LOADARGS_2(muxcode, arg1, arg2);		\
    __r3 = (unsigned long) (arg3)
#define LOADARGS_4(muxcode, arg1, arg2, arg3, arg4)	\
    LOADARGS_3(muxcode, arg1, arg2, arg3);		\
    __r4 = (unsigned long) (arg4)
#define LOADARGS_5(muxcode, arg1, arg2, arg3, arg4, arg5)	\
    LOADARGS_4(muxcode, arg1, arg2, arg3, arg4);	    	\
    __r5 = (unsigned long) (arg5)

#define ASM_INDECL_0 register unsigned long __r0  __asm__ ("r0")
#define ASM_INDECL_1 ASM_INDECL_0; register unsigned long __r1  __asm__ ("r1")
#define ASM_INDECL_2 ASM_INDECL_1; register unsigned long __r2  __asm__ ("r2")
#define ASM_INDECL_3 ASM_INDECL_2; register unsigned long __r3  __asm__ ("r3")
#define ASM_INDECL_4 ASM_INDECL_3; register unsigned long __r4  __asm__ ("r4")
#define ASM_INDECL_5 ASM_INDECL_4; register unsigned long __r5  __asm__ ("r5")

#define ASM_INPUT_0 "r" (__r0)
#define ASM_INPUT_1 ASM_INPUT_0, "r" (__r1)
#define ASM_INPUT_2 ASM_INPUT_1, "r" (__r2)
#define ASM_INPUT_3 ASM_INPUT_2, "r" (__r3)
#define ASM_INPUT_4 ASM_INPUT_3, "r" (__r4)
#define ASM_INPUT_5 ASM_INPUT_4, "r" (__r5)

#define __sys2(x)	#x
#define __sys1(x)	__sys2(x)

#ifdef CONFIG_XENO_ARM_EABI
#define __SYS_REG register unsigned long __r7 __asm__ ("r7") = XENO_ARM_SYSCALL;
#define __SYS_REG_LIST ,"r" (__r7)
#define __syscall "swi\t0"
#else
#define __SYS_REG
#define __SYS_REG_LIST
#define __NR_OABI_SYSCALL_BASE	0x900000
#define __syscall "swi\t" __sys1(__NR_OABI_SYSCALL_BASE + XENO_ARM_SYSCALL) ""
#endif

#define XENOMAI_DO_SYSCALL(nr, shifted_id, op, args...)	\
  ({								\
        unsigned long __res;					\
	register unsigned long __res_r0 __asm__ ("r0");		\
   	ASM_INDECL_##nr;					\
    __SYS_REG;                          \
								\
	LOADARGS_##nr(__xn_mux_code(shifted_id,op), args);	\
	__asm__ __volatile__ (				\
        __syscall                       \
		: "=r" (__res_r0)				\
		: ASM_INPUT_##nr __SYS_REG_LIST	\
		: "memory");					\
   	__res = __res_r0;					\
   	(int) __res;						\
  })

#define XENOMAI_SYSCALL0(op)                XENOMAI_DO_SYSCALL(0,0,op)
#define XENOMAI_SYSCALL1(op,a1)             XENOMAI_DO_SYSCALL(1,0,op,a1)
#define XENOMAI_SYSCALL2(op,a1,a2)          XENOMAI_DO_SYSCALL(2,0,op,a1,a2)
#define XENOMAI_SYSCALL3(op,a1,a2,a3)       XENOMAI_DO_SYSCALL(3,0,op,a1,a2,a3)
#define XENOMAI_SYSCALL4(op,a1,a2,a3,a4)    XENOMAI_DO_SYSCALL(4,0,op,a1,a2,a3,a4)
#define XENOMAI_SYSCALL5(op,a1,a2,a3,a4,a5) XENOMAI_DO_SYSCALL(5,0,op,a1,a2,a3,a4,a5)
#define XENOMAI_SYSBIND(a1,a2,a3,a4)        XENOMAI_DO_SYSCALL(4,0,__xn_sys_bind,a1,a2,a3,a4)

#define XENOMAI_SKINCALL0(id,op)                XENOMAI_DO_SYSCALL(0,id,op)
#define XENOMAI_SKINCALL1(id,op,a1)             XENOMAI_DO_SYSCALL(1,id,op,a1)
#define XENOMAI_SKINCALL2(id,op,a1,a2)          XENOMAI_DO_SYSCALL(2,id,op,a1,a2)
#define XENOMAI_SKINCALL3(id,op,a1,a2,a3)       XENOMAI_DO_SYSCALL(3,id,op,a1,a2,a3)
#define XENOMAI_SKINCALL4(id,op,a1,a2,a3,a4)    XENOMAI_DO_SYSCALL(4,id,op,a1,a2,a3,a4)
#define XENOMAI_SKINCALL5(id,op,a1,a2,a3,a4,a5) XENOMAI_DO_SYSCALL(5,id,op,a1,a2,a3,a4,a5)

#ifdef CONFIG_XENO_ARM_HW_DIRECT_TSC
#define CONFIG_XENO_HW_DIRECT_TSC
#endif /* CONFIG_XENO_ARM_HW_DIRECT_TSC */

#endif /* __KERNEL__ */

#define XENOMAI_SYSARCH_ATOMIC_ADD_RETURN	0
#define XENOMAI_SYSARCH_ATOMIC_SET_MASK		1
#define XENOMAI_SYSARCH_ATOMIC_CLEAR_MASK	2
#define XENOMAI_SYSARCH_XCHG			3

struct __xn_tscinfo {
        int type;		/* Must remain first member */
        union {
                struct {
                        volatile unsigned *counter;
                        unsigned mask;
                        volatile unsigned long long *tsc;
                } fr;
                struct {
			volatile unsigned *counter;
			unsigned mask;
			volatile unsigned *last_cnt;
			volatile unsigned long long *tsc;
                } dec;
        } u;
};
#define __XN_TSC_TYPE_NONE        0
#define __XN_TSC_TYPE_FREERUNNING 1
#define __XN_TSC_TYPE_DECREMENTER 2

#define XENOMAI_SYSARCH_TSCINFO                 4

#ifndef __KERNEL__
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <limits.h>

__attribute__((weak)) struct __xn_tscinfo __xn_tscinfo = {
	type: -1
};

static inline unsigned long long __xn_rdtsc(void)
{
#if CONFIG_XENO_ARM_HW_DIRECT_TSC == __XN_TSC_TYPE_FREERUNNING
	const unsigned long long mask = __xn_tscinfo.u.fr.mask;
	unsigned long long result;
	unsigned counter;

	__asm__ ("ldmia %1, %M0\n"
		 : "=r"(result), "+&r"(__xn_tscinfo.u.fr.tsc)
		 : "m"(*__xn_tscinfo.u.fr.tsc));
	__asm__ ("" : /* */ : /* */ : "memory");
	counter = *__xn_tscinfo.u.fr.counter;

	if ((counter & mask) < (result & mask))
		result += mask + 1;
	return (result & ~mask) | (counter & mask);

#elif CONFIG_XENO_ARM_HW_DIRECT_TSC == __XN_TSC_TYPE_DECREMENTER
	const unsigned mask = __xn_tscinfo.u.dec.mask;
	unsigned long long after, before;
	unsigned counter, last_cnt;

	do {
		before = *__xn_tscinfo.u.dec.tsc;
		counter = *__xn_tscinfo.u.dec.counter;
		last_cnt = *__xn_tscinfo.u.dec.last_cnt;
		/* compiler barrier. */
		asm("" : /* */ : /* */ : "memory");

		after = *__xn_tscinfo.u.dec.tsc;
	} while (after != before);

	counter &= mask;
	last_cnt &= mask;
	if (counter > last_cnt)
		before += mask + 1;
	return (before + last_cnt - counter);

#endif /* CONFIG_XENO_HW_DIRECT_TSC == __XN_TSC_TYPE_DECREMENTER */
}

static inline void xeno_arm_features_check(void)
{
#ifdef CONFIG_XENO_ARM_HW_DIRECT_TSC
	unsigned page_size;
	int err, fd;
	void *addr;

	if (__xn_tscinfo.type != -1)
		return;

	err = XENOMAI_SYSCALL2(__xn_sys_arch,
			       XENOMAI_SYSARCH_TSCINFO, &__xn_tscinfo);
	if (err) {
	  error:
		fprintf(stderr, "Xenomai: Your board/configuration does not"
			" allow tsc emulation in user-space: %d\n", err);
		exit(EXIT_FAILURE);
	}

	fd = open("/dev/mem", O_RDONLY | O_SYNC);
	if (fd == -1) {
		perror("Xenomai init: open(/dev/mem)");
		exit(EXIT_FAILURE);
	}

	page_size = sysconf(_SC_PAGESIZE);

	switch(__xn_tscinfo.type) {
#if CONFIG_XENO_ARM_HW_DIRECT_TSC == __XN_TSC_TYPE_FREERUNNING
	case __XN_TSC_TYPE_FREERUNNING: {
		unsigned long phys_addr;

		phys_addr = (unsigned long) __xn_tscinfo.u.fr.counter;
		addr = mmap(NULL, page_size, PROT_READ, MAP_SHARED,
			    fd, phys_addr & ~(page_size - 1));
		if (addr == MAP_FAILED) {
			perror("Xenomai init: mmap(/dev/mem)");
			exit(EXIT_FAILURE);
		}

		__xn_tscinfo.u.fr.counter = 
			((volatile unsigned *)
			 ((char *) addr + (phys_addr & (page_size - 1))));
		break;
	}
#elif CONFIG_XENO_ARM_HW_DIRECT_TSC == __XN_TSC_TYPE_DECREMENTER
	case __XN_TSC_TYPE_DECREMENTER: {
		unsigned long phys_addr;

		phys_addr = (unsigned long) __xn_tscinfo.u.dec.counter;
		addr = mmap(NULL, page_size, PROT_READ, MAP_SHARED,
			    fd, phys_addr & ~(page_size - 1));
		if (addr == MAP_FAILED) {
			perror("Xenomai init: mmap(/dev/mem)");
			exit(EXIT_FAILURE);
		}

		__xn_tscinfo.u.dec.counter = 
			((volatile unsigned *)
			 ((char *) addr + (phys_addr & (page_size - 1))));
		break;
	}
#endif /* CONFIG_XENO_ARM_HW_DIRECT_TSC == __XN_TSC_TYPE_DECREMENTER */
	case __XN_TSC_TYPE_NONE:
		goto error;
		
	default:
		fprintf(stderr,
			"Xenomai: kernel/user tsc emulation mismatch.\n");
		exit(EXIT_FAILURE);
	}

	if (close(fd)) {
		perror("Xenomai init: close(/dev/mem)");
		exit(EXIT_FAILURE);
	}
#endif /* CONFIG_XENO_ARM_HW_DIRECT_TSC */
}
#define xeno_arch_features_check() xeno_arm_features_check()

#endif /* !__KERNEL__ */

#endif /* !_XENO_ASM_ARM_SYSCALL_H */

// vim: ts=4 et sw=4 sts=4
