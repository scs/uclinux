/*
 * Copyright (C) 2003,2004 Philippe Gerum <rpm@xenomai.org>.
 *
 * ARM port
 *   Copyright (C) 2005 Stelian Pop
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

#ifndef _XENO_ASM_ARM_ATOMIC_H
#define _XENO_ASM_ARM_ATOMIC_H


#ifdef __KERNEL__

#include <linux/bitops.h>
#include <asm/atomic.h>
#include <asm/system.h>
#include <asm/xenomai/features.h>

#define xnarch_atomic_xchg(ptr,v)       xchg(ptr,v)
#define xnarch_memory_barrier()  	smp_mb()

#if __LINUX_ARM_ARCH__ >= 6
static inline void atomic_set_mask(unsigned long mask, unsigned long *addr)
{
    unsigned long tmp, tmp2;

    __asm__ __volatile__("@ atomic_set_mask\n"
"1: ldrex   %0, [%2]\n"
"   orr     %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq     %1, #0\n"
"   bne     1b"
    : "=&r" (tmp), "=&r" (tmp2)
    : "r" (addr), "Ir" (mask)
    : "cc");
}
#else /* ARM_ARCH_6 */
static inline void atomic_set_mask(unsigned long mask, unsigned long *addr)
{
    unsigned long flags;

    local_irq_save_hw(flags);
    *addr |= mask;
    local_irq_restore_hw(flags);
}
#endif /* ARM_ARCH_6 */

#define xnarch_atomic_set(pcounter,i)          atomic_set(pcounter,i)
#define xnarch_atomic_get(pcounter)            atomic_read(pcounter)
#define xnarch_atomic_inc(pcounter)            atomic_inc(pcounter)
#define xnarch_atomic_dec(pcounter)            atomic_dec(pcounter)
#define xnarch_atomic_inc_and_test(pcounter)   atomic_inc_and_test(pcounter)
#define xnarch_atomic_dec_and_test(pcounter)   atomic_dec_and_test(pcounter)
#define xnarch_atomic_set_mask(pflags,mask)    atomic_set_mask(mask,pflags)
#define xnarch_atomic_clear_mask(pflags,mask)  atomic_clear_mask(mask,pflags)

typedef atomic_t atomic_counter_t;

#else /* !__KERNEL__ */

#include <asm/xenomai/features.h>
#include <asm/xenomai/syscall.h>

typedef struct { volatile int counter; } atomic_counter_t;

/*
 * This function doesn't exist, so you'll get a linker error
 * if something tries to do an invalid xchg().
 */
extern void __xnarch_xchg_called_with_bad_pointer(void);

static __inline__ unsigned long
__xchg(volatile void *ptr, unsigned long x, unsigned int size)
{
    unsigned long ret;
#if CONFIG_XENO_ARM_ARCH >= 6
    unsigned int tmp;
#endif

    if (size != 4) {
        __xnarch_xchg_called_with_bad_pointer();
        return 0;
    }

#if CONFIG_XENO_ARM_ARCH >= 6
    asm volatile("@ __xchg4\n"
"1: ldrex   %0, [%3]\n"
"   strex   %1, %2, [%3]\n"
"   teq     %1, #0\n"
"   bne     1b"
    : "=&r" (ret), "=&r" (tmp)
    : "r" (x), "r" (ptr)
    : "memory", "cc");
#elif defined(CONFIG_XENO_ARM_SA1100)
    XENOMAI_SYSCALL5(__xn_sys_arch,
                     XENOMAI_SYSARCH_XCHG, ptr, x, size, &ret);
#else
    asm volatile("@ __xchg4\n"
"   swp     %0, %1, [%2]"
    : "=&r" (ret)
    : "r" (x), "r" (ptr)
    : "memory", "cc");
#endif
    return ret;
}

#define xnarch_atomic_xchg(ptr,x) \
    ({                                                                         \
    __typeof__(*(ptr)) _x_ = (x);                                          \
    (__typeof__(*(ptr))) __xchg((ptr), (unsigned long)_x_, sizeof(*(ptr)));\
    })

/*
 * Atomic operations lifted from linux/include/asm-arm/atomic.h 
 */
#if CONFIG_XENO_ARM_ARCH >= 6
static __inline__ int atomic_add_return(int i, atomic_counter_t *v)
{
    unsigned long tmp;
    int result;

    __asm__ __volatile__("@ atomic_add_return\n"
"1: ldrex   %0, [%2]\n"
"   add     %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq     %1, #0\n"
"   bne     1b"
    : "=&r" (result), "=&r" (tmp)
    : "r" (&v->counter), "Ir" (i)
    : "cc");

    return result;
}

static __inline__ int atomic_sub_return(int i, atomic_counter_t *v)
{
    unsigned long tmp;
    int result;

    __asm__ __volatile__("@ atomic_sub_return\n"
"1: ldrex   %0, [%2]\n"
"   sub     %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq     %1, #0\n"
"   bne     1b"
    : "=&r" (result), "=&r" (tmp)
    : "r" (&v->counter), "Ir" (i)
    : "cc");

    return result;
}

static __inline__ void atomic_set_mask(unsigned long mask, unsigned long *addr)
{
    unsigned long tmp, tmp2;

    __asm__ __volatile__("@ atomic_set_mask\n"
"1: ldrex   %0, [%2]\n"
"   orr     %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq     %1, #0\n"
"   bne     1b"
    : "=&r" (tmp), "=&r" (tmp2)
    : "r" (addr), "Ir" (mask)
    : "cc");
}

static __inline__ void atomic_clear_mask(unsigned long mask, unsigned long *addr)
{
    unsigned long tmp, tmp2;

    __asm__ __volatile__("@ atomic_clear_mask\n"
"1: ldrex   %0, [%2]\n"
"   bic     %0, %0, %3\n"
"   strex   %1, %0, [%2]\n"
"   teq     %1, #0\n"
"   bne     1b"
    : "=&r" (tmp), "=&r" (tmp2)
    : "r" (addr), "Ir" (mask)
    : "cc");
}
#else /* ARM_ARCH_6 */
static __inline__ int atomic_add_return(int i, atomic_counter_t *v)
{
    int ret;

    XENOMAI_SYSCALL4(__xn_sys_arch,
                     XENOMAI_SYSARCH_ATOMIC_ADD_RETURN, i, v, &ret);
    return ret;
}

static __inline__ int atomic_sub_return(int i, atomic_counter_t *v)
{
    int ret;

    XENOMAI_SYSCALL4(__xn_sys_arch,
                     XENOMAI_SYSARCH_ATOMIC_ADD_RETURN, -i, v, &ret);
    return ret;
}

static inline void atomic_set_mask(unsigned long mask, unsigned long *addr)
{
    XENOMAI_SYSCALL3(__xn_sys_arch,
                     XENOMAI_SYSARCH_ATOMIC_SET_MASK, mask, addr);
}

static inline void atomic_clear_mask(unsigned long mask, unsigned long *addr)
{
    XENOMAI_SYSCALL3(__xn_sys_arch,
                     XENOMAI_SYSARCH_ATOMIC_CLEAR_MASK, mask, addr);
}
#endif /* ARM_ARCH_6 */

#define xnarch_memory_barrier()                 __asm__ __volatile__("": : :"memory")

#define xnarch_atomic_inc(pcounter)             (void) atomic_add_return(1, pcounter)
#define xnarch_atomic_dec_and_test(pcounter)    (atomic_sub_return(1, pcounter) == 0)
#define xnarch_atomic_set_mask(pflags,mask)     atomic_set_mask(mask,pflags)
#define xnarch_atomic_clear_mask(pflags,mask)   atomic_clear_mask(mask,pflags)

#define cpu_relax()                             xnarch_memory_barrier()
#define xnarch_read_memory_barrier()		xnarch_memory_barrier()
#define xnarch_write_memory_barrier()		xnarch_memory_barrier()

#endif /* __KERNEL__ */

typedef unsigned long atomic_flags_t;

#endif /* !_XENO_ASM_ARM_ATOMIC_H */

// vim: ts=4 et sw=4 sts=4
