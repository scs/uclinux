/*
 * Copyright (C) 2003,2004 Philippe Gerum <rpm@xenomai.org>.
 * 
 * 64-bit PowerPC adoption
 *   copyright (C) 2005 Taneli Vähäkangas and Heikki Lindholm
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

#ifndef _XENO_ASM_POWERPC_ATOMIC_H
#define _XENO_ASM_POWERPC_ATOMIC_H

#ifdef __KERNEL__

#include <linux/bitops.h>
#include <linux/version.h>
#include <asm/atomic.h>
#include <asm/system.h>

#define xnarch_atomic_xchg(ptr,v)  xchg(ptr,v)
#define xnarch_memory_barrier()  smp_mb()

#ifdef CONFIG_PPC64
static __inline__ void atomic_clear_mask(unsigned long mask,
					 unsigned long *ptr)
{
    __asm__ __volatile__ ("\n\
1:	ldarx	5,0,%0 \n\
	andc	5,5,%1\n"
"	stdcx.	5,0,%0 \n\
	bne-	1b"
	: /*no output*/
	: "r" (ptr), "r" (mask)
	: "r5", "cc", "memory");
}

static __inline__ void atomic_set_mask(unsigned long mask,
				       unsigned long *ptr)
{
    __asm__ __volatile__ ("\n\
1:	ldarx	5,0,%0 \n\
	or	5,5,%1\n"
"	stdcx.	5,0,%0 \n\
	bne-	1b"
	: /*no output*/
	: "r" (ptr), "r" (mask)
	: "r5", "cc", "memory");
}
#else /* !CONFIG_PPC64 */
 /* These are defined in arch/{ppc,powerpc}/kernel/misc[_32].S on 32-bit PowerPC */
void atomic_set_mask(unsigned long mask, unsigned long *ptr);
void atomic_clear_mask(unsigned long mask, unsigned long *ptr);
#endif /* CONFIG_PPC64 */

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

#ifndef __powerpc64__
/* Always enable the work-around for 405 boards in user-space for
   now. */
#define PPC405_ERR77(ra,rb)	"dcbt " #ra "," #rb ";"
#else /* __powerpc64__ */
#define PPC405_ERR77(ra,rb)
#endif /* !__powerpc64__ */

#ifdef CONFIG_SMP
#define EIEIO_ON_SMP    "eieio\n"
#define ISYNC_ON_SMP    "\n\tisync"
#else
#define EIEIO_ON_SMP
#define ISYNC_ON_SMP
#endif

/*
 * Atomic exchange
 *
 * Changes the memory location '*ptr' to be val and returns
 * the previous value stored there.
 *
 * (lifted from linux/include/asm-powerpc/system.h)
 */

static __inline__ unsigned long 
    __xchg_u32(volatile void *p, unsigned long val)
{
    unsigned long prev;
    
    __asm__ __volatile__(
    EIEIO_ON_SMP
"1: lwarx	%0,0,%2 \n"
    PPC405_ERR77(0,%2)
"   stwcx.	%3,0,%2 \n\
    bne-	1b"
    ISYNC_ON_SMP
    : "=&r" (prev), "=m" (*(volatile unsigned int *)p)
    : "r" (p), "r" (val), "m" (*(volatile unsigned int *)p)
    : "cc", "memory");
    
    return prev;
}

#if defined(__powerpc64__)
static __inline__ unsigned long
    __xchg_u64(volatile void *p, unsigned long val)
{
    unsigned long prev;
    
    __asm__ __volatile__(
    EIEIO_ON_SMP
"1: ldarx	%0,0,%2 \n"
    PPC405_ERR77(0,%2)
"   stdcx.	%3,0,%2 \n\
    bne-	1b"
    ISYNC_ON_SMP
    : "=&r" (prev), "=m" (*(volatile unsigned long *)p)
    : "r" (p), "r" (val), "m" (*(volatile unsigned long *)p)
    : "cc", "memory");

    return prev;
}
#endif

static __inline__ unsigned long
    __xchg(volatile void *ptr, unsigned long x, unsigned int size)
{
    switch (size) {
    case 4:
	return __xchg_u32(ptr, x);
#if defined(__powerpc64__)
    case 8:
	return __xchg_u64(ptr, x);
#endif
    }
    return x;
}

#define xnarch_atomic_xchg(ptr,x) \
    ({                                                                         \
	__typeof__(*(ptr)) _x_ = (x);                                          \
	(__typeof__(*(ptr))) __xchg((ptr), (unsigned long)_x_, sizeof(*(ptr)));\
    })

#define xnarch_memory_barrier()		__asm__ __volatile__ ("sync" : : : "memory")
#define xnarch_read_memory_barrier()	xnarch_memory_barrier()	/* lwsync would do */
#define xnarch_write_memory_barrier()	xnarch_memory_barrier()
#define cpu_relax()			xnarch_memory_barrier()

#endif /* __KERNEL__ */

typedef unsigned long atomic_flags_t;

#endif /* !_XENO_ASM_POWERPC_ATOMIC_H */
