/*
 * Copyright &copy; 2003 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_IA64_ATOMIC_H
#define _XENO_ASM_IA64_ATOMIC_H

#ifdef __KERNEL__

#include <linux/bitops.h>
#include <asm/atomic.h>
#include <asm/system.h>

typedef atomic_t atomic_counter_t;

#define xnarch_atomic_xchg(ptr,v)		xchg(ptr,v)

#define xnarch_atomic_set(pcounter,i)          atomic_set(pcounter,i)
#define xnarch_atomic_get(pcounter)            atomic_read(pcounter)
#define xnarch_atomic_inc(pcounter)            atomic_inc(pcounter)
#define xnarch_atomic_dec(pcounter)            atomic_dec(pcounter)
#define xnarch_atomic_inc_and_test(pcounter)   atomic_inc_and_test(pcounter)
#define xnarch_atomic_dec_and_test(pcounter)   atomic_dec_and_test(pcounter)
#define xnarch_memory_barrier()                smp_mb()

static inline void atomic_set_mask(unsigned mask, unsigned long *addr)
{
    uint32_t old, new;
    volatile uint32_t *m;
        
    m = (volatile uint32_t *) addr;
    do {
        old = *m;
        new = old | mask;
    } while (cmpxchg(m, old, new) != old);
}

#define xnarch_atomic_set_mask(pflags,mask)    atomic_set_mask(mask,pflags)

static inline void atomic_clear_mask(unsigned mask, unsigned long *addr)
{
    uint32_t old, new;
    volatile uint32_t *m;
        
    m = (volatile uint32_t *) addr;
    do {
        old = *m;
        new = old & ~mask;
    } while (cmpxchg(m, old, new) != old);
}

#define xnarch_atomic_clear_mask(pflags,mask)  atomic_clear_mask(mask,pflags)

#else /* !__KERNEL__ */

#include <sys/types.h>
#include <stdint.h>

#define fls(x) generic_fls(x)

typedef struct { volatile int counter; } atomic_counter_t;

#define atomic_set(v,i)         (((v)->counter) = (i))
#define atomic_read(v)	        ((v)->counter)
#define atomic_inc(v)	        atomic_add(1, (v))
#define atomic_dec_and_test(v)	(atomic_sub_return(1, (v)) == 0)

static inline unsigned long xnarch_atomic_xchg (volatile void *ptr,
						unsigned long x)
{
	uint64_t ia64_intri_res;						
	asm __volatile ("xchg8 %0=[%1],%2" : "=r" (ia64_intri_res)	
			    : "r" (ptr), "r" (x) : "memory");		
	return ia64_intri_res;
}

#define do_cmpxchg4_acq(ptr, new, old)							\
({											\
	uint64_t ia64_intri_res;							\
	asm volatile ("mov ar.ccv=%0;;" :: "rO"((uint64_t)old));			\
	asm volatile ("cmpxchg4.acq %0=[%1],%2,ar.ccv":					\
			      "=r"(ia64_intri_res) : "r"(ptr), "r"(new) : "memory");	\
	ia64_intri_res;									\
})

static inline int atomic_add (int i, atomic_counter_t *v)
{
	int32_t old, new;

	do {
		old = atomic_read(v);
		new = old + i;
	} while (do_cmpxchg4_acq(v, new, old) != old);
	return new;
}

static inline int atomic_sub_return (int i, atomic_counter_t *v)
{
	int32_t old, new;

	do {
		old = atomic_read(v);
		new = old - i;
	} while (do_cmpxchg4_acq(v, new, old) != old);
	return new;
}

#define xnarch_memory_barrier()  	asm volatile ("mf" ::: "memory")

#define cpu_relax()			asm volatile ("hint @pause" ::: "memory")
#define xnarch_read_memory_barrier()	xnarch_memory_barrier()
#define xnarch_write_memory_barrier()	xnarch_memory_barrier()

#endif /* __KERNEL__ */

typedef unsigned long atomic_flags_t;

/* These functions actually only work on the first 32 bits word of the
   64 bits status word whose address is addr. But the bit fields used
   by the nucleus have to work on 32 bits architectures anyway. */
#define xnarch_atomic_set(pcounter,i)          atomic_set(pcounter,i)
#define xnarch_atomic_inc(pcounter)            atomic_inc(pcounter)
#define xnarch_atomic_dec_and_test(pcounter)   atomic_dec_and_test(pcounter)

#endif /* !_XENO_ASM_IA64_ATOMIC_H */
