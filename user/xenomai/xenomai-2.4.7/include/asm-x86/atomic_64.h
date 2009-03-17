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

#ifndef _XENO_ASM_X86_ATOMIC_64_H
#define _XENO_ASM_X86_ATOMIC_64_H
#define _XENO_ASM_X86_ATOMIC_H

#ifdef __KERNEL__

#include <linux/bitops.h>
#include <asm/atomic.h>
#include <asm/system.h>

#define xnarch_atomic_set(pcounter,i)          atomic_set(pcounter,i)
#define xnarch_atomic_get(pcounter)            atomic_read(pcounter)
#define xnarch_atomic_inc(pcounter)            atomic_inc(pcounter)
#define xnarch_atomic_dec(pcounter)            atomic_dec(pcounter)
#define xnarch_atomic_inc_and_test(pcounter)  atomic_inc_and_test(pcounter)
#define xnarch_atomic_dec_and_test(pcounter)  atomic_dec_and_test(pcounter)
#define xnarch_atomic_set_mask(pflags,mask)    atomic_set_mask(mask,pflags)
#define xnarch_atomic_clear_mask(pflags,mask) atomic_clear_mask(mask,pflags)
#define xnarch_atomic_xchg(ptr,x)              xchg(ptr,x)

#define xnarch_memory_barrier()  smp_mb()

typedef atomic_t atomic_counter_t;

#else /* !__KERNEL__ */

#define __xeno_xg(x) ((volatile long *)(x))

static inline unsigned long xnarch_atomic_xchg (volatile void *ptr,
						unsigned long x)
{
	__asm__ __volatile__("xchgq %0,%1"
			     :"=r" (x)
			     :"m" (*__xeno_xg(ptr)), "0" (x)
			     :"memory");
	return x;
}

#define xnarch_memory_barrier()		asm volatile("mfence":::"memory")
#define xnarch_read_memory_barrier()	asm volatile("lfence":::"memory")
#define xnarch_write_memory_barrier()	xnarch_memory_barrier()

#endif /* __KERNEL__ */

typedef unsigned long atomic_flags_t;

#endif /* !_XENO_ASM_X86_ATOMIC_64_H */
