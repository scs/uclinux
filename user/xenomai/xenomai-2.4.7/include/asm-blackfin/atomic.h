/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_BLACKFIN_ATOMIC_H
#define _XENO_ASM_BLACKFIN_ATOMIC_H

#ifdef __KERNEL__

#include <linux/bitops.h>
#include <asm/atomic.h>
#include <asm/system.h>

#define xnarch_atomic_xchg(ptr,v)   xchg(ptr,v)
#define xnarch_memory_barrier()     smp_mb()

#define xnarch_atomic_set(pcounter,i)          atomic_set(pcounter,i)
#define xnarch_atomic_get(pcounter)            atomic_read(pcounter)
#define xnarch_atomic_inc(pcounter)            atomic_inc(pcounter)
#define xnarch_atomic_dec(pcounter)            atomic_dec(pcounter)
#define xnarch_atomic_inc_and_test(pcounter)   atomic_inc_and_test(pcounter)
#define xnarch_atomic_dec_and_test(pcounter)   atomic_dec_and_test(pcounter)
#define xnarch_atomic_set_mask(pflags,mask)    atomic_set_mask(mask,(atomic_t*)pflags)
#define xnarch_atomic_clear_mask(pflags,mask)  atomic_clear_mask(mask,(atomic_t*)pflags)

typedef atomic_t atomic_counter_t;

#else /* !__KERNEL__ */

#include <asm/xenomai/syscall.h>

static __inline__ unsigned long xnarch_atomic_xchg(unsigned long *ptr, unsigned long x)
{
	unsigned long oldval;
	XENOMAI_SYSCALL4(__xn_sys_arch,__xn_lsys_xchg,ptr,x,&oldval);
	return oldval;
}

#define xnarch_memory_barrier()     __asm__ __volatile__("": : :"memory")

#define cpu_relax()			xnarch_memory_barrier()
#define xnarch_read_memory_barrier()	xnarch_memory_barrier()
#define xnarch_write_memory_barrier()	xnarch_memory_barrier()

#endif /* __KERNEL__ */

typedef unsigned long atomic_flags_t;

#endif /* !_XENO_ASM_BLACKFIN_ATOMIC_H */
