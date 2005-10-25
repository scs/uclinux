#ifndef _BLACKFIN_SYSTEM_H
#define _BLACKFIN_SYSTEM_H

#include <linux/linkage.h>
#include <asm/blackfin.h>	
#include <linux/compiler.h>	

#define prepare_to_switch()	do { } while(0)

/*
 * switch_to(n) should switch tasks to task ptr, first checking that
 * ptr isn't the current task, in which case it does nothing.  This
 * also clears the TS-flag if the task we switched to has used the
 * math co-processor latest.
 *
 * 05/25/01 - Tony Kou (tonyko@lineo.ca)
 *
 * Adapted for BlackFin (ADI) by Ted Ma, Metrowerks, and Motorola GSG
 * Copyright (c) 2002 Arcturus Networks Inc. (www.arcturusnetworks.com)
 * Copyright (c) 2003 Metrowerks (www.metrowerks.com)
 * Copyright (c) 2004 Analog Device Inc.
 */

/**************
MACRO definitions
***************/

asmlinkage void resume(void);
#define switch_to(prev,next,last) { \
  void *_last;								\
  __asm__ __volatile__(							\
  			"r0 = %1;\n\t"					\
			"r1 = %2;\n\t"					\
			"call resume;\n\t" 				\
			"%0 = r0;\n\t"					\
		       : "=d" (_last)					\
		       : "d" (prev),					\
			 "d" (next)					\
		       : "CC", "R0", "R1", "P0", "P1");			\
  (last) = _last; 							\
}

/*
 * Interrupt configuring macros.
 */

extern volatile unsigned long irq_flags;
			
#define local_irq_enable() do {		\
	__asm__ __volatile__ (		\
		"sti %0;"		\
		::"d"(irq_flags));	\
} while (0)

#define local_irq_disable() do {		\
	int _tmp_dummy;			\
	__asm__ __volatile__ (		\
		"cli %0;"		\
		:"=d" (_tmp_dummy):);		\
} while (0)

#ifdef CONFIG_DEBUG_HWERR
#define __save_and_cli(x) do {			\
	__asm__ __volatile__ (			\
		"cli %0;\n\tsti %1;"		\
		:"=&d"(x): "d" (0x3F));		\
} while (0)
#else
#define __save_and_cli(x) do {		\
	__asm__ __volatile__ (          \
		"cli %0;"		\
		:"=&d"(x):);		\
} while (0)
#endif

#define local_save_flags(x) asm volatile ("cli %0;"     \
					  "sti %0;"     \
				    	  :"=d"(x):);

#ifdef CONFIG_DEBUG_HWERR
#define irqs_enabled_from_flags(x) (((x) & ~0x3f) != 0)
#else
#define irqs_enabled_from_flags(x) ((x) != 0x1f)
#endif

#define local_irq_restore(x) do {			\
	if (irqs_enabled_from_flags(x))			\
		local_irq_enable ();			\
} while (0)

/* For spinlocks etc */
#define local_irq_save(x) __save_and_cli(x)

#define	irqs_disabled()				\
({						\
	unsigned long flags;			\
	local_save_flags(flags);		\
	!irqs_enabled_from_flags(flags);	\
})

/*
 * Force strict CPU ordering.
 */
#define nop()  asm volatile ("nop;\n\t"::)
#define mb()   asm volatile (""   : : :"memory")
#define rmb()  asm volatile (""   : : :"memory")
#define wmb()  asm volatile (""   : : :"memory")
#define set_rmb(var, value)    do { xchg(&var, value); } while (0)
#define set_mb(var, value)     set_rmb(var, value)
#define set_wmb(var, value)    do { var = value; wmb(); } while (0)

#define read_barrier_depends() 		do { } while(0)

#ifdef CONFIG_SMP
#define smp_mb()	mb()
#define smp_rmb()	rmb()
#define smp_wmb()	wmb()
#define smp_read_barrier_depends()	read_barrier_depends() 
#else
#define smp_mb()	barrier()
#define smp_rmb()	barrier()
#define smp_wmb()	barrier()
#define smp_read_barrier_depends()	do { } while(0) 
#endif

#define xchg(ptr,x) ((__typeof__(*(ptr)))__xchg((unsigned long)(x),(ptr),sizeof(*(ptr))))
#define tas(ptr) (xchg((ptr),1))

struct __xchg_dummy { unsigned long a[100]; };
#define __xg(x) ((volatile struct __xchg_dummy *)(x))

static inline unsigned long __xchg(unsigned long x, volatile void * ptr, int size)
{
  unsigned long tmp=0;
  unsigned long flags = 0;

  local_irq_save(flags);

  switch (size) {
  case 1:
    __asm__ __volatile__
    ("%0 = b%2 (z);\n\t"
     "b%2 = %1;\n\t"
    : "=&d" (tmp) : "d" (x), "m" (*__xg(ptr)) : "memory");
    break;
  case 2:
    __asm__ __volatile__
    ("%0 = w%2 (z);\n\t"
     "w%2 = %1;\n\t"
    : "=&d" (tmp) : "d" (x), "m" (*__xg(ptr)) : "memory");
    break;
  case 4:
    __asm__ __volatile__
    ("%0 = %2;\n\t"
     "%2 = %1;\n\t"
    : "=&d" (tmp) : "d" (x), "m" (*__xg(ptr)) : "memory");
    break;
  }
  local_irq_restore(flags);
  return tmp;
}

/*
 * Atomic compare and exchange.  Compare OLD with MEM, if identical,
 * store NEW in MEM.  Return the initial value in MEM.  Success is
 * indicated by comparing RETURN with OLD.
 */
static inline unsigned long __cmpxchg(volatile void *ptr, unsigned long old,
                                      unsigned long new, int size)
{
  unsigned long tmp=0;
  unsigned long flags = 0;

  local_irq_save(flags);

  switch (size) {
  case 1:
    __asm__ __volatile__
    ("%0 = b%3 (z);\n\t"
     "CC = %1 == %0;\n\t"
     "IF !CC JUMP 1f;\n\t"
     "b%3 = %2;\n\t"
     "1:\n\t"
    : "=&d" (tmp) : "d" (old), "d" (new), "m" (*__xg(ptr)) : "memory");
    break;
  case 2:
    __asm__ __volatile__
    ("%0 = w%3 (z);\n\t"
     "CC = %1 == %0;\n\t"
     "IF !CC JUMP 1f;\n\t"
     "w%3 = %2;\n\t"
     "1:\n\t"
    : "=&d" (tmp) : "d" (old), "d" (new), "m" (*__xg(ptr)) : "memory");
    break;
  case 4:
    __asm__ __volatile__
    ("%0 = %3;\n\t"
     "CC = %1 == %0;\n\t"
     "IF !CC JUMP 1f;\n\t"
     "%3 = %2;\n\t"
     "1:\n\t"
    : "=&d" (tmp) : "d" (old), "d" (new), "m" (*__xg(ptr)) : "memory");
    break;
  }
  local_irq_restore(flags);
  return tmp;
}

#define cmpxchg(ptr,o,n)\
        ((__typeof__(*(ptr)))__cmpxchg((ptr),(unsigned long)(o),\
                                        (unsigned long)(n),sizeof(*(ptr))))
#endif /* _BLACKFIN_SYSTEM_H */
