/*
 * Copyright (C) 2001,2002,2003,2004,2005 Philippe Gerum <rpm@xenomai.org>.
 * Copyright (C) 2004,2005 Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
 *
 * Xenomai is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#ifndef _XENO_ASM_GENERIC_SYSTEM_H
#define _XENO_ASM_GENERIC_SYSTEM_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <asm/uaccess.h>
#include <asm/param.h>
#include <asm/mmu_context.h>
#include <asm/ptrace.h>
#include <asm/xenomai/hal.h>
#include <asm/xenomai/atomic.h>
#include <nucleus/shadow.h>

/* debug support */
#include <nucleus/assert.h>

#ifndef CONFIG_XENO_OPT_DEBUG_NUCLEUS
#define CONFIG_XENO_OPT_DEBUG_NUCLEUS 0
#endif

/* Time base export */
#define xnarch_declare_tbase(base)		do { } while(0)

/* Tracer interface */
#define xnarch_trace_max_begin(v)		rthal_trace_max_begin(v)
#define xnarch_trace_max_end(v)		rthal_trace_max_end(v)
#define xnarch_trace_max_reset()		rthal_trace_max_reset()
#define xnarch_trace_user_start()		rthal_trace_user_start()
#define xnarch_trace_user_stop(v)		rthal_trace_user_stop(v)
#define xnarch_trace_user_freeze(v, once) 	rthal_trace_user_freeze(v, once)
#define xnarch_trace_special(id, v)		rthal_trace_special(id, v)
#define xnarch_trace_special_u64(id, v)	rthal_trace_special_u64(id, v)
#define xnarch_trace_pid(pid, prio)		rthal_trace_pid(pid, prio)
#define xnarch_trace_panic_freeze()		rthal_trace_panic_freeze()
#define xnarch_trace_panic_dump()		rthal_trace_panic_dump()

#ifndef xnarch_fault_um
#define xnarch_fault_um(fi) user_mode(fi->regs)
#endif

#define module_param_value(parm) (parm)

typedef unsigned long spl_t;

#define splhigh(x)  rthal_local_irq_save(x)
#ifdef CONFIG_SMP
#define splexit(x)  rthal_local_irq_restore((x) & 1)
#else /* !CONFIG_SMP */
#define splexit(x)  rthal_local_irq_restore(x)
#endif /* !CONFIG_SMP */
#define splnone()   rthal_local_irq_enable()
#define spltest()   rthal_local_irq_test()
#define splget(x)   rthal_local_irq_flags(x)

#if defined(CONFIG_SMP) && defined(CONFIG_XENO_OPT_DEBUG)
typedef struct {

        unsigned long long spin_time;
        unsigned long long lock_time;
        const char *file;
        const char *function;
        unsigned line;

} xnlockinfo_t;

typedef struct {

    atomic_t owner;
    const char *file;
    const char *function;
    unsigned line;
    int cpu;
    unsigned long long spin_time;
    unsigned long long lock_date;

} xnlock_t;

#define XNARCH_LOCK_UNLOCKED (xnlock_t) {	\
	{ ~0 },					\
	NULL,					\
	NULL,					\
	0,					\
	-1,					\
	0LL,					\
	0LL,					\
}

#else /* !(CONFIG_SMP && CONFIG_XENO_OPT_DEBUG) */

typedef struct { atomic_t owner; } xnlock_t;

#define XNARCH_LOCK_UNLOCKED (xnlock_t) { { ~0 } }
#endif /* !(CONFIG_SMP && CONFIG_XENO_OPT_DEBUG) */

#define XNARCH_NR_CPUS               RTHAL_NR_CPUS

#define XNARCH_NR_IRQS               RTHAL_NR_IRQS
#define XNARCH_TIMER_IRQ	     RTHAL_TIMER_IRQ
#define XNARCH_TIMER_DEVICE          RTHAL_TIMER_DEVICE
#define XNARCH_CLOCK_DEVICE          RTHAL_CLOCK_DEVICE

#define XNARCH_ROOT_STACKSZ   0	/* Only a placeholder -- no stack */

#define XNARCH_PROMPT "Xenomai: "
#define xnarch_loginfo(fmt,args...)  printk(KERN_INFO XNARCH_PROMPT fmt , ##args)
#define xnarch_logwarn(fmt,args...)  printk(KERN_WARNING XNARCH_PROMPT fmt , ##args)
#define xnarch_logerr(fmt,args...)   printk(KERN_ERR XNARCH_PROMPT fmt , ##args)
#define xnarch_printf(fmt,args...)   printk(KERN_INFO XNARCH_PROMPT fmt , ##args)

typedef cpumask_t xnarch_cpumask_t;

#ifdef CONFIG_SMP
#define xnarch_cpu_online_map            cpu_online_map
#else
#define xnarch_cpu_online_map		 cpumask_of_cpu(0)
#endif
#define xnarch_num_online_cpus()          num_online_cpus()
#define xnarch_cpu_set(cpu, mask)         cpu_set(cpu, (mask))
#define xnarch_cpu_clear(cpu, mask)       cpu_clear(cpu, (mask))
#define xnarch_cpus_clear(mask)           cpus_clear(mask)
#define xnarch_cpu_isset(cpu, mask)       cpu_isset(cpu, (mask))
#define xnarch_cpus_and(dst, src1, src2)  cpus_and((dst), (src1), (src2))
#define xnarch_cpus_equal(mask1, mask2)   cpus_equal((mask1), (mask2))
#define xnarch_cpus_empty(mask)           cpus_empty(mask)
#define xnarch_cpumask_of_cpu(cpu)        cpumask_of_cpu(cpu)
#define xnarch_cpu_test_and_set(cpu,mask) cpu_test_and_set(cpu, (mask))

#define xnarch_first_cpu(mask)            first_cpu(mask)
#define XNARCH_CPU_MASK_ALL               CPU_MASK_ALL

typedef struct xnarch_heapcb {

    atomic_t numaps;	/* # of active user-space mappings. */

    int kmflags;	/* Kernel memory flags (0 if vmalloc()). */

    void *heapbase;	/* Shared heap memory base. */

} xnarch_heapcb_t;

#ifdef __cplusplus
extern "C" {
#endif

unsigned long long xnarch_get_host_time(void);

long long xnarch_tsc_to_ns(long long ts);

static inline long long xnarch_tsc_to_ns_rounded(long long ts)
{
    return (xnarch_llimd(ts, 1000000000, RTHAL_CPU_FREQ/2) + 1) / 2;
}

long long xnarch_ns_to_tsc(long long ns);

unsigned long long xnarch_get_cpu_time(void);

static inline unsigned long long xnarch_get_cpu_freq(void)
{
    return RTHAL_CPU_FREQ;
}

static inline unsigned xnarch_current_cpu(void)
{
    return rthal_processor_id();
}

#define xnarch_halt(emsg) \
do { \
    rthal_emergency_console(); \
    xnarch_logerr("fatal: %s\n",emsg); \
    show_stack(NULL,NULL);			\
    xnarch_trace_panic_dump();			\
    for (;;) cpu_relax();			\
} while(0)

static inline int xnarch_setimask (int imask)
{
    spl_t s;
    splhigh(s);
    splexit(!!imask);
    return !!s;
}

#ifdef CONFIG_SMP

#if XENO_DEBUG(NUCLEUS)
#define xnlock_get(lock) \
    __xnlock_get(lock, __FILE__, __LINE__,__FUNCTION__)
#define xnlock_get_irqsave(lock,x) \
    ((x) = __xnlock_get_irqsave(lock, __FILE__, __LINE__,__FUNCTION__))
#else /* !XENO_DEBUG(NUCLEUS) */
#define xnlock_get(lock)            __xnlock_get(lock)
#define xnlock_get_irqsave(lock,x)  ((x) = __xnlock_get_irqsave(lock))
#endif /* !XENO_DEBUG(NUCLEUS) */
#define xnlock_clear_irqoff(lock)   xnlock_put_irqrestore(lock,1)
#define xnlock_clear_irqon(lock)    xnlock_put_irqrestore(lock,0)

static inline void xnlock_init (xnlock_t *lock)
{
    *lock = XNARCH_LOCK_UNLOCKED;
}

#define DECLARE_XNLOCK(lock)		xnlock_t lock
#define DECLARE_EXTERN_XNLOCK(lock)	extern xnlock_t lock
#define DEFINE_XNLOCK(lock)		xnlock_t lock = XNARCH_LOCK_UNLOCKED
#define DEFINE_PRIVATE_XNLOCK(lock)	static DEFINE_XNLOCK(lock)

#if XENO_DEBUG(NUCLEUS)

#define XNARCH_DEBUG_SPIN_LIMIT 3000000

static inline int __xnlock_get (xnlock_t *lock,
				 const char *file,
				 unsigned line,
				 const char *function)
{
    unsigned spin_count = 0;
#else /* !XENO_DEBUG(NUCLEUS) */
static inline int __xnlock_get (xnlock_t *lock)
{
#endif /* !XENO_DEBUG(NUCLEUS) */
    int recursing;

    recursing = (atomic_read(&lock->owner) == rthal_processor_id());
    if (!recursing) {
#if XENO_DEBUG(NUCLEUS)
	    unsigned long long lock_date = rthal_rdtsc();
#endif /* XENO_DEBUG(NUCLEUS) */
	    while(atomic_cmpxchg(&lock->owner, ~0, rthal_processor_id()) != ~0)
		    do {
			    cpu_relax();

#if XENO_DEBUG(NUCLEUS)
			    if (++spin_count == XNARCH_DEBUG_SPIN_LIMIT) {
				    rthal_emergency_console();
				    printk(KERN_ERR
					   "Xenomai: stuck on nucleus lock %p\n"
					   "       waiter = %s:%u (%s(), CPU #%d)\n"
					   "       owner  = %s:%u (%s(), CPU #%d)\n",
					   lock,file,line,function,rthal_processor_id(),
					   lock->file,lock->line,lock->function,lock->cpu);
				    show_stack(NULL,NULL);
				    for (;;)
					    cpu_relax();
			    }
#endif /* XENO_DEBUG(NUCLEUS) */
		    } while(atomic_read(&lock->owner) != ~0);

#if XENO_DEBUG(NUCLEUS)
	    lock->spin_time = rthal_rdtsc() - lock_date;
	    lock->lock_date = lock_date;
	    lock->file = file;
	    lock->function = function;
	    lock->line = line;
	    lock->cpu = rthal_processor_id();
#endif /* XENO_DEBUG(NUCLEUS) */
        }

    return recursing;
}

static inline void xnlock_put (xnlock_t *lock)
{
	if (likely(atomic_read(&lock->owner) == rthal_processor_id())) {

#if XENO_DEBUG(NUCLEUS)
	    extern xnlockinfo_t xnlock_stats[];

	    unsigned long long lock_time = rthal_rdtsc() - lock->lock_date;
	    int cpu = rthal_processor_id();

	    if (lock_time > xnlock_stats[cpu].lock_time) {
		    xnlock_stats[cpu].lock_time = lock_time;
		    xnlock_stats[cpu].spin_time = lock->spin_time;
		    xnlock_stats[cpu].file = lock->file;
		    xnlock_stats[cpu].function = lock->function;
		    xnlock_stats[cpu].line = lock->line;
	    }
#endif /* XENO_DEBUG(NUCLEUS) */
	    atomic_set(&lock->owner, ~0);
    }
#if XENO_DEBUG(NUCLEUS)
    else {
	    rthal_emergency_console();
	    printk(KERN_ERR
		   "Xenomai: unlocking unlocked nucleus lock %p\n"
		   "       owner  = %s:%u (%s(), CPU #%d)\n",
		   lock,lock->file,lock->line,lock->function,lock->cpu);
	    show_stack(NULL,NULL);
	    for (;;)
		    cpu_relax();
    }
#endif /* XENO_DEBUG(NUCLEUS) */
}

#if XENO_DEBUG(NUCLEUS)

static inline spl_t __xnlock_get_irqsave (xnlock_t *lock,
                                          const char *file,
                                          unsigned line,
                                          const char *function)
{
#else /* !XENO_DEBUG(NUCLEUS) */
static inline spl_t __xnlock_get_irqsave (xnlock_t *lock)
{
#endif /* !XENO_DEBUG(NUCLEUS) */
    unsigned long flags;

    rthal_local_irq_save(flags);

#if XENO_DEBUG(NUCLEUS)
    if (__xnlock_get(lock, file, line, function))
	    flags |= 2;
#else /* !XENO_DEBUG(NUCLEUS) */
    if (__xnlock_get(lock))
	    flags |= 2;
#endif /* !XENO_DEBUG(NUCLEUS) */
	
    return flags;
}

static inline void xnlock_put_irqrestore (xnlock_t *lock, spl_t flags)
{
    if (!(flags & 2))
	    xnlock_put(lock);

    rthal_local_irq_restore(flags & 1);
}

static inline int xnarch_send_ipi (xnarch_cpumask_t cpumask)
{
    return rthal_send_ipi(RTHAL_SERVICE_IPI0, cpumask);
}

static inline int xnlock_is_owner(xnlock_t *lock)
{
	return atomic_read(&lock->owner) == xnarch_current_cpu();
}

#else /* !CONFIG_SMP */

#define xnlock_init(lock)              do { } while(0)
#define xnlock_get(lock)               do { } while(0)
#define xnlock_put(lock)               do { } while(0)
#define xnlock_get_irqsave(lock,x)     rthal_local_irq_save(x)
#define xnlock_put_irqrestore(lock,x)  rthal_local_irq_restore(x)
#define xnlock_clear_irqoff(lock)      rthal_local_irq_disable()
#define xnlock_clear_irqon(lock)       rthal_local_irq_enable()
#define xnlock_is_owner(lock)	       1

#define DECLARE_XNLOCK(lock)
#define DECLARE_EXTERN_XNLOCK(lock)
#define DEFINE_XNLOCK(lock)
#define DEFINE_PRIVATE_XNLOCK(lock)

static inline int xnarch_send_ipi (xnarch_cpumask_t cpumask)
{
    return 0;
}

#endif /* !CONFIG_SMP */

#define xnlock_sync_irq(lock, x)			\
	do {						\
		xnlock_put_irqrestore(lock, x);		\
		xnlock_get_irqsave(lock, x);		\
	} while(0)

static inline int xnarch_remap_vm_page(struct vm_area_struct *vma,
				       unsigned long from,
				       unsigned long to)
{
    return wrap_remap_vm_page(vma,from,to);
}

static inline int xnarch_remap_io_page_range(struct vm_area_struct *vma,
					     unsigned long from,
					     unsigned long to,
					     unsigned long size,
					     pgprot_t prot)
{
    return wrap_remap_io_page_range(vma,from,to,size,prot);
}

#ifndef xnarch_hisyscall_entry
static inline void xnarch_hisyscall_entry(void)	{ }
#endif

#ifdef __cplusplus
}
#endif

/* Dashboard and graph control. */
#define XNARCH_DECL_DISPLAY_CONTEXT();
#define xnarch_init_display_context(obj)
#define xnarch_create_display(obj,name,tag)
#define xnarch_delete_display(obj)
#define xnarch_post_graph(obj,state)
#define xnarch_post_graph_if(obj,state,cond)

#endif /* !_XENO_ASM_GENERIC_SYSTEM_H */
