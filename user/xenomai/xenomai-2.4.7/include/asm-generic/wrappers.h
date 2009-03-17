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
 *
 * Linux wrappers.
 */

#ifndef _XENO_ASM_GENERIC_WRAPPERS_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

#include <linux/version.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/io.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

#include <linux/wrapper.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/bitops.h>
#include <linux/moduleparam.h>	/* Use the backport. */

/* Compiler */
#ifndef __attribute_const__
#define __attribute_const__	/* unimplemented */
#endif
#ifndef __restrict__
#define __restrict__		/* unimplemented */
#endif

#define module_param_named(name,var,type,mode)  module_param(var,type,mode)
#define _MODULE_PARM_STRING_charp "s"
#define compat_module_param_array(name, type, count, perm) \
	static inline void *__check_existence_##name(void) { return &name; } \
	MODULE_PARM(name, "1-" __MODULE_STRING(count) _MODULE_PARM_STRING_##type)

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

/* VM */

#define wrap_remap_vm_page(vma,from,to) ({ \
    vma->vm_flags |= VM_RESERVED; \
    remap_page_range(from,page_to_phys(vmalloc_to_page((void *)to)),PAGE_SIZE,vma->vm_page_prot); \
})
#define wrap_remap_io_page_range(vma,from,to,size,prot) ({ \
    vma->vm_flags |= VM_RESERVED; \
    remap_page_range(from,to,size,prot); \
})
#define wrap_remap_kmem_page_range(vma,from,to,size,prot) ({ \
    vma->vm_flags |= VM_RESERVED; \
    remap_page_range(from,to,size,prot); \
})
#define wrap_switch_mm(prev,next,task)	\
    switch_mm(prev,next,task,(task)->processor)
#define wrap_enter_lazy_tlb(mm,task)	\
    enter_lazy_tlb(mm,task,(task)->processor)
#define pte_offset_kernel(pmd,addr)	pte_offset(pmd,addr)
#define __copy_to_user_inatomic		__copy_to_user
#define __copy_from_user_inatomic	__copy_from_user

/* Seqfiles */
#define SEQ_START_TOKEN ((void *)1)

/* Sched and process flags */
#define MAX_RT_PRIO 100
#define task_cpu(p) ((p)->processor)
#ifndef CONFIG_PREEMPT
#define preempt_disable()  do { } while(0)
#define preempt_enable()   do { } while(0)
#endif /* !CONFIG_PREEMPT */
#ifndef SCHED_NORMAL
#define SCHED_NORMAL SCHED_OTHER
#endif /* !SCHED_NORMAL */
#define PF_NOFREEZE 0

/* Signals */
#define wrap_get_sigpending(m,p) sigandsets(m, \
					    &(p)->pending.signal, \
					    &(p)->pending.signal)
/* Wait queues */
#define DEFINE_WAIT(w) DECLARE_WAITQUEUE(w, current)
#define is_sync_wait(wait)  (!(wait) || ((wait)->task))

static inline void prepare_to_wait_exclusive(wait_queue_head_t *q,
					     wait_queue_t *wait,
					     int state)
{
	unsigned long flags;

	wait->flags |= WQ_FLAG_EXCLUSIVE;
	spin_lock_irqsave(&q->lock, flags);
	__add_wait_queue_tail(q, wait);
	if (is_sync_wait(wait))
		set_current_state(state);
	spin_unlock_irqrestore(&q->lock, flags);
}

static inline void finish_wait(wait_queue_head_t *q,
			       wait_queue_t *wait)
{
	unsigned long flags;

	__set_current_state(TASK_RUNNING);
	if (waitqueue_active(q)) {
		spin_lock_irqsave(&q->lock, flags);
		list_del_init(&wait->task_list);
		spin_unlock_irqrestore(&q->lock, flags);
	}
}

/* Workqueues. Some 2.4 ports already provide for a limited emulation
   of workqueue calls in linux/workqueue.h, except DECLARE_WORK(), so
   we define the latter here, and leave the rest in
   compat/linux/workqueue.h. */

#define __WORK_INITIALIZER(n,f,d) {				\
        .list	= { &(n).list, &(n).list },			\
	.sync = 0,						\
	.routine = (f),						\
	.data = (d),						\
}
#define DECLARE_WORK(n,f,d)      	struct tq_struct n = __WORK_INITIALIZER(n, f, d)
#define DECLARE_WORK_NODATA(n, f)	DECLARE_WORK(n, f, NULL)
#define DECLARE_WORK_FUNC(f)		void f(void *cookie)

/* Msleep is unknown before 2.4.28 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,4,28)
#define msleep(x) do {				 \
	set_current_state(TASK_UNINTERRUPTIBLE); \
	schedule_timeout((x)*(HZ/1000));         \
} while(0)
#endif

/* Shorthand for timeout setup */
#define schedule_timeout_interruptible(t) do {		\
		set_current_state(TASK_INTERRUPTIBLE);	\
		schedule_timeout(t);				\
} while(0)

#ifdef MODULE
#define try_module_get(mod) try_inc_mod_count(mod)
#define module_put(mod) __MOD_DEC_USE_COUNT(mod)
#else /* !__MODULE__ */
#define try_module_get(mod) (1)
#define module_put(mod) do { } while (0)
#endif /* !__MODULE__ */

/* Types */
typedef enum __kernel_clockid_t {
    CLOCK_REALTIME  =0,
    CLOCK_MONOTONIC =1
} clockid_t;

typedef int timer_t;
typedef int mqd_t;

/* Decls */
struct task_struct;
void show_stack(struct task_struct *task,
		unsigned long *sp);

#define atomic_cmpxchg(v, old, new) ((int)cmpxchg(&((v)->counter), old, new))

#ifndef __deprecated
#define __deprecated  __attribute__((deprecated))
#endif

#ifndef BITOP_WORD
#define BITOP_WORD(nr)	((nr) / BITS_PER_LONG)
#endif

#define __GFP_BITS_SHIFT 20
#define pgprot_noncached(p) (p)

#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0) */

#define compat_module_param_array(name, type, count, perm) \
	module_param_array(name, type, NULL, perm)

/* VM */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15) && defined(CONFIG_MMU)
#define wrap_remap_vm_page(vma,from,to) ({ \
    vma->vm_flags |= VM_RESERVED; \
    vm_insert_page(vma,from,vmalloc_to_page((void *)to)); \
})
#define wrap_remap_io_page_range(vma,from,to,size,prot)  ({		\
    (vma)->vm_page_prot = pgprot_noncached((vma)->vm_page_prot);	\
    /* Sets VM_RESERVED | VM_IO | VM_PFNMAP on the vma. */		\
    remap_pfn_range(vma,from,(to) >> PAGE_SHIFT,size,prot);		\
    })
#define wrap_remap_kmem_page_range(vma,from,to,size,prot)  ({		\
    /* Sets VM_RESERVED | VM_IO | VM_PFNMAP on the vma. */		\
    remap_pfn_range(vma,from,(to) >> PAGE_SHIFT,size,prot);		\
    })
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
/* Actually, this is a best-effort since we don't have
 * vm_insert_page(), and has the unwanted side-effet of setting the
 * VM_IO flag on the vma, which prevents GDB inspection of the mmapped
 * memory. Anyway, this legacy would only hit setups using pre-2.6.11
 * kernel revisions. */
#define wrap_remap_vm_page(vma,from,to) \
    remap_pfn_range(vma,from,page_to_pfn(vmalloc_to_page((void *)to)),PAGE_SHIFT,vma->vm_page_prot)
#define wrap_remap_io_page_range(vma,from,to,size,prot)  ({		\
    (vma)->vm_page_prot = pgprot_noncached((vma)->vm_page_prot);	\
    /* Sets VM_RESERVED | VM_IO | VM_PFNMAP on the vma. */		\
    remap_pfn_range(vma,from,(to) >> PAGE_SHIFT,size,prot);		\
    })
#define wrap_remap_kmem_page_range(vma,from,to,size,prot)  ({		\
    /* Sets VM_RESERVED | VM_IO | VM_PFNMAP on the vma. */		\
    remap_pfn_range(vma,from,(to) >> PAGE_SHIFT,size,prot);		\
    })
#else /* LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10) */
#define wrap_remap_vm_page(vma,from,to) ({ \
    vma->vm_flags |= VM_RESERVED; \
    remap_page_range(from,page_to_phys(vmalloc_to_page((void *)to)),PAGE_SIZE,vma->vm_page_prot); \
})
#define wrap_remap_io_page_range(vma,from,to,size,prot) ({	\
      vma->vm_flags |= VM_RESERVED;				\
      remap_page_range(vma,from,to,size,prot);			\
    })
#define wrap_remap_kmem_page_range(vma,from,to,size,prot) ({	\
      vma->vm_flags |= VM_RESERVED;				\
      remap_page_range(vma,from,to,size,prot);			\
    })
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15) */

#ifndef __GFP_BITS_SHIFT
#define __GFP_BITS_SHIFT 20
#endif

#define wrap_switch_mm(prev,next,task)	\
    switch_mm(prev,next,task)
#define wrap_enter_lazy_tlb(mm,task)	\
    enter_lazy_tlb(mm,task)

/* Device registration */
#if  LINUX_VERSION_CODE > KERNEL_VERSION(2,6,25)
#define DECLARE_DEVCLASS(clname) struct class *clname
#if  LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#define wrap_device_create(c,p,dt,dv,fmt,args...)	device_create(c,p,dt,fmt , ##args)
#else  /* >= 2.6.27 */
#define wrap_device_create(c,p,dt,dv,fmt,args...)	device_create(c,p,dt,dv,fmt , ##args)
#endif  /* >= 2.6.27 */
#define wrap_device_destroy	device_destroy
#define DECLARE_DEVHANDLE(devh) struct device *devh
#else /* <= 2.6.25 */
#define DECLARE_DEVHANDLE(devh) struct class_device *devh
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,13)
#define DECLARE_DEVCLASS(clname) struct class *clname
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15) || defined(gfp_zone)
/*
 * Testing that gfp_zone() exists as a macro is a gross hack used to
 * discover DENX-originated 2.6.14 kernels, for which the prototype of
 * class_device_create() already conforms to the one found in 2.6.15
 * mainline.
 */
#define wrap_device_create class_device_create
#else /* < 2.6.15 */
#define wrap_device_create(c,p,dt,dv,fmt,args...) class_device_create(c,dt,dv,fmt , ##args)
#endif /* >= 2.6.15 */
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define DECLARE_DEVCLASS(clname) struct class_simple *clname
#define wrap_device_create(c,p,dt,dv,fmt,args...) class_simple_device_add(c,dt,dv,fmt , ##args)
#define class_create class_simple_create
#define class_device_destroy(a,b) class_simple_device_remove(b)
#define class_destroy class_simple_destroy
#endif  /* >= 2.6.13 */
#define wrap_device_destroy(a, b)	class_device_destroy(a, b)
#endif  /* >= 2.6.26 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
#define atomic_cmpxchg(v, old, new) ((int)cmpxchg(&((v)->counter), old, new))
#endif /* < 2.6.15 */

/* Signals */
#define wrap_get_sigpending(m,p) sigorsets(m, \
					   &(p)->pending.signal, \
					   &(p)->signal->shared_pending.signal)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
#define DECLARE_WORK_NODATA(f, n)	DECLARE_WORK(f, n, NULL)
#define DECLARE_WORK_FUNC(f)		void f(void *cookie)
#else /* >= 2.6.20 */
#define DECLARE_WORK_NODATA(f, n)	DECLARE_WORK(f, n)
#define DECLARE_WORK_FUNC(f)		void f(struct work_struct *work)
#endif /* >= 2.6.20 */

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define IRQF_SHARED			SA_SHIRQ
#endif /* < 2.6.18 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
/* For pre-2.6.24 kernel with LTTng add-on. */
#ifdef CONFIG_MARKERS
#include <linux/marker.h>
#define trace_mark(ev, fmt, args...)	MARK(ev, fmt , ##args)
#else /* !CONFIG_MARKERS */
#define trace_mark(ev, fmt, args...)	do { } while (0)
#endif /* !CONFIG_MARKERS */
#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24) */
#include <linux/marker.h>
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define KMALLOC_MAX_SIZE 131072
#endif /* !KMALLOC_MAX_SIZE */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
static inline unsigned long hweight_long(unsigned long w)
{
#if BITS_PER_LONG == 64
	return hweight64(w);
#else /* 32 bits */
	return hweight32(w);
#endif /* 32 bits */
}

#define find_first_bit(addr, size) find_next_bit((addr), (size), 0)
unsigned long find_next_bit(const unsigned long *addr,
                            unsigned long size, unsigned long offset);
#endif /* linux version < 2.6.0 */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)

#include <linux/semaphore.h>
#include <linux/pid.h>

#define find_task_by_pid(nr)		\
  find_task_by_pid_type_ns(PIDTYPE_PID, nr, &init_pid_ns)
#define kill_proc(pid, sig, priv)	\
  kill_proc_info(sig, (priv) ? SEND_SIG_PRIV : SEND_SIG_NOINFO, pid)

#else /* LINUX_VERSION_CODE < 2.6.27 */

#include <asm/semaphore.h>
#ifndef CONFIG_MMU
#define pgprot_noncached(p) (p)
#endif /* !CONFIG_MMU */

#endif /* LINUX_VERSION_CODE < 2.6.27 */

#endif /* _XENO_ASM_GENERIC_WRAPPERS_H */
