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

#ifndef _XENO_ASM_X86_WRAPPERS_32_H
#define _XENO_ASM_X86_WRAPPERS_32_H
#define _XENO_ASM_X86_WRAPPERS_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

#include <asm-generic/xenomai/wrappers.h> /* Read the generic portion. */
#include <linux/interrupt.h>
#include <asm/processor.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

#define CONFIG_MMU 1

#define wrap_phys_mem_prot(filp,pfn,size,prot)  (prot)

#define wrap_range_ok(task,addr,size) ({ \
	unsigned long flag,sum; \
	asm("addl %3,%1 ; sbbl %0,%0; cmpl %1,%4; sbbl $0,%0" \
		:"=&r" (flag), "=r" (sum) \
	        :"1" (addr),"g" ((int)(size)),"g" ((task)->addr_limit.seg)); \
	flag == 0; })

#define wrap_test_fpu_used(task)  \
   ((task)->flags & PF_USEDFPU)
#define wrap_set_fpu_used(task)   \
do {				  \
    (task)->flags |= PF_USEDFPU;  \
} while(0)
#define wrap_clear_fpu_used(task) \
do {				  \
    (task)->flags &= ~PF_USEDFPU; \
} while(0)

/* Since the job is done in the vanilla __switch_to() we call, the
   following routine is a nop on 2.4 kernels. */
#define wrap_switch_iobitmap(p,cpu)   do { } while(0)

#define wrap_strncpy_from_user(dstP,srcP,n) __strncpy_from_user(dstP,srcP,n)

/**
 * fls - find last bit set
 * @x: the word to search
 *
 * This is defined the same way as
 * the libc and compiler builtin ffs routines, therefore
 * differs in spirit from ffz (man ffs).
 */
static inline int fls(int x)
{
	int r;

	__asm__("bsrl %1,%0\n\t"
		"jnz 1f\n\t"
		"movl $-1,%0\n"
		"1:" : "=r" (r) : "rm" (x));
	return r+1;
}

#else /*  LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)  */

#define wrap_phys_mem_prot(filp,pfn,size,prot)  (prot)

#define wrap_range_ok(task,addr,size) ({ \
	unsigned long flag,sum; \
	asm("addl %3,%1 ; sbbl %0,%0; cmpl %1,%4; sbbl $0,%0" \
		:"=&r" (flag), "=r" (sum) \
	        :"1" (addr),"g" ((int)(size)),"g" (task_thread_info(task)->addr_limit.seg)); \
	flag == 0; })

#define wrap_test_fpu_used(task)  \
   (task_thread_info(task)->status & TS_USEDFPU)
#define wrap_set_fpu_used(task)   \
do { \
   task_thread_info(task)->status |= TS_USEDFPU; \
} while(0)
#define wrap_clear_fpu_used(task) \
do { \
   task_thread_info(task)->status &= ~TS_USEDFPU; \
} while(0)


#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define wrap_iobitmap_base(tss)  (tss)->io_bitmap_base
#else
#define wrap_iobitmap_base(tss)  (tss)->x86_tss.io_bitmap_base
#endif

static inline void wrap_switch_iobitmap (struct task_struct *p, int cpu)
{
    struct thread_struct *thread = &p->thread;

    if (thread->io_bitmap_ptr) {

    	struct tss_struct *tss = &per_cpu(init_tss, cpu);

	if (wrap_iobitmap_base(tss) == INVALID_IO_BITMAP_OFFSET_LAZY) {
                
		memcpy(tss->io_bitmap, thread->io_bitmap_ptr, thread->io_bitmap_max);

		if (thread->io_bitmap_max < tss->io_bitmap_max)
		    memset((char *) tss->io_bitmap +
			   thread->io_bitmap_max, 0xff,
			   tss->io_bitmap_max - thread->io_bitmap_max);
	
		tss->io_bitmap_max = thread->io_bitmap_max;
		wrap_iobitmap_base(tss) = IO_BITMAP_OFFSET;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15)
		tss->io_bitmap_owner = thread;
#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15) */
	}
    }
}

#define wrap_strncpy_from_user(dstP,srcP,n) rthal_strncpy_from_user(dstP,srcP,n)

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0) */

#define rthal_irq_descp(irq)		(irq_desc + irq)
#define rthal_irq_desc_status(irq)	(rthal_irq_descp(irq)->status)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
#define rthal_irq_chip_enable(irq)					\
	({								\
		int __err__ = 0;					\
		if (rthal_irq_descp(irq)->handler == NULL)		\
			__err__ = -ENODEV;				\
		else							\
			rthal_irq_descp(irq)->handler->enable(irq);	\
		__err__;						\
	})
#define rthal_irq_chip_disable(irq)					\
	({								\
		int __err__ = 0;					\
		if (rthal_irq_descp(irq)->handler == NULL)		\
			__err__ = -ENODEV;				\
		else							\
			rthal_irq_descp(irq)->handler->disable(irq);	\
		__err__;						\
	})
typedef irqreturn_t (*rthal_irq_host_handler_t)(int irq,
						void *dev_id,
						struct pt_regs *regs);

#define DECLARE_LINUX_IRQ_HANDLER(fn, irq, dev_id)		\
	irqreturn_t fn(int irq, void *dev_id, struct pt_regs *regs)

#define rthal_irq_chip_end(irq)	rthal_irq_chip_enable(irq)
#else /* >= 2.6.19 */
#define rthal_irq_chip_enable(irq)   ({ rthal_irq_descp(irq)->chip->unmask(irq); 0; })
#define rthal_irq_chip_disable(irq)  ({ rthal_irq_descp(irq)->chip->mask(irq); 0; })
#define rthal_irq_chip_end(irq)      ({ rthal_irq_descp(irq)->ipipe_end(irq, rthal_irq_descp(irq)); 0; })
typedef irq_handler_t rthal_irq_host_handler_t;

#define DECLARE_LINUX_IRQ_HANDLER(fn, irq, dev_id)	\
	irqreturn_t fn(int irq, void *dev_id)

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define x86reg_origax	orig_ax
#define x86reg_ax	ax
#define x86reg_bx	bx
#define x86reg_cx	cx
#define x86reg_dx	dx
#define x86reg_si	si
#define x86reg_di	di
#define x86reg_sp	sp
#define x86reg_bp	bp
#define x86reg_ip	ip
#else
#define x86reg_origax	orig_eax
#define x86reg_ax	eax
#define x86reg_bx	ebx
#define x86reg_cx	ecx
#define x86reg_dx	edx
#define x86reg_si	esi
#define x86reg_di	edi
#define x86reg_sp	esp
#define x86reg_bp	ebp
#define x86reg_ip	eip
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,25)
typedef union i387_union x86_fpustate;
#define x86_fpustate_ptr(t) (&(t)->i387)
#else
typedef union thread_xstate x86_fpustate;
#define x86_fpustate_ptr(t) ((t)->xstate)
#endif

#endif /* _XENO_ASM_X86_WRAPPERS_32_H */
