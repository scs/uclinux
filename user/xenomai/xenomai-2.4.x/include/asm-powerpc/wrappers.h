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

#ifndef _XENO_ASM_POWERPC_WRAPPERS_H
#define _XENO_ASM_POWERPC_WRAPPERS_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

#include <asm-generic/xenomai/wrappers.h>	/* Read the generic portion. */
#include <linux/interrupt.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)

#define CONFIG_MMU 1

#define wrap_phys_mem_prot(filp,pfn,size,prot)  \
  __pgprot(pgprot_val(prot) | _PAGE_NO_CACHE | _PAGE_GUARDED)

#define atomic_inc_and_test(v) (atomic_inc_return(v) == 0)
#define show_stack(p,sp)       print_backtrace(sp)	/* Only works for current. */

#define wrap_range_ok(task,addr,size) \
    (segment_eq((task)->thread.fs, KERNEL_DS) || __user_ok((unsigned long)(addr),(size)))

/*
 * fls: find last (most-significant) bit set.
 * Note fls(0) = 0, fls(1) = 1, fls(0x80000000) = 32.
 */
static __inline__ int fls(unsigned int x)
{
	int lz;

	asm ("cntlzw %0,%1" : "=r" (lz) : "r" (x));
	return 32 - lz;
}

#else /*  LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)  */

#define wrap_phys_mem_prot(filp,pfn,size,prot) \
  phys_mem_access_prot(filp, pfn, size, prot)

#ifdef CONFIG_PPC64
#define wrap_range_ok(task,addr,size) \
    __access_ok(((__force unsigned long)(addr)),(size),(task->thread.fs))
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#define arch_leave_lazy_mmu_mode()  flush_tlb_pending()
#endif
#else /* !CONFIG_PPC64 */
#define wrap_range_ok(task,addr,size) \
    ((unsigned long)(addr) <= (task)->thread.fs.seg			\
     && ((size) == 0 || (size) - 1 <= (task)->thread.fs.seg - (unsigned long)(addr)))
#endif /* !CONFIG_PPC64 */

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0) */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)

#define wrap_put_user(src,dstP)           __put_user(src,dstP)
#define wrap_get_user(dst,srcP)           __get_user(dst,srcP)

#else /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15) */

/* from linux/include/asm-powerpc/uaccess.h */
#define wrap_get_user(x, ptr)					\
({								\
	int __gu_size = sizeof(*(ptr));				\
	long __gu_err;						\
	unsigned long __gu_val;					\
	const __typeof__(*(ptr)) __user *__gu_addr = (ptr);	\
	__chk_user_ptr(ptr);					\
	__get_user_size(__gu_val, __gu_addr, gu_size, __gu_err);\
	(x) = (__typeof__(*(ptr)))__gu_val;			\
	__gu_err;						\
})

#define wrap_put_user(x, ptr)					\
({								\
	int __pu_size = sizeof(*(ptr));				\
	long __pu_err;						\
	__typeof__(*(ptr)) __user *__pu_addr = (ptr);		\
	__chk_user_ptr(ptr);					\
	__put_user_size((__typeof__(*(ptr)))(x),		\
			__pu_addr, __pu_size, __pu_err);	\
	__pu_err;						\
})

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15) */

#define rthal_irq_descp(irq)		(irq_desc + irq)
#define rthal_irq_desc_status(irq)	(rthal_irq_descp(irq)->status)

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define rthal_irq_handlerp(irq) rthal_irq_descp(irq)->handler
#else
#define rthal_irq_handlerp(irq) rthal_irq_descp(irq)->chip
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
typedef irqreturn_t (*rthal_irq_host_handler_t)(int irq,
						void *dev_id,
						struct pt_regs *regs);
#else
typedef irq_handler_t rthal_irq_host_handler_t;
#endif


#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,19)
#define rthal_irq_chip_enable(irq)					\
	({								\
		int __err__ = 0;					\
		if (rthal_irq_handlerp(irq) == NULL ||			\
		    rthal_irq_handlerp(irq)->enable == NULL)		\
			__err__ = -ENODEV;				\
		else							\
			rthal_irq_handlerp(irq)->enable(irq);		\
		__err__;						\
	})
#define rthal_irq_chip_disable(irq)					\
	({								\
		int __err__ = 0;					\
		if (rthal_irq_handlerp(irq) == NULL ||			\
		    rthal_irq_handlerp(irq)->disable == NULL)		\
			__err__ = -ENODEV;				\
		else							\
			rthal_irq_handlerp(irq)->disable(irq);		\
		__err__;						\
	})
#define rthal_irq_chip_end(irq)						\
	({									\
		int __err__ = 0;						\
		if (rthal_irq_handlerp(irq) != NULL) {				\
			if (rthal_irq_handlerp(irq)->end != NULL)		\
				rthal_irq_handlerp(irq)->end(irq); 		\
			else if	(rthal_irq_handlerp(irq)->enable != NULL) 	\
				rthal_irq_handlerp(irq)->enable(irq); 		\
		} else								\
			__err__ = -ENODEV;					\
		__err__;							\
	})
#else /* > 2.6.19 */
#define rthal_irq_chip_enable(irq)					\
	({								\
		int __err__ = 0;					\
		if (unlikely(rthal_irq_handlerp(irq)->unmask == NULL))	\
			__err__ = -ENODEV;				\
		else							\
			rthal_irq_handlerp(irq)->unmask(irq);		\
		__err__;						\
	})
#define rthal_irq_chip_disable(irq)					\
	({								\
		int __err__ = 0;					\
		if (rthal_irq_handlerp(irq)->mask == NULL)		\
			__err__ = -ENODEV;				\
		else							\
			rthal_irq_handlerp(irq)->mask(irq);		\
		__err__;						\
	})
#define rthal_irq_chip_end(irq)      ({ rthal_irq_descp(irq)->ipipe_end(irq, rthal_irq_descp(irq)); 0; })
#endif

#endif /* _XENO_ASM_POWERPC_WRAPPERS_H */
