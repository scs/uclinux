/*
 * Copyright (C) 2001,2002,2003,2004 Philippe Gerum <rpm@xenomai.org>.
 *
 * ARM port
 *   Copyright (C) 2005 Stelian Pop
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

#ifndef _XENO_ASM_ARM_BITS_THREAD_H
#define _XENO_ASM_ARM_BITS_THREAD_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

static inline unsigned long xnarch_current_domain_access_control(void)
{
	unsigned long domain_access_control;
	asm("mrc p15, 0, %0, c3, c0":"=r"(domain_access_control));
	return domain_access_control;
}

static inline void xnarch_init_tcb(xnarchtcb_t * tcb)
{

	tcb->user_task = NULL;
	tcb->active_task = NULL;
	tcb->mm = NULL;
	tcb->active_mm = NULL;
	tcb->tip = &tcb->ti;
	tcb->ti.tp_value = 0;
	tcb->ti.cpu_domain = xnarch_current_domain_access_control();
#ifdef CONFIG_XENO_HW_FPU
	tcb->user_fpu_owner = NULL;
	tcb->fpup = &tcb->fpuenv;
	tcb->is_root = 0;
#endif /* CONFIG_XENO_HW_FPU */
	/* Must be followed by xnarch_init_thread(). */
}

#define xnarch_alloc_stack(tcb,stacksize) \
({ \
    int __err; \
    (tcb)->stacksize = stacksize; \
    if (stacksize == 0) { \
        (tcb)->stackbase = NULL; \
    __err = 0; \
    } else { \
        (tcb)->stackbase = xnheap_alloc(&kstacks, stacksize); \
        __err = (tcb)->stackbase ? 0 : -ENOMEM; \
    } \
    __err; \
})

#define xnarch_free_stack(tcb) \
do { \
      if ((tcb)->stackbase) \
	xnheap_free(&kstacks, (tcb)->stackbase); \
} while(0)

#endif /* !_XENO_ASM_ARM_BITS_THREAD_H */
