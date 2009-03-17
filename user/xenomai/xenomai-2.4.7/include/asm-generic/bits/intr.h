/*
 * Copyright (C) 2001,2002,2003,2004,2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_ASM_GENERIC_BITS_INTR_H
#define _XENO_ASM_GENERIC_BITS_INTR_H

#ifndef __KERNEL__
#error "Pure kernel header included from user-space!"
#endif

static inline int xnarch_hook_irq (unsigned irq,
				   rthal_irq_handler_t handler,
				   rthal_irq_ackfn_t ackfn,
				   void *cookie)
{
    return rthal_irq_request(irq,handler,ackfn,cookie);
}

static inline int xnarch_release_irq (unsigned irq)
{
    return rthal_irq_release(irq);
}

static inline int xnarch_enable_irq (unsigned irq)
{
    return rthal_irq_enable(irq);
}

static inline int xnarch_disable_irq (unsigned irq)
{
    return rthal_irq_disable(irq);
}

static inline int xnarch_end_irq (unsigned irq)
{
     return rthal_irq_end(irq);
}
                                                                                
static inline void xnarch_chain_irq (unsigned irq)
{
    rthal_irq_host_pend(irq);
}

static inline xnarch_cpumask_t xnarch_set_irq_affinity (unsigned irq,
							xnarch_cpumask_t affinity)
{
    return rthal_set_irq_affinity(irq,affinity);
}

static inline void *xnarch_get_irq_cookie(unsigned irq)
{
	return rthal_irq_cookie(&rthal_domain, irq);
}

#endif /* !_XENO_ASM_GENERIC_BITS_INTR_H */
