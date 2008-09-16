/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef _XENO_ASM_SIM_BITS_INTR_H
#define _XENO_ASM_SIM_BITS_INTR_H

typedef void (*rthal_irq_handler_t)(unsigned, void *);

typedef int (*rthal_irq_ackfn_t)(unsigned);

static inline int xnarch_hook_irq (unsigned irq,
				   rthal_irq_handler_t handler,
				   rthal_irq_ackfn_t ackfn, /* Ignored. */
				   void *cookie)
{
	return mvm_hook_irq(irq,handler,cookie);
}

static inline int xnarch_release_irq (unsigned irq)
{
	return mvm_release_irq(irq);
}

static inline int xnarch_enable_irq (unsigned irq)
{
	return mvm_enable_irq(irq);
}

static inline int xnarch_disable_irq (unsigned irq)
{
	return mvm_disable_irq(irq);
}

static inline int xnarch_end_irq (unsigned irq)
{
	return mvm_enable_irq(irq);
}
                                                                                
static inline void xnarch_chain_irq (unsigned irq)
{
	/* empty */
}

static inline unsigned long xnarch_set_irq_affinity (unsigned irq,
						     unsigned long affinity)
{
	return 0;
}

static inline void xnarch_relay_tick(void)
{
	/* empty */
}

static inline void xnarch_announce_tick(void)
{
	/* empty */
}

static inline void *xnarch_get_irq_cookie(unsigned irq)
{
	return NULL;		/* Unsupported. */
}

#endif /* !_XENO_ASM_SIM_BITS_INTR_H */
