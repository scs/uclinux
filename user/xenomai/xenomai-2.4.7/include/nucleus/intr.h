/*
 * @note Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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
 * \ingroup intr
 */

#ifndef _XENO_NUCLEUS_INTR_H
#define _XENO_NUCLEUS_INTR_H

/* Possible return values of ISR. */
#define XN_ISR_NONE   	 0x1
#define XN_ISR_HANDLED	 0x2
/* Additional bits. */
#define XN_ISR_PROPAGATE 0x100
#define XN_ISR_NOENABLE  0x200
#define XN_ISR_BITMASK	 (~0xff)

/* Creation flags. */
#define XN_ISR_SHARED	 0x1
#define XN_ISR_EDGE	 0x2

/* Operational flags. */
#define XN_ISR_ATTACHED	 0x10000

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/types.h>
#include <nucleus/stat.h>

typedef struct xnintr {

#ifdef CONFIG_XENO_OPT_SHIRQ
    struct xnintr *next; /* !< Next object in the IRQ-sharing chain. */
#endif /* CONFIG_XENO_OPT_SHIRQ */

    unsigned unhandled;	/* !< Number of consequent unhandled interrupts */

    xnisr_t isr;	/* !< Interrupt service routine. */

    void *cookie;	/* !< User-defined cookie value. */

    xnflags_t flags; 	/* !< Creation flags. */

    unsigned irq;	/* !< IRQ number. */

    xniack_t iack;	/* !< Interrupt acknowledge routine. */

    const char *name;	/* !< Symbolic name. */

    struct {
	xnstat_counter_t hits;	  /* !< Number of handled receipts since attachment. */
	xnstat_exectime_t account; /* !< Runtime accounting entity */
    } stat[XNARCH_NR_CPUS];

} xnintr_t;

extern xnintr_t nkclock;
#ifdef CONFIG_XENO_OPT_STATS
extern int xnintr_count;
extern int xnintr_list_rev;
#endif

#ifdef __cplusplus
extern "C" {
#endif

int xnintr_mount(void);

void xnintr_clock_handler(void);

int xnintr_irq_proc(unsigned int irq, char *str);

    /* Public interface. */

int xnintr_init(xnintr_t *intr,
		const char *name,
		unsigned irq,
		xnisr_t isr,
		xniack_t iack,
		xnflags_t flags);

int xnintr_destroy(xnintr_t *intr);

int xnintr_attach(xnintr_t *intr,
		  void *cookie);

int xnintr_detach(xnintr_t *intr);

int xnintr_enable(xnintr_t *intr);

int xnintr_disable(xnintr_t *intr);

xnarch_cpumask_t xnintr_affinity(xnintr_t *intr,
                                 xnarch_cpumask_t cpumask);

int xnintr_query(int irq, int *cpu, xnintr_t **prev, int revision, char *name,
		 unsigned long *hits, xnticks_t *exectime,
		 xnticks_t *account_period);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#endif /* !_XENO_NUCLEUS_INTR_H */
