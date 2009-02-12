/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org> 
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

#ifndef _XENO_INTR_H
#define _XENO_INTR_H

#include <nucleus/intr.h>
#include <native/types.h>

/* Creation flag. */
#define I_NOAUTOENA  XN_ISR_NOENABLE  /* Do not auto-enable interrupt channel
				        after each IRQ. */
#define I_PROPAGATE  XN_ISR_PROPAGATE /* Propagate IRQs down the
				       pipeline after processing; IOW,
				       pass them to Linux. */
typedef struct rt_intr_info {

    unsigned irq;	/* !< Interrupt request number. */

    unsigned long hits;	/* !< Number of receipts (since attachment), 0 if
                              statistics support is disable in the nucleus. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

} RT_INTR_INFO;

typedef struct rt_intr_placeholder {
    xnhandle_t opaque;
} RT_INTR_PLACEHOLDER;

#if (defined(__KERNEL__) || defined(__XENO_SIM__)) && !defined(DOXYGEN_CPP)

#include <nucleus/synch.h>
#include <native/ppd.h>

#define XENO_INTR_MAGIC 0x55550a0a

/* Creation flags. */
#define I_SHARED	XN_ISR_SHARED
#define I_EDGE		XN_ISR_EDGE

#define RT_INTR_HANDLED		XN_ISR_HANDLED
#define RT_INTR_NONE		XN_ISR_NONE
#define RT_INTR_PROPAGATE	XN_ISR_PROPAGATE
#define RT_INTR_NOENABLE	XN_ISR_NOENABLE

#define I_DESC(xintr)  ((RT_INTR *)(xintr)->cookie)

typedef struct rt_intr {

    unsigned magic;		/* !< Magic code - must be first */

    xnintr_t intr_base;		/* !< Base interrupt object. */

    void *private_data;		/* !< Private user-defined data. */

    xnhandle_t handle;		/* !< Handle in registry -- zero if unregistered. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    int mode;			/* !< Interrupt control mode. */

    int pending;		/* !< Pending hits to process. */

    xnsynch_t synch_base;	/* !< Base synchronization object. */

    pid_t cpid;			/* !< Creator's pid. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2intr(ln)		container_of(ln, RT_INTR, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

} RT_INTR;

#define rt_intr_save(x)    splhigh(x)
#define rt_intr_restore(x) splexit(x)
#define rt_intr_unmask()   splnone()
#define rt_intr_flags(x)   splget(x)

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_XENO_OPT_NATIVE_INTR

int __native_intr_pkg_init(void);

void __native_intr_pkg_cleanup(void);

static inline void __native_intr_flush_rq(xnqueue_t *rq)
{
	xeno_flush_rq(RT_INTR, rq, intr);
}

#else /* !CONFIG_XENO_OPT_NATIVE_INTR */

#define __native_intr_pkg_init()		({ 0; })
#define __native_intr_pkg_cleanup()		do { } while(0)
#define __native_intr_flush_rq(rq)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_NATIVE_INTR */

int rt_intr_create(RT_INTR *intr,
		   const char *name,
		   unsigned irq,
		   rt_isr_t isr,
		   rt_iack_t iack,
		   int mode);

#ifdef CONFIG_XENO_OPT_PERVASIVE
int rt_intr_handler(xnintr_t *cookie);
#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef RT_INTR_PLACEHOLDER RT_INTR;

#ifdef __cplusplus
extern "C" {
#endif

int rt_intr_bind(RT_INTR *intr,
		 const char *name,
		 RTIME timeout);

static inline int rt_intr_unbind (RT_INTR *intr)

{
    intr->opaque = XN_NO_HANDLE;
    return 0;
}

int rt_intr_create(RT_INTR *intr,
		   const char *name,
		   unsigned irq,
		   int mode);

int rt_intr_wait(RT_INTR *intr,
		 RTIME timeout);

#ifdef __cplusplus
}
#endif

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface. */

int rt_intr_delete(RT_INTR *intr);

int rt_intr_enable(RT_INTR *intr);

int rt_intr_disable(RT_INTR *intr);

int rt_intr_inquire(RT_INTR *intr,
		    RT_INTR_INFO *info);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_INTR_H */
