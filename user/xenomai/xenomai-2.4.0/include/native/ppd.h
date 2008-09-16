/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2007 Philippe Gerum <rpm@xenomai.org> 
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

#ifndef _XENO_PPD_H
#define _XENO_PPD_H

#include <nucleus/pod.h>
#include <nucleus/ppd.h>
#include <nucleus/heap.h>

typedef struct xeno_resource_holder {

	xnshadow_ppd_t ppd;

#define ppd2rholder(a)	container_of(a, struct xeno_resource_holder, ppd)

	xnqueue_t alarmq;
	xnqueue_t condq;
	xnqueue_t eventq;
	xnqueue_t heapq;
	xnqueue_t intrq;
	xnqueue_t mutexq;
	xnqueue_t pipeq;
	xnqueue_t queueq;
	xnqueue_t semq;
	xnqueue_t ioregionq;

} xeno_rholder_t;

extern xeno_rholder_t __native_global_rholder;

#ifdef CONFIG_XENO_OPT_PERVASIVE

extern int __native_muxid;

static inline xeno_rholder_t *xeno_get_rholder(void)
{
	xnshadow_ppd_t *ppd = xnshadow_ppd_get(__native_muxid);

	if (ppd == NULL)
		return &__native_global_rholder;

	return ppd2rholder(ppd);
}

#define __xeno_release_obj(obj)		\
	do {					\
		if ((obj)->cpid)		\
			xnfree(obj);		\
	} while(0)

#else /* !CONFIG_XENO_OPT_PERVASIVE */

static inline xeno_rholder_t *xeno_get_rholder(void)
{
	return &__native_global_rholder;
}

#define __xeno_release_obj(obj)

#endif /* !CONFIG_XENO_OPT_PERVASIVE */

#if XENO_DEBUG(NATIVE)
#define __xeno_trace_release(__name, __obj, __err)		\
	xnprintf("native: cleaning up %s \"%s\" (ret=%d).\n",	\
		 __name, (__obj)->name, __err)
#else /* !XENO_DEBUG(NATIVE) */
#define __xeno_trace_release(__name, __obj, __err)
#endif /* !XENO_DEBUG(NATIVE) */

#define xeno_flush_rq(__type, __rq, __name)				\
	do {								\
		int rt_##__name##_delete(__type *);			\
		xnholder_t *holder, *nholder;				\
		__type *obj;						\
		int err;						\
		spl_t s;						\
		xnlock_get_irqsave(&nklock, s);				\
		nholder = getheadq(__rq);				\
		while ((holder = nholder) != NULL) {			\
			nholder = nextq((__rq), holder);		\
			xnlock_put_irqrestore(&nklock, s);		\
			obj = rlink2##__name(holder);			\
			err = rt_##__name##_delete(obj);		\
			__xeno_trace_release(#__name, obj, err);	\
			if (unlikely(err)) {				\
				if ((__rq) != &__native_global_rholder.__name##q) { \
					xnlock_get_irqsave(&nklock, s);	\
					nholder = popq((rq), holder);	\
					appendq(&__native_global_rholder.__name##q, holder); \
					obj->rqueue = &__native_global_rholder.__name##q; \
				}					\
			} else {					\
				__xeno_release_obj(obj);		\
				xnlock_get_irqsave(&nklock, s);		\
			}						\
		}							\
		xnlock_put_irqrestore(&nklock, s);			\
	} while(0)

#endif /* !_XENO_PPD_H */
