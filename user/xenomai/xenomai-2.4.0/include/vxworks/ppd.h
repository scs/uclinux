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

#ifndef _VXWORKS_PPD_H
#define _VXWORKS_PPD_H

#include <nucleus/pod.h>
#include <nucleus/ppd.h>

#ifndef CONFIG_XENO_OPT_DEBUG_VXWORKS
#define CONFIG_XENO_OPT_DEBUG_VXWORKS  0
#endif

typedef struct wind_resource_holder {

	xnshadow_ppd_t ppd;

#define ppd2rholder(a)	container_of(a, struct wind_resource_holder, ppd)

	xnqueue_t wdq;		/* Watchdogs created by the process. */

	int wdcount;		/* Number of watchdogs created */
	xnsynch_t wdsynch;	/* Per-process synch for watchdog server task. */
	xnqueue_t wdpending;	/* Elapsed watchdogs to notify to user-space. */

} wind_rholder_t;

extern wind_rholder_t __wind_global_rholder;

#ifdef CONFIG_XENO_OPT_PERVASIVE

extern int __wind_muxid;

static inline wind_rholder_t *wind_get_rholder(void)
{
	xnshadow_ppd_t *ppd = xnshadow_ppd_get(__wind_muxid);

	if (ppd == NULL)
		return &__wind_global_rholder;

	return ppd2rholder(ppd);
}

#else /* !CONFIG_XENO_OPT_PERVASIVE */

static inline wind_rholder_t *wind_get_rholder(void)
{
	return &__wind_global_rholder;
}

#endif /* !CONFIG_XENO_OPT_PERVASIVE */

#if XENO_DEBUG(VXWORKS)
#define __wind_trace_release(__name, __obj, __err)			\
	xnprintf("VxWorks: cleaning up %s \"%s\" (ret=%d).\n",		\
		 __name, (__obj)->name, __err)
#else /* !XENO_DEBUG(VXWORKS) */
#define __wind_trace_release(__name, __obj, __err)
#endif /* !XENO_DEBUG(VXWORKS) */

#define wind_flush_rq(__type, __rq, __name)				\
	do {								\
		STATUS __name##Delete(__natural_word_type id);		\
		xnholder_t *holder, *nholder;				\
		__type *obj;						\
		STATUS err;						\
		spl_t s;						\
		xnlock_get_irqsave(&nklock, s);				\
		nholder = getheadq(__rq);				\
		while ((holder = nholder) != NULL) {			\
			nholder = nextq((__rq), holder);		\
			xnlock_put_irqrestore(&nklock, s);		\
			obj = rlink2##__name(holder);			\
			err = __name##Delete((__natural_word_type)obj);	\
			__wind_trace_release(#__name, obj, err);	\
			if (unlikely(err)) {				\
				if ((__rq) != &__wind_global_rholder.__name##q) { \
					xnlock_get_irqsave(&nklock, s);	\
					nholder = popq((rq), holder);	\
					appendq(&__wind_global_rholder.__name##q, holder); \
					obj->rqueue = &__wind_global_rholder.__name##q; \
				}					\
			} else						\
				xnlock_get_irqsave(&nklock, s);		\
		}							\
		xnlock_put_irqrestore(&nklock, s);			\
	} while(0)

#endif /* !_VXWORKS_PPD_H */
