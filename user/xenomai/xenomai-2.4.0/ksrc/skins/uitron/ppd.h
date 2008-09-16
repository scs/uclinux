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

#ifndef _UITRON_PPD_H
#define _UITRON_PPD_H

#include <nucleus/pod.h>
#include <nucleus/ppd.h>

#ifndef CONFIG_XENO_OPT_DEBUG_UITRON
#define CONFIG_XENO_OPT_DEBUG_UITRON  0
#endif

typedef struct ui_resource_holder {

	xnshadow_ppd_t ppd;

#define ppd2rholder(a)	container_of(a, struct ui_resource_holder, ppd)

	xnqueue_t flgq;
	xnqueue_t mbxq;
	xnqueue_t semq;

} ui_rholder_t;

extern ui_rholder_t __ui_global_rholder;

#ifdef CONFIG_XENO_OPT_PERVASIVE

extern int __ui_muxid;

static inline ui_rholder_t *ui_get_rholder(void)
{
	xnshadow_ppd_t *ppd = xnshadow_ppd_get(__ui_muxid);

	if (ppd == NULL)
		return &__ui_global_rholder;

	return ppd2rholder(ppd);
}

#else /* !CONFIG_XENO_OPT_PERVASIVE */

static inline ui_rholder_t *ui_get_rholder(void)
{
	return &__ui_global_rholder;
}

#endif /* !CONFIG_XENO_OPT_PERVASIVE */

#if XENO_DEBUG(UITRON)
#define __ui_trace_release(__name, __obj, __err)			\
	xnprintf("uITRON: cleaning up %s \"%s\" (ret=%d).\n",		\
		 __name, (__obj)->name, __err)
#else /* !XENO_DEBUG(NATIVE) */
#define __ui_trace_release(__name, __obj, __err)
#endif /* !XENO_DEBUG(NATIVE) */

#define ui_flush_rq(__type, __rq, __name)					\
	do {								\
		ER del_##__name(ID id);					\
		xnholder_t *holder, *nholder;				\
		__type *obj;						\
		ER err;							\
		spl_t s;						\
		xnlock_get_irqsave(&nklock, s);				\
		nholder = getheadq(__rq);				\
		while ((holder = nholder) != NULL) {			\
			nholder = nextq((__rq), holder);		\
			xnlock_put_irqrestore(&nklock, s);		\
			obj = rlink2##__name(holder);			\
			err = del_##__name((obj)->id);			\
			__ui_trace_release(#__name, obj, err);		\
			if (unlikely(err)) {				\
				if ((__rq) != &__ui_global_rholder.__name##q) { \
					xnlock_get_irqsave(&nklock, s);	\
					nholder = popq((rq), holder);	\
					appendq(&__ui_global_rholder.__name##q, holder); \
					obj->rqueue = &__ui_global_rholder.__name##q; \
				}					\
			} else						\
				xnlock_get_irqsave(&nklock, s);		\
		}							\
		xnlock_put_irqrestore(&nklock, s);			\
	} while(0)

#endif /* !_UITRON_PPD_H */
