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

#ifndef _XENO_MISC_H
#define _XENO_MISC_H

#include <native/types.h>

#define IORN_IOPORT	0x1
#define IORN_IOMEM	0x2

typedef struct rt_ioregion_placeholder {
	xnhandle_t opaque;
	/*
	 * We keep the region start and length in the userland
	 * placeholder to support deprecated rt_misc_io_*() calls.
	 */
	uint64_t start;
	uint64_t len;
} RT_IOREGION_PLACEHOLDER;

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <native/ppd.h>

#define XENO_IOREGION_MAGIC 0x55550b0b

typedef struct rt_ioregion {

	unsigned magic;		/* !< Magic code - must be first */

	xnhandle_t handle;	/* !< Handle in registry -- must be registered. */

	uint64_t start;		/* !< Start of I/O region. */

	uint64_t len;		/* !< Length of I/O region. */

	char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

	int flags;		/* !< Operation flags. */

	pid_t cpid;		/* !< Creator's pid. */

	xnholder_t rlink;	/* !< Link in resource queue. */

#define rlink2ioregion(ln)	container_of(ln, RT_IOREGION, rlink)

	xnqueue_t *rqueue;     /* !< Backpointer to resource queue. */

} RT_IOREGION;

int rt_ioregion_delete(RT_IOREGION *iorn);

static inline void __native_ioregion_flush_rq(xnqueue_t *rq)
{
#ifdef CONFIG_XENO_OPT_PERVASIVE
	xeno_flush_rq(RT_IOREGION, rq, ioregion);
#endif
}

static inline int __native_misc_pkg_init(void)
{
	return 0;
}

static inline void __native_misc_pkg_cleanup(void)
{
#ifdef CONFIG_XENO_OPT_PERVASIVE
	__native_ioregion_flush_rq(&__native_global_rholder.ioregionq);
#endif
}

#else /* !(__KERNEL__ && __XENO_SIM__) */

typedef RT_IOREGION_PLACEHOLDER RT_IOREGION;

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface. */

int rt_io_get_region(RT_IOREGION *iorn,
		     const char *name,
		     uint64_t start,
		     uint64_t len,
		     int flags);

int rt_io_put_region(RT_IOREGION *iorn);

__deprecated_call__
static inline int  rt_misc_get_io_region(unsigned long start,
					 unsigned long len,
					 const char *label)
{
	RT_IOREGION iorn;

	return rt_io_get_region(&iorn, label, (uint64_t)start,
				(uint64_t)len, IORN_IOPORT);
}

__deprecated_call__
static inline int rt_misc_put_io_region(unsigned long start,
					unsigned long len)
{
	RT_IOREGION iorn;

	iorn.opaque = XN_NO_HANDLE;
	iorn.start = (uint64_t)start;
	iorn.len = (uint64_t)len;
	rt_io_put_region(&iorn);

	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* !(__KERNEL__ || __XENO_SIM__) */

#endif /* !_XENO_MISC_H */
