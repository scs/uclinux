/*
 * Copyright (C) 2001,2002,2003 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_NUCLEUS_TYPES_H
#define _XENO_NUCLEUS_TYPES_H

#ifdef __KERNEL__
#include <linux/errno.h>
#ifdef CONFIG_PREEMPT_RT
#define linux_semaphore compat_semaphore
#else /* CONFIG_PREEMPT_RT */
#define linux_semaphore semaphore
#endif /* !CONFIG_PREEMPT_RT */
#else /* !__KERNEL__ */
#include <stdio.h>
#include <sys/types.h>
#include <errno.h>
#ifndef BITS_PER_LONG
#include <stdint.h>
#define BITS_PER_LONG __WORDSIZE
#endif /* !BITS_PER_LONG */
#endif /* __KERNEL__ */

#include <asm/xenomai/system.h>
#include <nucleus/compiler.h>
#include <nucleus/assert.h>

#if BITS_PER_LONG == 32
#define __natural_word_type int
#else  /* defaults to long otherwise */
#define __natural_word_type long
#endif

typedef unsigned long xnsigmask_t;

typedef unsigned long long xnticks_t;

typedef long long xnsticks_t;

typedef unsigned long long xntime_t; /* ns */

typedef long long xnstime_t;

typedef unsigned long xnhandle_t;

#define XN_NO_HANDLE ((xnhandle_t)0)

struct xnintr;

typedef int (*xnisr_t)(struct xnintr *intr);

typedef void (*xniack_t)(unsigned irq, void *arg);

#define XN_INFINITE   (0)
#define XN_NONBLOCK   ((xnticks_t)-1)

/* Timer modes */
typedef enum xntmode {
	XN_RELATIVE,
	XN_ABSOLUTE,
	XN_REALTIME
} xntmode_t;

#define XN_APERIODIC_TICK  0
#define XN_NO_TICK         ((xnticks_t)-1)

#define testbits(flags,mask) ((flags) & (mask))
#define setbits(flags,mask)  xnarch_atomic_set_mask(&(flags),mask)
#define clrbits(flags,mask)  xnarch_atomic_clear_mask(&(flags),mask)
#define __testbits(flags,mask) testbits(flags,mask)
#define __setbits(flags,mask)  do { (flags) |= (mask); } while(0)
#define __clrbits(flags,mask)  do { (flags) &= ~(mask); } while(0)

typedef atomic_flags_t xnflags_t;

#ifndef NULL
#define NULL 0
#endif

#define XNOBJECT_NAME_LEN 32

static inline void xnobject_copy_name(char *dst, const char *src)
{
    if (src)
	snprintf(dst, XNOBJECT_NAME_LEN, "%s", src);
    else
        *dst = '\0';
}

#define xnobject_create_name(dst, n, obj) \
    snprintf(dst, n, "%p", obj)

#define minval(a,b) ((a) < (b) ? (a) : (b))
#define maxval(a,b) ((a) > (b) ? (a) : (b))

#ifdef __cplusplus
extern "C" {
#endif

const char *xnpod_fatal_helper(const char *format, ...);

int __xeno_user_init(void);

void __xeno_user_exit(void);

#ifdef __cplusplus
}
#endif

#define xnprintf(fmt,args...)  xnarch_printf(fmt , ##args)
#define xnloginfo(fmt,args...) xnarch_loginfo(fmt , ##args)
#define xnlogwarn(fmt,args...) xnarch_logwarn(fmt , ##args)
#define xnlogerr(fmt,args...)  xnarch_logerr(fmt , ##args)

#define xnpod_fatal(format,args...) \
do { \
    const char *panic; \
    xnarch_trace_panic_freeze(); \
    panic = xnpod_fatal_helper(format,##args); \
    xnarch_halt(panic); \
} while (0)

#ifdef __XENO_SIM__
#define SKIN_INIT(name)  __xeno_skin_init(void)
#define SKIN_EXIT(name)  __xeno_skin_exit(void)
#else /* !__XENO_SIM__ */
#define SKIN_INIT(name)  __ ## name ## _skin_init(void)
#define SKIN_EXIT(name)  __ ## name ## _skin_exit(void)
#endif /* __XENO_SIM__ */

#define root_thread_init __xeno_user_init
#define root_thread_exit __xeno_user_exit

#endif /* !_XENO_NUCLEUS_TYPES_H */
