/**
 * @file
 * This file is part of the Xenomai project.
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
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

#ifndef _XENO_ALARM_H
#define _XENO_ALARM_H

#include <native/types.h>

typedef struct rt_alarm_info {

    RTIME expiration;		/* !< Expiration date. */

    unsigned long expiries;	/* !< Number of expiries. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

} RT_ALARM_INFO;

typedef struct rt_alarm_placeholder {
    xnhandle_t opaque;
} RT_ALARM_PLACEHOLDER;

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/timer.h>
#include <nucleus/synch.h>
#include <native/ppd.h>

#define XENO_ALARM_MAGIC 0x55550909

typedef struct rt_alarm {

    unsigned magic;   /* !< Magic code - must be first */

    xntimer_t timer_base; /* !< Base timer object. */

    xnhandle_t handle;	/* !< Handle in registry -- zero if unregistered. */

    rt_alarm_t handler;		/* !< Alarm handler. */
    
    void *cookie;		/* !< Opaque cookie. */

    unsigned long expiries;	/* !< Number of expiries. */

#ifdef CONFIG_XENO_OPT_PERVASIVE
    pid_t cpid;			/* !< Creator's pid. */

    xnsynch_t synch_base;	/* !< Synch. base for user-space tasks. */
#endif /* CONFIG_XENO_OPT_PERVASIVE */

    xnholder_t rlink;		/* !< Link in resource queue. */

#define rlink2alarm(ln)	container_of(ln, RT_ALARM, rlink)

    xnqueue_t *rqueue;		/* !< Backpointer to resource queue. */

    char name[XNOBJECT_NAME_LEN]; /* !< Symbolic name. */

} RT_ALARM;

#ifdef __cplusplus
extern "C" {
#endif

#ifdef CONFIG_XENO_OPT_NATIVE_ALARM

int __native_alarm_pkg_init(void);

void __native_alarm_pkg_cleanup(void);

static inline void __native_alarm_flush_rq(xnqueue_t *rq)
{
	xeno_flush_rq(RT_ALARM, rq, alarm);
}

#else /* !CONFIG_XENO_OPT_NATIVE_ALARM */

#define __native_alarm_pkg_init()		({ 0; })
#define __native_alarm_pkg_cleanup()		do { } while(0)
#define __native_alarm_flush_rq(rq)		do { } while(0)

#endif /* !CONFIG_XENO_OPT_NATIVE_ALARM */

int rt_alarm_create(RT_ALARM *alarm,
		    const char *name,
		    rt_alarm_t handler,
		    void *cookie);

#ifdef CONFIG_XENO_OPT_PERVASIVE

void rt_alarm_handler(RT_ALARM *alarm,
		      void *cookie);

#endif /* CONFIG_XENO_OPT_PERVASIVE */

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

typedef RT_ALARM_PLACEHOLDER RT_ALARM;

#ifdef __cplusplus
extern "C" {
#endif

int rt_alarm_create(RT_ALARM *alarm,
		    const char *name);

int rt_alarm_wait(RT_ALARM *alarm);

#ifdef __cplusplus
}
#endif

/* No binding for alarms. */

#endif /* __KERNEL__ || __XENO_SIM__ */

#ifdef __cplusplus
extern "C" {
#endif

/* Public interface. */

int rt_alarm_delete(RT_ALARM *alarm);

int rt_alarm_start(RT_ALARM *alarm,
		   RTIME value,
		   RTIME interval);

int rt_alarm_stop(RT_ALARM *alarm);

int rt_alarm_inquire(RT_ALARM *alarm,
		     RT_ALARM_INFO *info);

#ifdef __cplusplus
}
#endif

#endif /* !_XENO_ALARM_H */
