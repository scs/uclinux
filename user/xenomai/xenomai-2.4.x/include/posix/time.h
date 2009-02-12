/*
 * Copyright (C) 2005 Philippe Gerum <rpm@xenomai.org>.
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

#ifndef _XENO_POSIX_TIME_H
#define _XENO_POSIX_TIME_H

#if defined(__KERNEL__) || defined(__XENO_SIM__)

#include <nucleus/xenomai.h>

#ifdef __KERNEL__
#include <linux/time.h>
#define DELAYTIMER_MAX UINT_MAX
#endif /* __KERNEL__ */

#ifdef __XENO_SIM__
#include <posix_overrides.h>
#endif /* __XENO_SIM__ */

#ifndef TIMER_ABSTIME
#define TIMER_ABSTIME 1
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

#include_next <time.h>
/* In case time.h is included for a side effect of an __need* macro, include it
   a second time to get all definitions. */
#include_next <time.h>

#endif /* !(__KERNEL__ || __XENO_SIM__) */

#ifndef CLOCK_MONOTONIC
/* Some archs do not implement this, but Xenomai always does. */
#define CLOCK_MONOTONIC 1
#endif /* CLOCK_MONOTONIC */

#if defined(__KERNEL__) || defined(__XENO_SIM__)

struct sigevent;

struct timespec;

#ifdef __cplusplus
extern "C" {
#endif

int clock_getres(clockid_t clock_id,
		 struct timespec *res);

int clock_gettime(clockid_t clock_id,
		  struct timespec *tp);

int clock_settime(clockid_t clock_id,
		  const struct timespec *tp);

int clock_nanosleep(clockid_t clock_id,
		    int flags,
                    const struct timespec *rqtp,
		    struct timespec *rmtp);

int nanosleep(const struct timespec *rqtp,
              struct timespec *rmtp);

int timer_create(clockid_t clockid,
		 const struct sigevent *__restrict__ evp,
		 timer_t *__restrict__ timerid);

int timer_delete(timer_t timerid);

int timer_settime(timer_t timerid,
		  int flags,
		  const struct itimerspec *__restrict__ value,
		  struct itimerspec *__restrict__ ovalue);

int timer_gettime(timer_t timerid, struct itimerspec *value);

int timer_getoverrun(timer_t timerid);

#ifdef __cplusplus
}
#endif

#else /* !(__KERNEL__ || __XENO_SIM__) */

#ifdef __cplusplus
extern "C" {
#endif

int __real_clock_getres(clockid_t clock_id,
			struct timespec *tp);

int __real_clock_gettime(clockid_t clock_id,
			 struct timespec *tp);

int __real_clock_settime(clockid_t clock_id,
			 const struct timespec *tp);

int __real_clock_nanosleep(clockid_t clock_id,
			   int flags,
			   const struct timespec *rqtp,
			   struct timespec *rmtp);

int __real_nanosleep(const struct timespec *rqtp,
		     struct timespec *rmtp);

int __real_timer_create (clockid_t clockid,
			 struct sigevent *evp,
			 timer_t *timerid);

int __real_timer_delete (timer_t timerid);

int __real_timer_settime(timer_t timerid,
			 int flags,
			 const struct itimerspec *value,
			 struct itimerspec *ovalue);

int __real_timer_gettime(timer_t timerid,
			 struct itimerspec *value);

int __real_timer_getoverrun(timer_t timerid);

#ifdef __cplusplus
}
#endif

#endif /* !(__KERNEL__ || __XENO_SIM__) */

#endif /* _XENO_POSIX_TIME_H */
