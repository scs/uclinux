/**
 *
 * @note Copyright (C) 2004 Philippe Gerum <rpm@xenomai.org> 
 * @note Copyright (C) 2005 Nextream France S.A.
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

#ifndef _RTAI_TIMER_H
#define _RTAI_TIMER_H

#include <rtai/types.h>

#ifdef __cplusplus
extern "C" {
#endif

static inline RTIME nano2count(RTIME ns)
{
    return ns;
}

static inline RTIME count2nano(RTIME count)
{
    return count;
}

void rt_set_oneshot_mode(void);

void rt_set_periodic_mode(void);

RTIME start_rt_timer(int period);

void stop_rt_timer(void);

void rt_sleep(RTIME delay);

RTIME rt_get_time_ns(void);

#ifdef __cplusplus
}
#endif

#endif /* !_RTAI_TIMER_H */
