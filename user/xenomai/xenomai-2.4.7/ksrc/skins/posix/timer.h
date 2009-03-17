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

#ifndef _POSIX_TIMER_H
#define _POSIX_TIMER_H

#include <posix/sig.h>        /* For struct itimerspec. */

void pse51_timer_notified(pse51_siginfo_t *si);

void pse51_timer_init_thread(pthread_t new);

void pse51_timer_cleanup_thread(pthread_t zombie);

void pse51_timerq_cleanup(pse51_kqueues_t *q);

int pse51_timer_pkg_init(void);

void pse51_timer_pkg_cleanup(void);

#endif /* !_POSIX_TIMER_H */
