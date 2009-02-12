/*
 * Written by Gilles Chanteperdrix <gilles.chanteperdrix@laposte.net>.
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


#ifndef _POSIX_COND_H
#define _POSIX_COND_H

#include <posix/posix.h>

int pse51_cond_timedwait_prologue(xnthread_t *cur,
				  struct __shadow_cond *shadow,
				  struct __shadow_mutex *mutex,
				  unsigned *count_ptr,
				  int timed,
				  xnticks_t to);

int pse51_cond_timedwait_epilogue(xnthread_t *cur,
				  struct __shadow_cond *shadow,
				  struct __shadow_mutex *mutex, unsigned count);

void pse51_condq_cleanup(pse51_kqueues_t *q);

void pse51_cond_pkg_init(void);

void pse51_cond_pkg_cleanup(void);

#endif /* !_POSIX_COND_H */
